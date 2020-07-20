/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2020 Andreas Sandberg <andreas@sandberg.pp.se>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#ifdef _WIN32
#define _WIN32_WINNT 0x0501
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#include <glib.h>
#include <string.h>
#include <unistd.h>
#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif
#include <errno.h>
#include <stdlib.h>
#include <math.h>
#include <nettle/aes.h>
// #include <libsigrok/libsigrok.h>
// #include "libsigrok-internal.h"

#include "protocol.h"

#define SERIAL_WRITE_TIMEOUT_MS 1

#define TC_POLL_LEN 192
#define TC_POLL_PERIOD_MS 100
#define TC_TIMEOUT_MS 1000

static const char POLL_CMD[] = "getva";

#define MAGIC_PAC1 0x31636170UL
#define MAGIC_PAC2 0x32636170UL
#define MAGIC_PAC3 0x33636170UL

/* Length of PAC block excluding CRC */
#define PAC_DATA_LEN 60
/* Length of PAC block including CRC */
#define PAC_LEN 64

/* Offset to PAC block from start of poll data */
#define OFF_PAC1 (0 * PAC_LEN)
#define OFF_PAC2 (1 * PAC_LEN)
#define OFF_PAC3 (2 * PAC_LEN)

#define OFF_MODEL 4
#define LEN_MODEL 4

#define OFF_FW_VER 8
#define LEN_FW_VER 4

#define OFF_SERIAL 12

static const uint8_t AES_KEY[] = {
	0x58, 0x21, 0xfa, 0x56, 0x01, 0xb2, 0xf0, 0x26,
	0x87, 0xff, 0x12, 0x04, 0x62, 0x2a, 0x4f, 0xb0,
	0x86, 0xf4, 0x02, 0x60, 0x81, 0x6f, 0x9a, 0x0b,
	0xa7, 0xf1, 0x06, 0x61, 0x9a, 0xb8, 0x72, 0x88,
};

static const struct binary_analog_channel tplink_hs_channels[] = {
	{ "V",  {   0 + 48, BVT_LE_UINT32, 1e-4, }, 4, SR_MQ_VOLTAGE, SR_UNIT_VOLT },
	{ "I",  {   0 + 52, BVT_LE_UINT32, 1e-5, }, 5, SR_MQ_CURRENT, SR_UNIT_AMPERE },
	{ "D+", {  64 + 32, BVT_LE_UINT32, 1e-2, }, 2, SR_MQ_VOLTAGE, SR_UNIT_VOLT },
	{ "D-", {  64 + 36, BVT_LE_UINT32, 1e-2, }, 2, SR_MQ_VOLTAGE, SR_UNIT_VOLT },
	{ "E0", {  64 + 12, BVT_LE_UINT32, 1e-3, }, 3, SR_MQ_ENERGY, SR_UNIT_WATT_HOUR },
	{ "E1", {  64 + 20, BVT_LE_UINT32, 1e-3, }, 3, SR_MQ_ENERGY, SR_UNIT_WATT_HOUR },
	{ NULL, },
};

static int check_pac_crc(uint8_t *data)
{
	uint16_t crc;
	uint32_t crc_field;

	crc = sr_crc16(SR_CRC16_DEFAULT_INIT, data, PAC_DATA_LEN);
	crc_field = RL32(data + PAC_DATA_LEN);

	if (crc != crc_field) {
		sr_spew("CRC error. Calculated: %0x" PRIx16 ", expected: %0x" PRIx32,
			crc, crc_field);
		return 0;
	} else {
		return 1;
	}
}

static int process_poll_pkt(struct dev_context  *devc, uint8_t *dst)
{
	struct aes256_ctx ctx;

	aes256_set_decrypt_key(&ctx, AES_KEY);
	aes256_decrypt(&ctx, TC_POLL_LEN, dst, devc->buf);

	if (RL32(dst + OFF_PAC1) != MAGIC_PAC1 ||
	    RL32(dst + OFF_PAC2) != MAGIC_PAC2 ||
	    RL32(dst + OFF_PAC3) != MAGIC_PAC3) {
		sr_err("Invalid poll packet magic values!");
		return SR_ERR;
	}

	if (!check_pac_crc(dst + OFF_PAC1) ||
	    !check_pac_crc(dst + OFF_PAC2) ||
	    !check_pac_crc(dst + OFF_PAC3)) {
		sr_err("Invalid poll checksum!");
		return SR_ERR;
	}

	return SR_OK;
}

static int plink_hs_tcp_open(struct dev_context *devc)
{
	struct addrinfo hints;
	struct addrinfo *results, *res;
	int err;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	err = getaddrinfo(devc->address, devc->port, &hints, &results);

	if (err) {
		sr_err("Address lookup failed: %s:%s: %s", devc->address,
			devc->port, gai_strerror(err));
		return SR_ERR;
	}

	for (res = results; res; res = res->ai_next) {
		if ((devc->socket = socket(res->ai_family, res->ai_socktype,
						res->ai_protocol)) < 0)
			continue;
		if (connect(devc->socket, res->ai_addr, res->ai_addrlen) != 0) {
			close(devc->socket);
			devc->socket = -1;
			continue;
		}
		break;
	}

	freeaddrinfo(results);

	if (devc->socket < 0) {
		sr_err("Failed to connect to %s:%s: %s", devc->address,
			devc->port, g_strerror(errno));
		return SR_ERR;
	}

	return SR_OK;
}

static int tplink_hs_tcp_close(struct dev_context *devc)
{
	if (close(devc->socket) < 0)
		return SR_ERR;

	return SR_OK;
}

static int tplink_hs_tcp_send_cmd(struct dev_context *devc,
				    const char *format, ...)
{
	int len, out;
	va_list args, args_copy;
	char *buf;

	va_start(args, format);
	va_copy(args_copy, args);
	len = vsnprintf(NULL, 0, format, args_copy);
	va_end(args_copy);

	buf = g_malloc0(len + 2);
	vsprintf(buf, format, args);
	va_end(args);

	if (buf[len - 1] != '\n')
		buf[len] = '\n';

	out = send(devc->socket, buf, strlen(buf), 0);

	if (out < 0) {
		sr_err("Send error: %s", g_strerror(errno));
		g_free(buf);
		return SR_ERR;
	}

	if (out < (int)strlen(buf)) {
		sr_dbg("Only sent %d/%zu bytes of command: '%s'.", out,
		       strlen(buf), buf);
	}

	sr_spew("Sent command: '%s'.", buf);

	g_free(buf);

	return SR_OK;
}

static int tplink_hs_tcp_read_data(struct dev_context *devc, char *buf,
				     int maxlen)
{
	int len;

	len = recv(devc->socket, buf, maxlen, 0);

	if (len < 0) {
		sr_err("Receive error: %s", g_strerror(errno));
		return SR_ERR;
	}

	return len;
}

static int tplink_hs_tcp_get_string(struct dev_context *devc, const char *cmd,
				      char **tcp_resp)
{
	GString *response = g_string_sized_new(1024);
	int len;
	gint64 timeout;

	*tcp_resp = NULL;
	if (cmd) {
		if (tplink_hs_tcp_send_cmd(devc, cmd) != SR_OK)
			return SR_ERR;
	}

	timeout = g_get_monotonic_time() + devc->read_timeout;
	len = tplink_hs_tcp_read_data(devc, response->str,
					response->allocated_len);

	if (len < 0) {
		g_string_free(response, TRUE);
		return SR_ERR;
	}

	if (len > 0)
		g_string_set_size(response, len);

	if (g_get_monotonic_time() > timeout) {
		sr_err("Timed out waiting for response.");
		g_string_free(response, TRUE);
		return SR_ERR_TIMEOUT;
	}

	/* Remove trailing newline if present */
	if (response->len >= 1 && response->str[response->len - 1] == '\n')
		g_string_truncate(response, response->len - 1);

	/* Remove trailing carriage return if present */
	if (response->len >= 1 && response->str[response->len - 1] == '\r')
		g_string_truncate(response, response->len - 1);

	sr_spew("Got response: '%.70s', length %" G_GSIZE_FORMAT ".",
		response->str, response->len);

	*tcp_resp = g_string_free(response, FALSE);

	return SR_OK;
}

static int tplink_hs_tcp_detect(struct dev_context *devc)
{
	char *resp = NULL;
	int ret;

	ret = tplink_hs_tcp_get_string(devc, "{\"system\":{\"get_sysinfo\":{}}}", &resp);
	printf(resp);


	if (ret == SR_OK && !g_ascii_strncasecmp(resp, "BeagleLogic", 11))
		ret = SR_OK;
	else
		ret = SR_ERR;

	g_free(resp);

	return ret;
}

SR_PRIV int tplink_hs_probe(struct dev_context  *devc)
{
	int len;
	uint8_t poll_pkt[TC_POLL_LEN];

	if (tplink_hs_tcp_open(devc) != SR_OK)
		return SR_ERR;
	if (tplink_hs_tcp_detect(devc) != SR_OK)
		return SR_ERR;
	if (tplink_hs_tcp_close(devc) != SR_OK)
		return SR_ERR;
	sr_info("BeagleLogic device found at %s : %s",
		devc->address, devc->port);

	return SR_OK;


	// if (serial_write_blocking(serial, &POLL_CMD, sizeof(POLL_CMD) - 1,
 //                                  SERIAL_WRITE_TIMEOUT_MS) < 0) {
	// 	sr_err("Unable to send probe request.");
	// 	return SR_ERR;
	// }

	// len = serial_read_blocking(serial, devc->buf, TC_POLL_LEN, TC_TIMEOUT_MS);
	// if (len != TC_POLL_LEN) {
	// 	sr_err("Failed to read probe response.");
	// 	return SR_ERR;
	// }

	// if (process_poll_pkt(devc, poll_pkt) != SR_OK) {
	// 	sr_err("Unrecognized TC device!");
	// 	return SR_ERR;
	// }

	// devc->channels = tplink_hs_channels;
	// devc->dev_info.model_name = g_strndup((const char *)poll_pkt + OFF_MODEL, LEN_MODEL);
	// devc->dev_info.fw_ver = g_strndup((const char *)poll_pkt + OFF_FW_VER, LEN_FW_VER);
	// devc->dev_info.serial_num = RL32(poll_pkt + OFF_SERIAL);

	// return SR_OK;
}

SR_PRIV int tplink_hs_poll(const struct sr_dev_inst *sdi)
{
	struct dev_context *devc = sdi->priv;
	struct sr_serial_dev_inst *serial = sdi->conn;

	if (serial_write_blocking(serial, &POLL_CMD, sizeof(POLL_CMD) - 1,
                                  SERIAL_WRITE_TIMEOUT_MS) < 0) {
		sr_err("Unable to send poll request.");
		return SR_ERR;
	}

	devc->cmd_sent_at = g_get_monotonic_time() / 1000;

	return SR_OK;
}

static void handle_poll_data(const struct sr_dev_inst *sdi)
{
	struct dev_context *devc = sdi->priv;
	uint8_t poll_pkt[TC_POLL_LEN];
	int i;
	GSList *ch;

	sr_spew("Received poll packet (len: %d).", devc->buflen);
	if (devc->buflen != TC_POLL_LEN) {
		sr_err("Unexpected poll packet length: %i", devc->buflen);
		return;
	}

	if (process_poll_pkt(devc, poll_pkt) != SR_OK) {
		sr_err("Failed to process poll packet.");
		return;
	}

	for (ch = sdi->channels, i = 0; ch; ch = g_slist_next(ch), i++) {
		bv_send_analog_channel(sdi, ch->data,
				       &devc->channels[i], poll_pkt, TC_POLL_LEN);
        }

	sr_sw_limits_update_samples_read(&devc->limits, 1);
}

static void recv_poll_data(struct sr_dev_inst *sdi, struct sr_serial_dev_inst *serial)
{
	struct dev_context *devc = sdi->priv;
	int len;

	/* Serial data arrived. */
	while (devc->buflen < TC_POLL_LEN) {
		len = serial_read_nonblocking(serial, devc->buf + devc->buflen, 1);
		if (len < 1)
			return;

		devc->buflen++;
	}

	if (devc->buflen == TC_POLL_LEN)
		handle_poll_data(sdi);

	devc->buflen = 0;
}

SR_PRIV int tplink_hs_receive_data(int fd, int revents, void *cb_data)
{
	struct sr_dev_inst *sdi;
	struct dev_context *devc;
	struct sr_serial_dev_inst *serial;
	int64_t now, elapsed;

	(void)fd;

	if (!(sdi = cb_data))
		return TRUE;

	if (!(devc = sdi->priv))
		return TRUE;

	serial = sdi->conn;
	if (revents == G_IO_IN)
		recv_poll_data(sdi, serial);

	if (sr_sw_limits_check(&devc->limits)) {
		sr_dev_acquisition_stop(sdi);
		return TRUE;
	}

	now = g_get_monotonic_time() / 1000;
	elapsed = now - devc->cmd_sent_at;

	if (elapsed > TC_POLL_PERIOD_MS)
		tplink_hs_poll(sdi);

	return TRUE;
}
