/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2020 Francois Gervais <francoisgervais@gmail.com>
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

/*
 * Done with help of the following sources:
 *
 * https://github.com/python-kasa/python-kasa
 * https://github.com/JustinZhou300/TP-Link-HS110-C
 * https://www.softscheck.com/en/reverse-engineering-tp-link-hs110/
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
// #include <math.h>
// #include <nettle/aes.h>
// #include <libsigrok/libsigrok.h>
// #include "libsigrok-internal.h"

#include "protocol.h"
#include "tplink-hs.h"

#define MESSAGE_PADDING_SIZE 4
#define MESSAGE_SIZE_OFFSET 3

// struct command {
// 	char *name;
// 	char *msg;
// };

// static const struct command commands = {
// 	"sysinfo"  , "{\"system\":{\"get_sysinfo\":{}}}",
//         "realtime" , "{\"emeter\":{\"get_realtime\":{}}}",
// };

#define CMD_SYSINFO_MSG "{\"system\":{\"get_sysinfo\":{}}}"
#define CMD_REALTIME_MSG "{\"emeter\":{\"get_realtime\":{}}}"

// struct sysinfo {
// 	char *model;
// 	char *sw_ver;
// 	char *deviceId;
// };



// #define SERIAL_WRITE_TIMEOUT_MS 1

// #define TC_POLL_LEN 192
// #define HS_POLL_PERIOD_MS 100
#define HS_POLL_PERIOD_MS 1000
// #define TC_TIMEOUT_MS 1000

// static const char POLL_CMD[] = "getva";

// #define MAGIC_PAC1 0x31636170UL
// #define MAGIC_PAC2 0x32636170UL
// #define MAGIC_PAC3 0x33636170UL

/* Length of PAC block excluding CRC */
// #define PAC_DATA_LEN 60
/* Length of PAC block including CRC */
// #define PAC_LEN 64

/* Offset to PAC block from start of poll data */
// #define OFF_PAC1 (0 * PAC_LEN)
// #define OFF_PAC2 (1 * PAC_LEN)
// #define OFF_PAC3 (2 * PAC_LEN)

// #define OFF_MODEL 4
// #define LEN_MODEL 4

// #define OFF_FW_VER 8
// #define LEN_FW_VER 4

// #define OFF_SERIAL 12

// static const uint8_t AES_KEY[] = {
// 	0x58, 0x21, 0xfa, 0x56, 0x01, 0xb2, 0xf0, 0x26,
// 	0x87, 0xff, 0x12, 0x04, 0x62, 0x2a, 0x4f, 0xb0,
// 	0x86, 0xf4, 0x02, 0x60, 0x81, 0x6f, 0x9a, 0x0b,
// 	0xa7, 0xf1, 0x06, 0x61, 0x9a, 0xb8, 0x72, 0x88,
// };

// static const struct binary_analog_channel tplink_hs_channels[] = {
// 	{ "I",  {   0 + 36, BVT_LE_UINT32, 1e-6, }, 6, SR_MQ_CURRENT, SR_UNIT_AMPERE },
// 	{ "V",  {   0 + 55, BVT_LE_UINT32, 1e-6, }, 6, SR_MQ_VOLTAGE, SR_UNIT_VOLT },
// 	{ NULL, },
// };

static const struct channel_spec tplink_hs_channels[] = {
	{ "V",  SR_CHANNEL_ANALOG, SR_MQ_VOLTAGE, SR_UNIT_VOLT },
	{ "I",  SR_CHANNEL_ANALOG, SR_MQ_CURRENT, SR_UNIT_AMPERE },
	{ NULL, },
};

// static int check_pac_crc(uint8_t *data)
// {
// 	uint16_t crc;
// 	uint32_t crc_field;

// 	crc = sr_crc16(SR_CRC16_DEFAULT_INIT, data, PAC_DATA_LEN);
// 	crc_field = RL32(data + PAC_DATA_LEN);

// 	if (crc != crc_field) {
// 		sr_spew("CRC error. Calculated: %0x" PRIx16 ", expected: %0x" PRIx32,
// 			crc, crc_field);
// 		return 0;
// 	} else {
// 		return 1;
// 	}
// }

// static int process_poll_pkt(struct dev_context  *devc, uint8_t *dst)
// {
// 	struct aes256_ctx ctx;

// 	aes256_set_decrypt_key(&ctx, AES_KEY);
// 	aes256_decrypt(&ctx, TC_POLL_LEN, dst, devc->buf);

// 	if (RL32(dst + OFF_PAC1) != MAGIC_PAC1 ||
// 	    RL32(dst + OFF_PAC2) != MAGIC_PAC2 ||
// 	    RL32(dst + OFF_PAC3) != MAGIC_PAC3) {
// 		sr_err("Invalid poll packet magic values!");
// 		return SR_ERR;
// 	}

// 	if (!check_pac_crc(dst + OFF_PAC1) ||
// 	    !check_pac_crc(dst + OFF_PAC2) ||
// 	    !check_pac_crc(dst + OFF_PAC3)) {
// 		sr_err("Invalid poll checksum!");
// 		return SR_ERR;
// 	}

// 	return SR_OK;
// }

static int tplink_hs_tcp_encrypt(char *msg, int len)
{
	int i;
	char key = 171;

	for (i = 0; i < len; i++)
	{
		key ^= msg[i];
		msg[i] = key;
	}

	return SR_OK;
}

static int tplink_hs_tcp_decrypt(char *msg, int len)
{
	int i;
	char key = 171;
	char temp;

	for (i = 0; i < len; i++)
	{
		temp = key ^ msg[i];
		key = msg[i];
		msg[i] = temp;
	}

	return SR_OK;
}

// static char *tplink_hs_tcp_encrypt(char *msg)
// {
// 	int padding = 4;
// 	int outputLen;
// 	char *output;
// 	char key = 171;

// 	outputLen = strlen(msg) + padding + 1
// 	output = g_malloc0(outputLen)

// 	output[3] = (char) strlen(msg) * (padding > 0);

// 	for (int i = 0; i < strlen(msg); i++)
// 	{
// 		char temp = key ^ (char)msg[i];
// 		key = temp;
// 		output[i + padding] = temp;
// 	}

// 	return output;
// }

// static char *tplink_hs_tcp_decrypt(char *msg, int len)
// {
// 	int padding = 4;
// 	char *output = (char *)g_malloc0(len);
// 	char key = 171;

// 	for (int i = padding; i < len; i++)
// 	{
// 		char temp = key ^ (char)msg[i];
// 		key = msg[i];
// 		output[i - padding] = temp;
// 	}
// 	output[strlen(output) - 1] = '\0';

// 	return output;
// }

static int tplink_hs_tcp_open(struct dev_context *devc)
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
	sr_spew("FG: tplink_hs_tcp_close");

	if (close(devc->socket) < 0)
		return SR_ERR;

	return SR_OK;
}

static int tplink_hs_tcp_send_cmd(struct dev_context *devc,
				    const char *msg)
{
	int len, out;
	char *buf;

	len = strlen(msg);

	buf = g_malloc0(len + MESSAGE_PADDING_SIZE);
	memcpy(buf + MESSAGE_PADDING_SIZE, msg, len);

	sr_spew("FG: Unencrypted command: '%s'.", buf + MESSAGE_PADDING_SIZE);

	// if (buf[len - 1] != '\n')
	// 	buf[len] = '\n';

	tplink_hs_tcp_encrypt(buf + MESSAGE_PADDING_SIZE, len);
	buf[MESSAGE_SIZE_OFFSET] = len;
	out = send(devc->socket, buf, len + MESSAGE_PADDING_SIZE, 0);

	if (out < 0) {
		sr_err("Send error: %s", g_strerror(errno));
		g_free(buf);
		return SR_ERR;
	}

	if (out < len + MESSAGE_PADDING_SIZE) {
		sr_dbg("Only sent %d/%zu bytes of command: '%s'.", out,
		       strlen(buf), buf);
	}

	sr_spew("Sent command: '%s'.", buf + MESSAGE_PADDING_SIZE);

	g_free(buf);

	return SR_OK;
}

static int tplink_hs_tcp_read_data(struct dev_context *devc, char *buf,
				     int maxlen)
{
	int len;

	len = recv(devc->socket, buf, maxlen, 0);

	if (len > 0)
		sr_spew("FG: len: '%d'.", len);

	if (len < 0) {
		sr_err("Receive error: %s", g_strerror(errno));
		return SR_ERR;
	}

	if ((len - MESSAGE_PADDING_SIZE) < 0)
		return 0;

	len -= MESSAGE_PADDING_SIZE;
	memmove(buf, buf + MESSAGE_PADDING_SIZE, len);
	tplink_hs_tcp_decrypt(buf, len);

	sr_spew("FG: data received: '%s'.", buf);

	return len;
}

static int tplink_hs_tcp_drain(struct dev_context *devc)
{
	char *buf = g_malloc(1024);
	fd_set rset;
	int ret, len = 0;
	struct timeval tv;

	FD_ZERO(&rset);
	FD_SET(devc->socket, &rset);

	/* 25ms timeout */
	tv.tv_sec = 0;
	tv.tv_usec = 25 * 1000;

	do {
		ret = select(devc->socket + 1, &rset, NULL, NULL, &tv);
		if (ret > 0)
			len += tplink_hs_tcp_read_data(devc, buf, 1024);
	} while (ret > 0);

	sr_spew("Drained %d bytes of data.", len);

	g_free(buf);

	return SR_OK;
}

static int tplink_hs_tcp_get_json(struct dev_context *devc, const char *cmd,
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

static int tplink_hs_get_node_value(char *string, char *node_name,
				      char **value)
{
	char *node_start;
	char *value_start;
	char *value_end;

	*value = NULL;

	node_start = strstr(string, node_name);
	if (node_start == NULL)
		return SR_ERR;

	value_start = node_start + strlen(node_name) + 2;

	if (*value_start == '\"')
		value_start += 1;

	value_end = strstr(value_start, ",");
	if (value_end == NULL)
		return SR_ERR;

	if (*(value_end - 1) == '\"')
		value_end -= 1;

	*value = g_strndup(value_start, value_end - value_start);

	return SR_OK;
}

// static int tplink_hs_tcp_get_sysinfo(struct dev_context *devc,
// 				      struct sysinfo **resp)
// {
// 	char *response = g_malloc0(1024);
// 	int len;
// 	gint64 timeout;

// 	*resp = NULL;
// 	if (tplink_hs_tcp_send_cmd(devc, CMD_SYSINFO_MSG) != SR_OK)
// 		return SR_ERR;

// 	timeout = g_get_monotonic_time() + devc->read_timeout;
// 	len = tplink_hs_tcp_read_data(devc, response, 1024);

// 	if (len < 0) {
// 		g_free(response);
// 		return SR_ERR;
// 	}

// 	if (g_get_monotonic_time() > timeout) {
// 		sr_err("Timed out waiting for response.");
// 		g_free(response);
// 		return SR_ERR_TIMEOUT;
// 	}

// 	sr_spew("Got response: '%.70s', length %d.",
// 		response, len);

// 	*resp = g_malloc0(sizeof(struct sysinfo));
// 	if (strstr(response, "HS110") != NULL)
// 		(*resp)->model = "HS110";

// 	return SR_OK;
// }

// static int tplink_hs_tcp_detect(struct dev_context *devc)
// {
// 	// struct sysinfo *resp = NULL;
// 	char *resp = NULL;
// 	int ret;

// 	ret = tplink_hs_tcp_get_json(devc, CMD_SYSINFO_MSG, &resp);
// 	// sr_spew("FG: tplink_hs_tcp_get_string(): '%s'.", resp->model);


// 	if (ret == SR_OK && strstr(resp, "HS110") != NULL)
// 		ret = SR_OK;
// 	else
// 		ret = SR_ERR;

// 	g_free(resp);

// 	return ret;
// }

static int tplink_hs_start(struct dev_context *devc)
{
	tplink_hs_tcp_drain(devc);

	if (tplink_hs_tcp_send_cmd(devc, CMD_REALTIME_MSG) != SR_OK)
		return SR_ERR;

	devc->cmd_sent_at = g_get_monotonic_time() / 1000;

	return SR_OK;
}

static int tplink_hs_stop(struct dev_context *devc)
{
	sr_spew("FG: tplink_hs_stop");

	tplink_hs_tcp_drain(devc);

	sr_spew("FG: tplink_hs_stop - DONE");

	return SR_OK;
}

SR_PRIV int tplink_hs_probe(struct dev_context  *devc)
{
	// int len;
	// uint8_t poll_pkt[TC_POLL_LEN];
	char *resp = NULL;

	if (tplink_hs_tcp_open(devc) != SR_OK)
		return SR_ERR;
	// if (tplink_hs_tcp_detect(devc) != SR_OK)
	// 	goto err;

	// return SR_OK;

	if (tplink_hs_tcp_get_json(devc, CMD_SYSINFO_MSG, &resp) != SR_OK)
		goto err;
	if (tplink_hs_tcp_close(devc) != SR_OK)
		goto err;

	if (strstr(resp, "HS110") == NULL) {
		sr_err("Unrecognized HS device");
		goto err;
	}


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

	devc->dev_info.channels = tplink_hs_channels;
	// devc->dev_info.model_name = g_strndup((const char *)poll_pkt + OFF_MODEL, LEN_MODEL);
	// devc->dev_info.fw_ver = g_strndup((const char *)poll_pkt + OFF_FW_VER, LEN_FW_VER);
	// devc->dev_info.serial_num = RL32(poll_pkt + OFF_SERIAL);

	if (tplink_hs_get_node_value(resp, "model",
				       &devc->dev_info.model) != SR_OK)
		goto err;
	if (tplink_hs_get_node_value(resp, "sw_ver",
				       &devc->dev_info.sw_ver) != SR_OK)
		goto err;
	if (tplink_hs_get_node_value(resp, "deviceId",
				       &devc->dev_info.device_id) != SR_OK)
		goto err;

	g_free(resp);

	sr_spew("Registered device: %s - %s - %s", devc->dev_info.model,
						   devc->dev_info.sw_ver,
						   devc->dev_info.device_id);
	// sr_spew("FG: %s", devc->dev_info.sw_ver);
	// sr_spew("FG: %s", devc->dev_info.device_id);

	// devc->dev_info.model_name = g_strndup(strstr(resp, "model") + 7, LEN_MODEL);
	// devc->dev_info.fw_ver = g_strndup((const char *)poll_pkt + OFF_FW_VER, LEN_FW_VER);
	// devc->dev_info.serial_num = RL32(poll_pkt + OFF_SERIAL);

	return SR_OK;

err:
	g_free(devc->dev_info.model);
	g_free(devc->dev_info.sw_ver);
	g_free(devc->dev_info.device_id);
	g_free(resp);

	return SR_ERR;
}

// SR_PRIV int tplink_hs_poll(const struct sr_dev_inst *sdi)
// {
// 	struct dev_context *devc = sdi->priv;
// 	struct sr_serial_dev_inst *serial = sdi->conn;

// 	if (serial_write_blocking(serial, &POLL_CMD, sizeof(POLL_CMD) - 1,
//                                   SERIAL_WRITE_TIMEOUT_MS) < 0) {
// 		sr_err("Unable to send poll request.");
// 		return SR_ERR;
// 	}

// 	devc->cmd_sent_at = g_get_monotonic_time() / 1000;

// 	return SR_OK;
// }

static void handle_poll_data(const struct sr_dev_inst *sdi)
{
	struct dev_context *devc = sdi->priv;
	// uint8_t poll_pkt[TC_POLL_LEN];
	// int i;
	// GSList *ch;
	struct sr_datafeed_packet packet;
	struct sr_datafeed_analog analog;
	struct sr_analog_encoding encoding;
	struct sr_analog_meaning meaning;
	struct sr_analog_spec spec;
	// float data[devc->dev_info.num_channels];
	// float data[2];
	int i;

	sr_analog_init(&analog, &encoding, &meaning, &spec, 0);

	packet.type = SR_DF_ANALOG;
	packet.payload = &analog;
	// analog.meaning->channels = sdi->channels;
	analog.num_samples = 1;

	for (i = 0; devc->dev_info.channels[i].name; i++) {
		analog.meaning->mq = devc->dev_info.channels[i].mq;
		analog.meaning->unit = devc->dev_info.channels[i].unit;
		analog.meaning->mqflags = SR_MQFLAG_DC;
		analog.encoding->digits = 6;
		analog.spec->spec_digits = 6;
		// analog.data = data;

		if (devc->dev_info.channels[i].mq == SR_MQ_VOLTAGE) {
			analog.meaning->channels =
				g_slist_append(NULL, sdi->channels->data);
			analog.data = &devc->voltage;
		}
		else if (devc->dev_info.channels[i].mq == SR_MQ_CURRENT) {
			analog.meaning->channels =
				g_slist_append(NULL, sdi->channels->next->data);
			analog.data = &devc->current;
		}

		sr_session_send(sdi, &packet);
	}


	// sr_spew("Received poll packet (len: %d).", devc->buflen);
	// if (devc->buflen != TC_POLL_LEN) {
	// 	sr_err("Unexpected poll packet length: %i", devc->buflen);
	// 	return;
	// }

	// if (process_poll_pkt(devc, poll_pkt) != SR_OK) {
	// 	sr_err("Failed to process poll packet.");
	// 	return;
	// }

	// for (ch = sdi->channels, i = 0; ch; ch = g_slist_next(ch), i++) {
	// 	bv_send_analog_channel(sdi, ch->data,
	// 			       &devc->channels[i], poll_pkt, TC_POLL_LEN);
 	// }

	sr_sw_limits_update_samples_read(&devc->limits, 1);
}

static int recv_poll_data(struct sr_dev_inst *sdi)
{
	struct dev_context *devc = sdi->priv;
	char *response = g_malloc0(1024);
	char *node_current_value;
	char *node_voltage_value;
	int len;

	// /* Serial data arrived. */
	// while (devc->buflen < TC_POLL_LEN) {
	// 	len = serial_read_nonblocking(serial, devc->buf + devc->buflen, 1);
	// 	if (len < 1)
	// 		return;

	// 	devc->buflen++;
	// }

	// if (devc->buflen == TC_POLL_LEN)
	// 	handle_poll_data(sdi);

	// devc->buflen = 0;


	len = tplink_hs_tcp_read_data(devc, response, 1024);

	if (len < 0)
		goto err;

	if (tplink_hs_get_node_value(response, "current",
			       &node_current_value) != SR_OK)
		goto err;
	if (tplink_hs_get_node_value(response, "voltage",
			       &node_voltage_value) != SR_OK)
		goto err;

	sr_spew("volatage: %s, current: %s", node_voltage_value,
					     node_current_value);

	devc->voltage = strtof(node_voltage_value, NULL);
	devc->current = strtof(node_current_value, NULL);

	sr_spew("volatage(f): %f, current(f): %f", devc->voltage,
						    devc->current);

	handle_poll_data(sdi);

	g_free(response);
	return SR_OK;

err:
	g_free(response);
	return SR_ERR;

}

SR_PRIV int tplink_hs_receive_data(int fd, int revents, void *cb_data)
{
	struct sr_dev_inst *sdi;
	struct dev_context *devc;
	// struct sr_serial_dev_inst *serial;
	int64_t now, elapsed;

	(void)fd;

	if (!(sdi = cb_data))
		return TRUE;

	if (!(devc = sdi->priv))
		return TRUE;

	// serial = sdi->conn;
	if (revents == G_IO_IN) {
		sr_info("In callback G_IO_IN");
		recv_poll_data(sdi);
		tplink_hs_tcp_close(devc);
	}

	if (sr_sw_limits_check(&devc->limits)) {
		sr_dev_acquisition_stop(sdi);
		return TRUE;
	}

	now = g_get_monotonic_time() / 1000;
	elapsed = now - devc->cmd_sent_at;

	if (elapsed > HS_POLL_PERIOD_MS) {
		// tplink_hs_poll(sdi);
		// sr_session_source_remove_pollfd(sdi->session, &devc->pollfd);
		tplink_hs_tcp_open(devc);
		// sdi->driver->dev_open(sdi);
		// sr_session_source_add_pollfd(sdi->session, &devc->pollfd,
		// 	1000, tplink_hs_receive_data,
		// 	(void *)sdi);
		// tplink_hs_start(devc);
		if (tplink_hs_tcp_send_cmd(devc, CMD_REALTIME_MSG) == SR_OK)
			devc->cmd_sent_at = g_get_monotonic_time() / 1000;
	}

	return TRUE;
}

SR_PRIV const struct tplink_hs_ops tplink_hs_dev_ops = {
	.open = tplink_hs_tcp_open,
	.close = tplink_hs_tcp_close,
	// .get_buffersize = beaglelogic_get_buffersize,
	// .set_buffersize = beaglelogic_set_buffersize,
	// .get_samplerate = beaglelogic_get_samplerate,
	// .set_samplerate = beaglelogic_set_samplerate,
	// .get_sampleunit = beaglelogic_get_sampleunit,
	// .set_sampleunit = beaglelogic_set_sampleunit,
	// .get_triggerflags = beaglelogic_get_triggerflags,
	// .set_triggerflags = beaglelogic_set_triggerflags,
	.start = tplink_hs_start,
	.stop = tplink_hs_stop,
	// .get_lasterror = beaglelogic_get_lasterror,
	// .get_bufunitsize = beaglelogic_get_bufunitsize,
	// .set_bufunitsize = beaglelogic_set_bufunitsize,
	// .mmap = dummy,
	// .munmap = dummy,
};
