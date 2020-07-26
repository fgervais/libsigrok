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

#ifndef LIBSIGROK_HARDWARE_TPLINK_HS_PROTOCOL_H
#define LIBSIGROK_HARDWARE_TPLINK_HS_PROTOCOL_H

#include <libsigrok/libsigrok.h>
#include "libsigrok-internal.h"

#define LOG_PREFIX "tplink-hs"

// #define TPLINK_HS_BUFSIZE 256

struct channel_spec {
	const char *name;
	int type;
	enum sr_mq mq;
	enum sr_unit unit;
};

struct tplink_dev_info {
	char *model;
	char *sw_ver;
	char *device_id;

	// int num_channels;
	const struct channel_spec *channels;
};

struct dev_context {
	struct tplink_dev_info dev_info;

	const struct tplink_hs_ops *ops;

	// const struct binary_analog_channel *channels;
	struct sr_sw_limits limits;

	// uint8_t buf[TPLINK_HS_BUFSIZE];
	// int buflen;
	int64_t cmd_sent_at;

	char *address;
	char *port;
	int socket;
	unsigned int read_timeout;
	// unsigned char *tcp_buffer;

	GPollFD pollfd;

	float current;
	float voltage;
};

SR_PRIV int tplink_hs_probe(struct dev_context  *devc);
SR_PRIV int tplink_hs_receive_data(int fd, int revents, void *cb_data);
// SR_PRIV int tplink_hs_poll(const struct sr_dev_inst *sdi);

#endif
