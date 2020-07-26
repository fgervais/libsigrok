/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2014-2017 Kumar Abhishek <abhishek@theembeddedkitchen.net>
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

#ifndef TPLINK_HS_H_
#define TPLINK_HS_H_

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <unistd.h>

/* Possible States of tplink_hs */
enum tplink_hs_states {
	STATE_BL_DISABLED,	/* Powered off (at module start) */
	STATE_BL_INITIALIZED,	/* Powered on */
	STATE_BL_MEMALLOCD,	/* Buffers allocated */
	STATE_BL_ARMED,		/* All Buffers DMA-mapped and configuration done */
	STATE_BL_RUNNING,	/* Data being captured */
	STATE_BL_REQUEST_STOP,	/* Stop requested */
	STATE_BL_ERROR   	/* Buffer overrun */
};

/* Setting attributes */
// enum tplink_hs_triggerflags {
// 	BL_TRIGGERFLAGS_ONESHOT = 0,
// 	BL_TRIGGERFLAGS_CONTINUOUS
// };

/* Possible sample unit / formats */
// enum tplink_hs_sampleunit {
// 	BL_SAMPLEUNIT_16_BITS = 0,
// 	BL_SAMPLEUNIT_8_BITS
// };
/* END tplink_hs.h */

/* For all the functions below:
 * Parameters:
 * 	devc : Device context structure to operate on
 * Returns:
 * 	SR_OK or SR_ERR
 */

struct tplink_hs_ops {
	int (*open)(struct dev_context *devc);
	int (*close)(struct dev_context *devc);

	// int (*get_buffersize)(struct dev_context *devc);
	// int (*set_buffersize)(struct dev_context *devc);

	// int (*get_samplerate)(struct dev_context *devc);
	// int (*set_samplerate)(struct dev_context *devc);

	// int (*get_sampleunit)(struct dev_context *devc);
	// int (*set_sampleunit)(struct dev_context *devc);

	// int (*get_triggerflags)(struct dev_context *devc);
	// int (*set_triggerflags)(struct dev_context *devc);

	/* Start and stop the capture operation */
	int (*start)(struct dev_context *devc);
	int (*stop)(struct dev_context *devc);

	// /* Get the last error size */
	// int (*get_lasterror)(struct dev_context *devc);

	// /* Gets the unit size of the capture buffer (usually 4 or 8 MB) */
	// int (*get_bufunitsize)(struct dev_context *devc);
	// int (*set_bufunitsize)(struct dev_context *devc);

	// int (*mmap)(struct dev_context *devc);
	// int (*munmap)(struct dev_context *devc);
};

// SR_PRIV extern const struct tplink_hs_ops tplink_hs_native_ops;
SR_PRIV extern const struct tplink_hs_ops tplink_hs_dev_ops;

// SR_PRIV int tplink_hs_tcp_detect(struct dev_context *devc);
// SR_PRIV int tplink_hs_tcp_drain(struct dev_context *devc);

#endif
