/*
 * lmtpd ~ a simple local mail transfer protocol daemon for msmtp
 * Copyright (c) 2007-2010, albinoloverats ~ Software Development
 * email: lmtpd@albinoloverats.net
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
 *
 */

#ifndef _LMTPD_H_
#define _LMTPD_H_

#define NAME "lmtpd"
#define VERSION "201009"


/*
 * config file parameter names and defaults
 */
#define CONFIG_FILE "/etc/lmtpd.conf"

#define CONF_LOG "log_file"
#define DEFAULT_LOG "/var/log/lmtpd.log"

#define CONF_PORT "port"
#define DEFAULT_PORT 2710

#define CONF_LOCAL "localhost_only"
#define DEFAULT_LOCAL true

#define CONF_ROOT "root_alias"
#define DEFAULT_ROOT "root"

#define CONF_MBOX "mbox_dir"
#define DEFAULT_MBOX "/var/mail/"

/*
 * misc constants
 */
#define RUN_DIR "/var/run"
#define LOCK_FILE RUN_DIR "/lmtpd.lock"

#define LOCALHOST "127.0.0.1"
#define BUFFER 1024
#define ROOT "root"
#define FALSE "false"

/*
 * standard message prefixes
 */
#define MESSAGE_220 "220 lmtp.localhost LMTP Postfix"
#define MESSAGE_250A "250 Hello %s, I am glad to meet you"
#define MESSAGE_250 "250 Ok"
#define MESSAGE_250C "250 Ok, message queued for %s"
#define MESSAGE_354 "354 End data with <CR><LF>.<CR><LF>"
#define MESSAGE_221 "221 Bye bye"

#define MESSAGE_LHLO "LHLO "
#define MESSAGE_FROM "MAIL FROM:"
#define MESSAGE_RCPT "RCPT TO:"
#define MESSAGE_DATA "DATA"
#define MESSAGE_STOP ".\r"
#define MESSAGE_QUIT "QUIT"

#define DOUBLE_DOT ".."
#define FROM_PREFIX "From "


/*
 * functions
 */
static void lmtpd_daemonize(uint16_t, bool);
static void lmtpd_wait(int);
static void lmtpd_stop(int);

static uint16_t socket_create(uint16_t);
static char *socket_read(int, size_t *);
static void socket_send(int, char *);

static void message_recieve(int32_t);

static void validate(char *, char *);
static char *extract_address(char *);
static uint8_t convert_double_dot(char *);
static char *convert_from_prefix(char *);
static void convert_new_line(char *);

#endif /* _LMTPD_H_ */
