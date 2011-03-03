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

#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <pwd.h>
#include <time.h>
#include <ctype.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common/common.h"
#include "common/list.h"
#include "src/lmtpd.h"

static char *root_alias = DEFAULT_ROOT;
static char *mbox_dir = DEFAULT_MBOX;

static uint16_t original_socket = 0;
static int64_t lock_file = 0;

int main(int argc, char **argv)
{
    init(NAME, VERSION);

    /*
     *get hold of lock file
     */
    lock_file = open(LOCK_FILE, O_WRONLY | O_TRUNC | O_CREAT | F_WRLCK, S_IRUSR | S_IWUSR);
    if (lock_file < 0)
        die("cannot acquire file lock, check %s isn't already running and try again", NAME);

    chdir(RUN_DIR);

    uint16_t port = DEFAULT_PORT;
    bool local_only = DEFAULT_LOCAL;
    char *log_file = DEFAULT_LOG;

    list_t *opts = config(CONFIG_FILE);
    list_t *x = opts;
    uint64_t i = 0;
    while (true)
    {
        conf_t *c = (conf_t *)x->object;
        if (!strcmp(CONF_LOG, c->option))
            log_file = c->value;
        else if (!strcmp(CONF_PORT, c->option))
            port = (uint16_t)strtol(c->value, NULL, 0);
        else if (!strcmp(CONF_LOCAL, c->option))
        {
            if (!strcmp(FALSE, c->value))
                local_only = false;
        }
        else if (!strcmp(CONF_ROOT, c->option))
            root_alias = c->value;
        else if (!strcmp(CONF_MBOX, c->option))
            mbox_dir = c->value;
        x = x->next;
        if (!x)
            break;
        i++;
    }
#if 0
    list_delete(&opts);
#endif

    while (true)
    {
        static struct option long_options[] =
        {
            {"log_file"  , required_argument, 0, 'f'},
            {"port"      , required_argument, 0, 'p'},
            {"anyhost"   ,       no_argument, 0, 'x'},
            {"root_alias", required_argument, 0, 'r'},
            {"mbox_dir"  , required_argument, 0, 'm'},
            {"help"      ,       no_argument, 0, 'h'},
            {"licence"   ,       no_argument, 0, 'l'},
            {"version"   ,       no_argument, 0, 'v'},
            {0, 0, 0, 0}
        };
        int32_t optex = 0;
        int32_t opt = getopt_long(argc, argv, "f:p:xr:m:hlv", long_options, &optex);
        if (opt < 0)
            break;
        switch (opt)
        {
            case 'g':
                log_file = strdup(optarg);
                break;
            case 'p':
                port = (uint16_t)strtol(optarg, NULL, 0);
                break;
            case 'x':
                local_only = false;
                break;
            case 'r':
                root_alias = strdup(optarg);
                break;
            case 'm':
                mbox_dir = strdup(optarg);
                break;
            case 'l':
                return show_licence();
            case 'v':
                return show_version();
            case '?':
            default:
                die("unknown option %c", opt);
                /*
                 * it's worth noting that unknown options cause encrypt to bail
                 */
        }
    }

    redirect_log(log_file);

    lmtpd_daemonize(port, local_only);

    while (true)
        sleep(1);

    return EXIT_SUCCESS;
}

static void lmtpd_daemonize(uint16_t port, bool local_only)
{
    pid_t pid = fork();
    if (pid < 0)
        die("could not fork daemon process");
    else if (pid > 0)
        exit(EXIT_SUCCESS); /* parent process exits */

    /*
     * perform some general daemon house keeping
     */
    struct sigaction sa;
    sa.sa_handler = lmtpd_wait;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1)
        die("unable to handle child processes");
    if ((signal(SIGTERM, lmtpd_stop) == SIG_ERR) || (signal(SIGINT, lmtpd_stop) == SIG_ERR))
        die("could not set custom signal handler");
    signal(SIGCHLD, SIG_IGN);
    setsid();
    {
        char *p = NULL;
        asprintf(&p, "%d\n", getpid());
        if (!p)
            die("out of memory @ %s:%i", __FILE__, __LINE__ - 2);
        write(lock_file, p, strlen(p));
    }

    uint16_t original_socket = socket_create(port);
    if (listen(original_socket, 1) < 0)
        die("could not listen on socket");

    msg("server up and running");
    while(true)
    {
        struct sockaddr_in client;
        char caddr[INET_ADDRSTRLEN];
        uint32_t z = sizeof( client );
        int32_t n = accept(original_socket, (struct sockaddr *)&client, &z);
        if (n < 0)
            die("could not accept on socket");

        inet_ntop(AF_INET, &client.sin_addr, caddr, INET_ADDRSTRLEN);
        if (local_only) /* only allow localhost, else allow everybody */
        {
            if (strcmp(LOCALHOST, caddr))
            {
                close(n);
                continue;
            }
        }
        msg("connection from %s:%hu", caddr, ntohs(client.sin_port));

        pid = fork();
        if (pid < 0)
            die("could not fork daemon process");
        else if (pid > 0)
            close(n);
        else /* spawn child prcess for connection */
        {
            close(original_socket);
            message_recieve(n);
            msg("closed connection with %s:%hu", caddr, ntohs(client.sin_port));
            close(n);
            _exit(EXIT_SUCCESS);
        }
    }
}

static void lmtpd_wait(int s)
{
    msg("waiting for child %i", s);
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

static void lmtpd_stop(int s)
{
    char *ss = NULL;
    switch (s)
    {
        case SIGTERM:
            ss = strdup("SIGTERM");
            break;
        case SIGINT:
            ss = strdup("SIGINT");
            break;
    }
    msg("caught %s signal, closing gracefully", ss);
    close(original_socket);
    close(lock_file);
    unlink(LOCK_FILE);
    errno = ECANCELED;
    exit(EXIT_SUCCESS);
}

static uint16_t socket_create(uint16_t p)
{
    struct sockaddr_in name;
    int32_t s = socket(PF_INET, SOCK_STREAM, 0);
    if (s < 0)
        die("could not create socket");
    name.sin_family = AF_INET;
    name.sin_port = htons(p);
    name.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(s, (struct sockaddr *)&name, sizeof( name )) < 0)
        die("could not bind socket");
    return (uint16_t)s;
}

static char *socket_read(int s, size_t *l)
{
    char *d = calloc(BUFFER, sizeof( char ));
    if (!d)
        die("out of memory @ %s:%i", __FILE__, __LINE__ - 2);
    uint64_t z = 1;
    *l = 0;
    while (true)
    {
        char c;
        int r = 0;
        if ((r = read(s, &c, 1)) < 0)
            die("could not read from socket");
        if (!r)
            continue;
        if (c == '\n')
            break;
        d[*l] = c;
        (*l)++;
        if (*l > (z * BUFFER) - sizeof( uint64_t ))
        {
            z++;
            char *x = realloc(d, z * BUFFER);
            if (!x)
                die("out of memory @ %s:%i", __FILE__, __LINE__ - 2);
            d = x;
        }

    }
    msg("C: %s", d);
    return d;
}

static void socket_send(int s, char *m)
{
    char *d = NULL;
    asprintf(&d, "%s\r\n", m);
    msg("S: %s", m);
    if (!d)
        die("out of memory @ %s:%i", __FILE__, __LINE__ - 2);
    if (write(s, d, strlen(d)) < 0)
        die("could not send data: %s", m);
}

static void message_recieve(int32_t s)
{
    char *r;
    size_t l = 0;
    time_t date = time(NULL);

    /* send greeting, wait for response */
    socket_send(s, MESSAGE_220);
    r = socket_read(s, &l);
    validate(MESSAGE_LHLO, r);
    char *cname = strdup(r + strlen(MESSAGE_LHLO));
    free(r);

    /* send welcome, wait for sender */
    {
        char *x = NULL;
        for (int i = strlen(cname); i > 0; i--)
            if (isspace(cname[i]))
                cname[i] = '\0';
        asprintf(&x, MESSAGE_250A, cname);
        free(cname);
        socket_send(s, x);
    }
    r = socket_read(s, &l);
    validate(MESSAGE_FROM, r);
    char *from = extract_address(r);
    free(r);

    /* ok, wait for recipients (loop until DATA) */
    int rcp = 0;
    char **rcpt = calloc(rcp + 1, sizeof( char * ));
    if (!rcpt)
        die("out of memory @ %s:%i", __FILE__, __LINE__ - 2);
    while (true)
    {
        socket_send(s, MESSAGE_250);
        r = socket_read(s, &l);
        if (!strncmp(MESSAGE_DATA, r, strlen(MESSAGE_DATA)))
            break;
        validate(MESSAGE_RCPT, r);
        rcpt[rcp] = extract_address(r);
        rcp++;
        char **x = realloc(rcpt, rcp * sizeof( char * ) + 1);
        if (!x)
            die("out of memory @ %s:%i", __FILE__, __LINE__ - 2);
        free(r);
    }
    free(r);

    /* send 352, wait for .\n\r */
    socket_send(s, MESSAGE_354);
    char *data = NULL;
    uint64_t dl = 0;
    while (true)
    {
        r = socket_read(s, &l);
        if (!strcmp(MESSAGE_STOP, r))
            break;
        char *x = realloc(data, l + dl);
        if (!x)
            die("out of memory @ %s:%i", __FILE__, __LINE__ - 2);
        data = x;
        if ((x = convert_from_prefix(r)))
        {
            free(r);
            r = x;
            l++;
        }
        uint8_t dd = convert_double_dot(r);
        if (dd)
            l--;
        memcpy(data + dl, r + dd, l);
        dl += l;
        free(r);
    }
    free(r);
    convert_new_line(data);
    data[dl] = '\0';

    /* ok, wait for QUIT */
    for (int i = 0; i < rcp; i++)
    {
        char *x = NULL;
        asprintf(&x, MESSAGE_250C, rcpt[i]);
        socket_send(s, x);
        free(x);
    }
    r = socket_read(s, &l);
    validate(MESSAGE_QUIT, r);
    free(r);
    /* bye, close */
    socket_send(s, MESSAGE_221);

    for (int i = 0; i < rcp; i++)
    {
        char *usr = rcpt[i];
        /* lookup the user; if root, find alias instead */
        if (!strcmp(ROOT, usr))
        {
            usr = root_alias;
        }
        struct passwd *pw = getpwnam(usr);
        if (!pw)
            continue;
        uid_t uid = pw->pw_uid;
        gid_t gid = pw->pw_gid;
        /* write the message to the mail box */
        char *mesg = NULL;
        asprintf(&mesg, "From %s %s%s\n", from, ctime(&date), data);
        char *mbn = NULL;
        asprintf(&mbn, "%s/%s", mbox_dir, usr);
        int64_t mbox = open(mbn, O_WRONLY | O_APPEND | O_CREAT | F_WRLCK);
        if (mbox < 0)
            die("could not access mail box %s", mbn);
        free(mbn);
        write(mbox, mesg, strlen(mesg));
        fchown(mbox, uid, gid);
        fchmod(mbox, S_IRUSR | S_IWUSR);
        close(mbox);
        free(rcpt[i]);
        free(mesg);
    }
    free(rcpt);
    free(data);
}

static void validate(char *m, char *d)
{
    if (strncmp(m, d, strlen(m)))
        die("unexpected message from client: %s", d);
}

static char *extract_address(char *r)
{
    for (int i = strlen(r); i > 0; i--)
        if (r[i] == '>')
            r[i] = '\0';
    return strdup(strchr(r, '<') + 1);
}

static uint8_t convert_double_dot(char *r)
{
    uint8_t dd = 0;
    if (!strncmp(DOUBLE_DOT, r, strlen(DOUBLE_DOT)))
    {
        dd = 1;
    }
    return dd;
}

static char *convert_from_prefix(char *r)
{
    if (strncmp(FROM_PREFIX, r, strlen(FROM_PREFIX)))
        return NULL;
    char *x = calloc(strlen(r) + 2, sizeof( char ));
    if (!x)
        die("out of memory @ %s:%i", __FILE__, __LINE__ - 2);
    memmove(x + 1, r, strlen(r));
    x[0] = '>';
    return x;
}

static void convert_new_line(char *d)
{
    for (unsigned i = 0; i < strlen(d); i++)
        if (d[i] == '\r')
            d[i] = '\n';
}


int64_t show_help(void)
{
    fprintf(stderr, "\nOptions:\n\n");
    fprintf(stderr, "-f, --log_file\n");
    fprintf(stderr, "-p, --port\n");
    fprintf(stderr, "-x, --anyhost\n");
    fprintf(stderr, "-r, --root_alias\n");
    fprintf(stderr, "-m, --mbox_dir\n");
    fprintf(stderr, "-v, --help\n");
    fprintf(stderr, "-v, --licence\n");
    fprintf(stderr, "-v, --version\n");

    return EXIT_SUCCESS;
}
