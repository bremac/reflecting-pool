#define _GNU_SOURCE

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <sys/epoll.h>
#include <sys/socket.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bpf.h"
#include "checksum.h"
#include "definitions.h"
#include "localaddrs.h"
#include "sessions.h"
#include "util.h"


// TODO: IPv6 support
// TODO: Naming and abstraction inconsistent in this module.
// TODO: Do we need to check SO_ERROR in the epoll loop, or is this
//       covered by EPOLLERR?
//       See http://stackoverflow.com/a/6206705
// TODO: Pass time to session_allocate and session_insert
// TODO: Add tests for failure cases to the test suite.
// TODO: Move dispatch_packet to sessions module after removing I/O calls.
//       This will let us to test dispatch and decoding logic.
// TODO: Explantory module comments for each module, plus key functions.
// TODO: Add ability to write to a log file.

static int is_daemon = 0;
static int listen_port = -1;
static const char *forward_host = NULL;
static const char *forward_port = NULL;
static const char *log_filename = NULL;
static const char *username = "_reflectd";
static size_t raw_buffer_size = 10 * 1024 * 1024;

static double forward_percentage = 100;
static unsigned int max_connections = 200;
static size_t window_size_bytes = 300 * 1024;

static uint32_t *local_addrs;
static struct sessiontable *table;
static int raw_fd;
static int epoll_fd;


static int
unblock(int fd)
{
    int flags;

    if ((flags = fcntl(fd, F_GETFL, 0)) < 0)
        return -1;

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return -1;

    return 0;
}

static int
create_reflector_socket(void)
{
    struct addrinfo hints, *result = NULL;
    int error;
    int fd = -1;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;       // TODO: Use AF_UNSPEC and retry logic.
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    hints.ai_protocol = IPPROTO_TCP;
    error = getaddrinfo(forward_host, forward_port, &hints, &result);

    if (error != 0) {
        log_msg("connecting to target failed: %s", gai_strerror(error));
        goto err;
    }

    if ((fd = socket(result->ai_family, result->ai_socktype,
                     result->ai_protocol)) < 0) {
        log_error("failed to create socket for %s:%s",
                  forward_host, forward_port);
        goto err;
    }

    if (unblock(fd) < 0) {
        log_error("failed to make socket non-blocking for %s:%s",
                  forward_host, forward_port);
        goto err;
    }

    if (connect(fd, result->ai_addr, result->ai_addrlen) < 0 &&
        errno != EINPROGRESS) {
        log_error("failed to connect to %s:%s", forward_host, forward_port);
        goto err;
    }

    freeaddrinfo(result);
    return fd;

err:
    if (fd >= 0)
        close(fd);

    freeaddrinfo(result);
    return -1;
}

static int
epoll_register_session(struct session *session)
{
    struct epoll_event event;
    event.data.ptr = session;
    event.events = EPOLLIN | EPOLLOUT | EPOLLET;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, session->fd, &event) < 0) {
        log_error("failed to register session");
        return -1;
    }

    return 0;
}

void
read_and_discard_all(int fd, uint8_t *buffer, size_t size)
{
    int ret;

    do {
        ret = read(fd, buffer, size);
    } while (ret > 0);
}

void
session_write_all(struct session *session)
{
    struct segment *segment;
    ssize_t count;

    while ((segment = session_peek(session)) != NULL) {
        if (segment->length > 0) {
            count = write(session->fd, segment->dataptr, segment->length);

            if (count < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    log_error("failed to write to connection");
                    session_release(table, session);
                }

                return;
            }

            if (count < (ssize_t)segment->length) {
                segment->dataptr += count;
                segment->length -= count;
                return;
            }
        }

        if (segment->fin) {
            shutdown(session->fd, SHUT_WR);
        }

        if (segment->rst) {
            session_release(table, session);
            return;
        }

        session_pop(session);
    }
}

struct packet_in {
    size_t data_len;
    uint8_t *data;
    uint32_t seq_lower;
    uint32_t source_ip;
    uint32_t dest_ip;
    uint16_t source_port;
    uint16_t dest_port;
    uint8_t ack;
    uint8_t fin;
    uint8_t rst;
    uint8_t syn;
};

int
read_packet(uint8_t *buffer, size_t total_len, struct packet_in *pkt)
{
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    size_t ip_header_len, tcp_header_len, combined_header_len;

    if (total_len < sizeof(struct iphdr)) {
        log_msg("packet too small to contain an IP header");
        return -1;
    }

    ip_header = (struct iphdr *)buffer;
    ip_header_len = ip_header->ihl * 4;

    if (total_len - ip_header_len < sizeof(struct tcphdr)) {
        log_msg("packet too small to contain a TCP header");
        return -1;
    }

    tcp_header = (struct tcphdr *)(buffer + ip_header_len);
    tcp_header_len = tcp_header->doff * 4;

    pkt->seq_lower = ntohl(tcp_header->seq);
    pkt->source_ip = ntohl(ip_header->saddr);
    pkt->source_port = ntohs(tcp_header->source);
    pkt->dest_ip = ntohl(ip_header->daddr);
    pkt->dest_port = ntohs(tcp_header->dest);

    pkt->ack = tcp_header->ack;
    pkt->fin = tcp_header->fin;
    pkt->rst = tcp_header->rst;
    pkt->syn = tcp_header->syn;

    combined_header_len = ip_header_len + tcp_header_len;
    pkt->data_len = ntohs(ip_header->tot_len) - combined_header_len;
    pkt->data = buffer + combined_header_len;

    if (combined_header_len + pkt->data_len != total_len) {
        log_msg("packet length mismatch: %d + %d bytes vs. %lld",
                (int)combined_header_len, (int)pkt->data_len,
                (long long)total_len);
        return -1;
    }

    /* Discard packets from other machines with bad checksums.
     * Don't check packets from the local machine, as these are usually
     * wrong until they hit the NIC due to checksum offloading. */
    if (!is_local_address(local_addrs, pkt->source_ip)
        && !are_checksums_valid(ip_header, tcp_header)) {
        log_msg("packet has an invalid checksum");
        return -1;
    }

    return 0;
}

void
dispatch_packet(struct packet_in *pkt)
{
    struct session *session = NULL;
    struct segment *segment = NULL;

    if (pkt->rst && pkt->source_port == listen_port
        && is_local_address(local_addrs, pkt->source_ip)) {
        session = session_find(table, pkt->dest_ip, pkt->dest_port);
        session_release(table, session);
    }

    if (!is_local_address(local_addrs, pkt->dest_ip) ||
        pkt->dest_port != listen_port) {
        log_msg("received unexpected packet");
        return;
    }

    session = session_find(table, pkt->source_ip, pkt->source_port);

    /* New TCP connection is being established */
    if (pkt->syn && !pkt->ack) {
        if (session != NULL) {
            log_msg("received SYN packet for existing session");
            return;
        }

        /* Forward only a specified percentage of connections. */
        if ((double)random() * 100 / RAND_MAX > forward_percentage)
            return;

        session = session_allocate(table, pkt->source_ip, pkt->source_port,
                                   pkt->seq_lower + 1);

        if (session == NULL) {
            log_msg("unable to find available session, dropping packet");
            goto err;
        }

        session->fd = create_reflector_socket();
        if (session->fd < 0)
            goto err;

        if (epoll_register_session(session) < 0)
            goto err;
    } else {
        if (session == NULL)    /* not following this session */
            return;

        if (pkt->data_len == 0 && !pkt->fin && !pkt->rst)
            return;

        segment = segment_create(pkt->data_len);

        if (segment == NULL) {
            log_msg("could not allocate %llu byte segment",
                    (long long)pkt->data_len);
            goto err;
        }

        segment->seq = adjust_seq(pkt->seq_lower, session->next_seq);
        segment->length = pkt->data_len;
        if (pkt->data_len > 0)
            memcpy(segment->bytes, pkt->data, pkt->data_len);
        segment->dataptr = segment->bytes;
        segment->fin = pkt->fin;
        segment->rst = pkt->rst;

        session_insert(table, session, segment);
        session_write_all(session);
    }

    return;

err:
    segment_destroy(segment);
    session_release(table, session);
}

#define MAX_EVENTS (MAX_TCP_SESSIONS + 1)

void
initialize(void)
{
    FILE *fp;

    if (log_filename == NULL || !strcmp(log_filename, ""))
        log_init(stderr);
    else {
        if ((fp = fopen(log_filename, "a")) == NULL)
            err(1, "failed to open log file %s", log_filename);
        setlinebuf(fp);
        log_init(fp);
    }

    if ((raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
        err(1, "failed to create raw_fd socket");

    if (setsockopt(raw_fd, SOL_SOCKET, SO_RCVBUFFORCE,
                   &raw_buffer_size, sizeof(raw_buffer_size)) < 0)
        err(1, "failed to set receive buffer size");

    if (is_daemon) {
        daemon(0, 0);
        pidfile("reflectd");
    }

    setuser(username);

    if ((local_addrs = load_local_addresses()) == NULL)
        exit(1);

    bpf_attach(raw_fd, local_addrs, listen_port);

    if (unblock(raw_fd) < 0)
        err(1, "failed to make raw socket non-blocking");

    if ((table = sessiontable_create()) == NULL)
        exit(1);

    log_msg("forwarding packets from 0.0.0.0:%d to %s:%s",
            listen_port, forward_host, forward_port);

    srandom(time(NULL));
}

static void
raw_fd_ready(int events)
{
    struct packet_in pkt;
    struct sockaddr _addr;
    socklen_t _addr_len;
    ssize_t len;
    uint8_t buffer[IP_MAXPACKET];

    if (events & (EPOLLERR | EPOLLHUP))
        err(1, "i/o error on raw socket");

    while (1) {
        len = recvfrom(raw_fd, buffer, sizeof(buffer), 0, &_addr, &_addr_len);

        if (len < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK)
                log_error("error reading from raw socket");
            return;
        }

        if (read_packet(buffer, len, &pkt) < 0)
            continue;

        log_set_conn(pkt.source_ip, pkt.source_port);
        dispatch_packet(&pkt);
        log_clear_conn();
    }
}

static void
client_fd_ready(int events, struct session *session)
{
    uint8_t buffer[IP_MAXPACKET];

    if (events & (EPOLLERR | EPOLLHUP)) {
        session_release(table, session);
        return;
    }

    if (events & EPOLLIN)
        read_and_discard_all(session->fd, buffer, sizeof(buffer));
    if (events & EPOLLOUT)
        session_write_all(session);
}

void
run_event_loop(void)
{
    struct epoll_event event, *events;
    int i, event_count;

    if ((epoll_fd = epoll_create1(0)) < 0)
        err(1, "epoll_create1");

    event.data.ptr = &raw_fd;
    event.events = EPOLLIN | EPOLLET;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, raw_fd, &event) < 0)
        err(1, "epoll_ctl failed to add raw_fd");

    if ((events = calloc(MAX_EVENTS, sizeof(struct epoll_event))) == NULL)
        err(1, "failed to allocate memory for events");

    while (1) {
        event_count = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);

        if (event_count < 0)
            err(1, "epoll_wait");

        for (i = 0; i < event_count; i++) {
            if (events[i].data.ptr == &raw_fd)
                raw_fd_ready(events[i].events);
            else
                client_fd_ready(events[i].events, events[i].data.ptr);
        }
    }
}

void
parse_config(const char *filename)
{
    FILE *fp;
    char *key, *value;
    const char *error_msg;
    int lineno = 0;
    int ret;

    if ((fp = fopen(filename, "r")) == NULL)
        err(1, "failed to read %s", filename);

    while ((ret = config_read(fp, &key, &value, &lineno)) > 0) {
        if (!strcmp(key, "daemonize")) {
            is_daemon = !strcmp(value, "true");
        } else if (!strcmp(key, "username")) {
            username = strdup(value);
        } else if (!strcmp(key, "log-filename")) {
            log_filename = strdup(value);
        } else if (!strcmp(key, "listen-port")) {
            listen_port = strtonum(value, 1, 65535, &error_msg);
            if (error_msg != NULL)
                errx(1, "%s, line %d: listen-port is %s",
                     filename, lineno, error_msg);
        } else if (!strcmp(key, "forward-host")) {
            forward_host = strdup(value);
        } else if (!strcmp(key, "forward-port")) {
            strtonum(value, 1, 65535, &error_msg);
            if (error_msg != NULL)
                errx(1, "%s, line %d: forward-port is %s",
                     filename, lineno, error_msg);
            forward_port = strdup(value);
        } else if (!strcmp(key, "forward-percentage")) {
            forward_percentage = strtonum(value, 1, 100, &error_msg);
            if (error_msg != NULL)
                errx(1, "%s, line %d: forward-percentage is %s",
                     filename, lineno, error_msg);
        } else if (!strcmp(key, "max-connections")) {
            max_connections = strtonum(value, 1, 10000, &error_msg);
            if (error_msg != NULL)
                errx(1, "%s, line %d: max-connections is %s",
                     filename, lineno, error_msg);
        } else if (!strcmp(key, "window-size-kbytes")) {
            window_size_bytes = strtonum(value, 1, 10000, &error_msg) * 1024;
            if (error_msg != NULL)
                errx(1, "%s, line %d: window-size-kbytes is %s",
                     filename, lineno, error_msg);
        } else {
            errx(1, "unknown configuration setting: %s", key);
        }

        free(key);
        free(value);
    }

    if (ret < 0)
        err(1, "failed to read %s", filename);

    fclose(fp);

    if (listen_port < 0)
        errx(1, "configuration error: listen-port was not specified");
    if (forward_host == NULL)
        errx(1, "configuration error: forward-host was not specified");
    if (forward_port == NULL)
        errx(1, "configuration error: forward-port was not specified");
}

int
main(int argc, char **argv)
{
    if (argc > 2 || (argc == 2 && !strcmp(argv[0], "-h"))) {
        fprintf(stderr,
"Usage: %s <CONFIG>\n"
"\n"
"Mirror inbound traffic on a specific port to another destination.\n"
""
"  CONFIG  path to the reflectd configuration file. Defaults to\n"
"          /etc/reflectd.conf if not specified. See reflectd(8).\n", argv[0]);

         exit(1);
    }

    parse_config(argc == 2 ? argv[1] : "/etc/reflectd.conf");
    initialize();
    run_event_loop();
    return EXIT_SUCCESS;
}
