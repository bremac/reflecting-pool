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
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bpf.h"
#include "checksum.h"
#include "definitions.h"
#include "localaddrs.h"
#include "segments.h"
#include "sessions.h"


// TODO: IPv6 support
// TODO: Naming and abstraction inconsistent in this module.
// TODO: Limit total queued bytes to MAX_WINDOW_BYTES.
// TODO: Do we need to check SO_ERROR in the epoll loop, or is this
//       covered by EPOLLERR?
//       See http://stackoverflow.com/a/6206705
// TODO: Pass time to session_allocate and session_insert
// TODO: Use offsetof instead of sizeof for tail-allocated structures.
// TODO: Add tests for failure cases to the test suite.

static double forward_percentage = 100;
static int listen_port = -1;
static const char *target_hostname = NULL;
static const char *target_port = NULL;
static const char *username = NULL;
static size_t raw_buffer_size = 10 * 1024 * 1024;

static uint32_t *local_addrs;
static struct sessiontable *table;
static int raw_fd;
static int epoll_fd;


static int
make_socket_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags < 0)
        return -1;

    flags |= O_NONBLOCK;

    if (fcntl(fd, F_SETFL, flags) < 0)
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
    error = getaddrinfo(target_hostname, target_port, &hints, &result);

    if (error != 0) {
        warnx("connecting to target failed: %s", gai_strerror(error));
        goto err;
    }

    if ((fd = socket(result->ai_family, result->ai_socktype,
                     result->ai_protocol)) < 0) {
        warn("failed to create socket for %s:%s", target_hostname, target_port);
        goto err;
    }

    if (make_socket_nonblocking(fd) < 0) {
        warn("failed to make socket non-blocking for %s:%s",
             target_hostname, target_port);
        goto err;
    }

    if (connect(fd, result->ai_addr, result->ai_addrlen) < 0 &&
        errno != EINPROGRESS) {
        warn("failed to connect to %s:%s", target_hostname, target_port);
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
        warn("failed to register session");
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
    } while (ret >= 0);
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
                    warn("failed to write to connection");
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
        warnx("packet too small to contain an IP header");
        return -1;
    }

    ip_header = (struct iphdr *)buffer;
    ip_header_len = ip_header->ihl * 4;

    if (total_len - ip_header_len < sizeof(struct tcphdr)) {
        warnx("packet too small to contain a TCP header");
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
        warnx("packet length mismatch: %d + %d bytes vs. %lld",
              (int)combined_header_len, (int)pkt->data_len,
              (long long)total_len);
        return -1;
    }

    /* Discard packets from other machines with bad checksums.
     * Don't check packets from the local machine, as these are usually
     * wrong until they hit the NIC due to checksum offloading. */
    if (!is_local_address(local_addrs, pkt->source_ip)
        && !are_checksums_valid(ip_header, tcp_header)) {
        warnx("packet has an invalid checksum");
        return -1;
    }

    return 0;
}

void
dispatch_packet(struct packet_in *pkt)
{
    struct session *session = NULL;
    struct segment *segment = NULL;
    uint64_t seq;

    if (pkt->rst && pkt->source_port == listen_port
        && is_local_address(local_addrs, pkt->source_ip)) {
        session = session_find(table, pkt->dest_ip, pkt->dest_port);
        session_release(table, session);
    }

    if (!is_local_address(local_addrs, pkt->dest_ip) ||
        pkt->dest_port != listen_port) {
        warnx("received unexpected packet for %04x:%d",
            pkt->dest_ip, pkt->dest_port);
        return;
    }

    session = session_find(table, pkt->source_ip, pkt->source_port);

    /* New TCP connection is being established */
    if (pkt->syn && !pkt->ack) {
        if (session != NULL) {
            warnx("received SYN packet for existing session %04x:%d",
                  pkt->source_ip, pkt->source_port);
            return;
        }

        /* Forward only a specified percentage of connections. */
        if ((double)random() * 100 / RAND_MAX > forward_percentage)
            return;

        session = session_allocate(table, pkt->source_ip, pkt->source_port,
                                   pkt->seq_lower + 1);

        if (session == NULL) {
            warnx("unable to find available session, dropping packet");
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

        seq = adjust_seq(pkt->seq_lower, session->next_seq);
        if (seq == SEQ_INVALID) {
            //warnx("invalid sequence number for %04x:%d: %04x vs. %llx",
            //      session->source_ip, session->source_port,
            //      pkt->seq_lower, (long long)session->next_seq);
            return;
        }

        if (pkt->data_len == 0 && !pkt->fin && !pkt->rst)
            return;

        segment = segment_create(pkt->data_len);

        if (segment == NULL) {
            warnx("could not allocate %llu byte segment for %04x:%d",
                  (long long)pkt->data_len, pkt->source_ip, pkt->source_port);
            goto err;
        }

        segment->seq = seq;
        segment->length = pkt->data_len;
        if (pkt->data_len > 0)
            memcpy(segment->bytes, pkt->data, pkt->data_len);
        segment->dataptr = segment->bytes;
        segment->fin = pkt->fin;
        segment->rst = pkt->rst;

        if (session_insert(table, session, segment)) {
            warnx("failed to insert segment into segmentq for %04x:%d",
                  pkt->source_ip, pkt->source_port);
            goto err;
        }

        session_write_all(session);
    }

    return;

err:
    segment_destroy(segment);
    session_release(table, session);
}


void
drop_privileges(const char *username)
{
    struct passwd *passwd;

    if ((passwd = getpwnam(username)) == NULL)
        err(1, "no user found with name %s", username);

    if (setresgid(passwd->pw_gid, passwd->pw_gid, passwd->pw_gid) < 0)
        err(1, "failed to drop group privileges");

    if (setgroups(0, NULL) < 0)
        err(1, "failed to drop supplementary group privileges");

    if (setresuid(passwd->pw_uid, passwd->pw_uid, passwd->pw_uid) < 0)
        err(1, "failed to drop user privileges");
}

void
usage(const char *command_name, const char *message)
{
    if (message != NULL)
        fprintf(stderr, "%s: %s\n\n", command_name, message);

    fprintf(stderr,
"Usage: %s -l PORT -u USERNAME -h HOST -p PORT [OPTIONS]\n"
"\n"
"Mirror inbound traffic on a specific port to another destination.\n"
"\n"
"  -f PERCENT    forward PERCENT of connections received\n"
"  -l PORT       listen on PORT for incoming traffic\n"
"  -u USERNAME   run as user USERNAME\n"
"  -h HOSTNAME   forward traffic to HOSTNAME\n"
"  -p PORT       forward traffic to PORT on HOSTNAME\n", command_name);

    exit(1);
}

double
parse_positive_number(const char *s, double max)
{
    char *end;
    double number;

    errno = 0;
    number = strtod(s, &end);

    if (*end || errno == ERANGE || number < 0 || number > max)
        return -1;

    return number;
}

void
parse_options(int argc, char **argv)
{
    double target_port_num;
    int opt;

    while ((opt = getopt(argc, argv, "f:h:l:p:u:")) > 0) {
        switch (opt) {
        case 'f':
            forward_percentage = parse_positive_number(optarg, 100);
            if (forward_percentage < 0)
                usage(argv[0], "PERCENT should be between 0 and 100");
            break;
        case 'h':
            target_hostname = optarg;
            break;
        case 'l':
            listen_port = parse_positive_number(optarg, 65535);
            if (listen_port < 0 || (int)listen_port != listen_port)
                usage(argv[0], "PORT must be between 0 and 65535");
            break;
        case 'p':
            /* Validate the target port (getaddrinfo takes a string.) */
            target_port_num = parse_positive_number(optarg, 65535);
            if (target_port_num < 0 || (int)target_port_num != target_port_num)
                usage(argv[0], "PORT must be between 0 and 65535");
            target_port = optarg;
            break;
        case 'u':
            username = optarg;
            break;
        default:
            usage(argv[0], NULL);
        }
    }

    if (listen_port < 0 || username == NULL ||
        target_hostname == NULL || target_port == NULL)
        usage(argv[0], NULL);
}

#define MAX_EVENTS (MAX_TCP_SESSIONS + 1)

void
initialize(void)
{
    if ((raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
        err(1, "failed to create raw_fd socket");

    if (setsockopt(raw_fd, SOL_SOCKET, SO_RCVBUFFORCE,
                   &raw_buffer_size, sizeof(raw_buffer_size)) < 0)
        err(1, "failed to set receive buffer size");

    drop_privileges(username);

    if ((local_addrs = load_local_addresses()) == NULL)
        exit(1);

    bpf_attach(raw_fd, local_addrs, listen_port);

    if (make_socket_nonblocking(raw_fd) < 0)
        err(1, "failed to make raw socket non-blocking");

    if ((table = sessiontable_create()) == NULL)
        exit(1);

    srandom(time(NULL));
}

void
run_event_loop(void)
{
    struct packet_in pkt;
    struct session *session;
    struct sockaddr _addr;
    socklen_t _addr_len;
    struct epoll_event event, *events;
    ssize_t len;
    int i, event_count;
    uint8_t buffer[IP_MAXPACKET];

    if ((epoll_fd = epoll_create1(0)) < 0)
        err(1, "epoll_create1");

    event.data.fd = raw_fd;
    event.events = EPOLLIN | EPOLLET;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, raw_fd, &event) < 0)
        err(1, "epoll_ctl failed to add raw_fd");

    if ((events = calloc(MAX_EVENTS, sizeof(struct epoll_event))) == NULL)
        err(1, "failed to allocate memory for events");

    while (1) {
        //event_count = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        event_count = epoll_wait(epoll_fd, events, MAX_EVENTS, 5000);

        if (event_count < 0)
            err(1, "epoll_wait");

        if (event_count == 0)
            sessiontable_dump(table);

        for (i = 0; i < event_count; i++) {
            if (events[i].data.fd == raw_fd) {
                if (events[i].events & (EPOLLERR | EPOLLHUP))
                    err(1, "i/o error on raw socket");

                while (1) {
                    len = recvfrom(raw_fd, buffer, sizeof(buffer), 0,
                                   &_addr, &_addr_len);
                    if (len < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
                        warn("error reading from raw socket");
                    if (len < 0)
                        break;

                    if (read_packet(buffer, len, &pkt) < 0)
                        continue;

                    dispatch_packet(&pkt);

                    // TODO: handle epoll registration here
                    /*session = dispatch_packet(&pkt);
                    if (pkt->syn && !pkt->ack)
                        ; // epoll registration
                    else
                        session_write_all(session);*/
                }
            } else {  /* The available socket is not the raw_fd. */
                if (events[i].events & (EPOLLERR | EPOLLHUP)) {
                    session_release(table, events[i].data.ptr);
                } else if (events[i].events & EPOLLIN) {
                    session = events[i].data.ptr;
                    read_and_discard_all(session->fd, buffer, sizeof(buffer));
                } else if (events[i].events & EPOLLOUT) {
                    session = events[i].data.ptr;
                    session_write_all(session);
                }
            }
        }
    }
}

int
main(int argc, char **argv)
{
    parse_options(argc, argv);
    initialize();
    run_event_loop();
    return EXIT_SUCCESS;
}
