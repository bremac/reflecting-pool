#define _GNU_SOURCE

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <sys/epoll.h>
#include <sys/socket.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "checksum.h"
#include "definitions.h"
#include "localaddrs.h"
#include "segments.h"
#include "sessions.h"


// TODO: dump session state on error
// TODO: IPv6 support
// TODO: port + interface BPF filter?
// TODO: Naming and abstraction inconsistent in this module.
// TODO: Limit total queued bytes to MAX_WINDOW_BYTES.
// TODO: Use getopt for listen port, user, target port, and target host.
// TODO: Do we need to check SO_ERROR in the epoll loop, or is this
//       covered by EPOLLERR?
//       See http://stackoverflow.com/a/6206705
// TODO: Pass time to session_allocate and session_insert

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

// TODO: modern idioms?
static int
create_reflector_socket(void)
{
    struct sockaddr_in addr;
    int fd = -1;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        warn("failed to create socket for %s:%d", TARGET_HOST, TARGET_PORT);
        goto err;
    }

    if (inet_pton(AF_INET, TARGET_HOST, &addr.sin_addr) != 1) {
        warn("failed to determine IPv4 address for %s", TARGET_HOST);
        goto err;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(TARGET_PORT);

    if (make_socket_nonblocking(fd) < 0) {
        warn("failed to make socket non-blocking for %s:%d",
                 TARGET_HOST, TARGET_PORT);
        goto err;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 &&
        errno != EINPROGRESS) {
        warn("failed to connect to %s:%d", TARGET_HOST, TARGET_PORT);
        goto err;
    }

    return fd;

err:
    if (fd >= 0)
        close(fd);

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
            count = write(session->fd, segment->bytes, segment->length);

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
        }

        session_pop(session);
    }
}

// TODO: better name
void
dispatch_packet(uint8_t *buffer, size_t total_len)
{
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    struct session *session = NULL;
    struct segment *segment = NULL;
    uint64_t seq;
    size_t header_len, data_len;
    uint32_t seq_lower;
    uint32_t source_ip, dest_ip;
    uint16_t source_port, dest_port;

    ip_header = (struct iphdr *)buffer;
    tcp_header = (struct tcphdr *)(buffer + ip_header->ihl * 4);

    source_ip = ntohl(ip_header->saddr);
    source_port = ntohs(tcp_header->source);
    dest_ip = ntohl(ip_header->daddr);
    dest_port = ntohs(tcp_header->dest);
    seq_lower = ntohl(tcp_header->seq);

    if (is_local_address(local_addrs, source_ip) &&
        source_port == LISTEN_PORT && tcp_header->rst) {
        session = session_find(table, dest_ip, dest_port);
        session_release(table, session);
    }

    if (!is_local_address(local_addrs, dest_ip) ||
        dest_port != LISTEN_PORT) {
        return;
    }

    /* Discard packets from other machines with bad checksums.
     * Don't check packets from the local machine, as these are usually
     * wrong until they hit the NIC due to checksum offloading. */
    if (!is_local_address(local_addrs, source_ip) &&
        !are_checksums_valid(ip_header, tcp_header)) {
        warnx("dropping invalid packet");
        return;
    }

    session = session_find(table, source_ip, source_port);

    /* New TCP connection is being established */
    if (tcp_header->syn && !tcp_header->ack) {
        if (session != NULL) {
            warnx("received SYN packet for existing session %04x:%d",
                        source_ip, source_port);
            goto err;
        }

        // TODO: statistical discard goes here.

        session = session_allocate(table, source_ip, source_port,
                                   seq_lower + 1);

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

        seq = adjust_seq(seq_lower, session->next_seq);
        if (seq == SEQ_INVALID)
            return;

        header_len = ip_header->ihl * 4 + tcp_header->doff * 4;
        data_len = ntohs(ip_header->tot_len) - header_len;

        if (header_len + data_len != total_len) {
            warnx("packet length mismatch: %d + %d bytes vs. %lld",
                        (int)header_len, (int)data_len, (long long)total_len);
            return;
        }

        if (data_len == 0 && !tcp_header->fin && !tcp_header->rst)
            return;

        segment = segment_create(data_len);

        if (segment == NULL) {
            warnx("could not allocate %llu byte segment for %04x:%d",
                        (long long)data_len, source_ip, source_port);
            goto err;
        }

        segment->seq = seq;
        segment->length = data_len;
        if (data_len > 0)
            memcpy(segment->bytes, buffer + header_len, data_len);
        segment->dataptr = segment->bytes;
        segment->fin = tcp_header->fin;
        segment->rst = tcp_header->rst;

        if (session_insert(session, segment)) {
            warnx("failed to insert segment into segmentq for %04x:%d",
                        source_ip, source_port);
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

#define MAX_EVENTS (MAX_TCP_SESSIONS + 1)

void
initialize(void)
{
    if ((raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
        err(1, "failed to create raw_fd socket");

    drop_privileges(RESTRICTED_USER);

    if ((local_addrs = load_local_addresses()) == NULL)
        exit(1);

    if (make_socket_nonblocking(raw_fd) < 0)
        err(1, "failed to make raw socket non-blocking");

    if ((table = sessiontable_create()) == NULL)
        exit(1);
}

void
run_event_loop(void)
{
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
        event_count = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);

        if (event_count < 0)
            err(1, "epoll_wait");

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

                    // TODO: handle epoll registration here
                    dispatch_packet(buffer, len);
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
main(void) /*int argc, const char **argv)*/
{
    initialize();
    run_event_loop();
    return EXIT_SUCCESS;
}
