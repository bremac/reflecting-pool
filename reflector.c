#define _GNU_SOURCE

#include <arpa/inet.h>
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

#include "definitions.h"
#include "localaddrs.h"
#include "segments.h"
#include "sessions.h"


#define PROTOCOL_TCP      6

// TODO: dump session state on error
// TODO: IPv6 support

static uint32_t *local_addrs;
static struct sessiontable *table;
static int listener;
static int epoll_fd;

int
is_new_connection(struct tcphdr *tcp_header)
{
  return tcp_header->syn && !tcp_header->ack;
}

// TODO: better name
static inline int
error_is_eagain(int error)
{
  return error == EAGAIN || error == EWOULDBLOCK;
}

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

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    warn("failed to connect to %s:%d", TARGET_HOST, TARGET_PORT);
    goto err;
  }

  if (make_socket_nonblocking(fd) < 0) {
    warn("failed to make socket non-blocking for %s:%d",
         TARGET_HOST, TARGET_PORT);
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
    count = write(session->fd, segment->bytes, segment->length);

    if (count < 0) {
      if (error_is_eagain(errno))
        return;
      else {
        warn("failed to write to connection");
        session_release(table, session);
        return;
      }
    }

    if (count < (ssize_t)segment->length) {
      segment->dataptr += count;
      return;
    }

    session_pop(session);
  }
}

// TODO: better name
void
forward_packet(uint8_t *buffer, size_t total_len)
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

  if (ip_header->protocol != PROTOCOL_TCP)
    return;

  tcp_header = (struct tcphdr *)(buffer + ip_header->ihl * 4);

  source_ip = ntohl(ip_header->saddr);
  source_port = ntohs(tcp_header->source);
  dest_ip = ntohl(ip_header->daddr);
  dest_port = ntohs(tcp_header->dest);
  seq_lower = ntohl(tcp_header->seq);

  if (!is_local_addr(local_addrs, dest_ip) ||
      dest_port != LISTEN_PORT) {
    return;
  }

  if (is_new_connection(tcp_header)) {
    session = session_find(table, source_ip, source_port);

    if (session != NULL) {
      warnx("received SYN packet for existing session %04x:%d",
            source_ip, source_port);
      goto err;
    }

    // TODO: statistical discard goes here.

    session = session_allocate(table, source_ip, source_port, seq_lower + 1);

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
    session = session_find(table, source_ip, source_port);

    if (session == NULL)  /* not following this session */
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

    if (data_len == 0)
      return;

    segment = segment_create(data_len);

    if (segment == NULL) {
      warnx("could not allocate %llu byte segment for %04x:%d",
            (long long)data_len, source_ip, source_port);
      goto err;
    }

    segment->seq = seq;
    segment->length = data_len;
    memcpy(segment->bytes, buffer + header_len, data_len);
    segment->dataptr = segment->bytes;

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

#define MAX_EVENTS (MAX_TCP_SESSIONS + 1)

void
initialize(void)
{
  struct epoll_event event;

  if ((local_addrs = load_local_addrs()) == NULL)
    exit(1);

  if ((table = sessiontable_create()) == NULL)
    exit(1);

  if ((listener = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
    err(1, "failed to create listener socket");

  make_socket_nonblocking(listener);

  if ((epoll_fd = epoll_create1(0)) < 0)
    err(1, "epoll_create1");

  event.data.fd = listener;
  event.events = EPOLLIN | EPOLLET;

  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listener, &event) < 0)
    err(1, "epoll_ctl failed to add listener");
}

void
run_event_loop(void)
{
  struct session *session;
  struct sockaddr _addr;
  socklen_t _addr_len;
  struct epoll_event *events;
  ssize_t total_len;
  int i, event_count;
  int has_error;
  uint8_t buffer[MAX_PACKET_BYTES];

  if ((events = calloc(MAX_EVENTS, sizeof(struct epoll_event))) == NULL)
    err(1, "failed to allocate memory for events");

  while (1) {
    event_count = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);

    if (event_count < 0)
      err(1, "epoll_wait");

    for (i = 0; i < event_count; i++) {
      has_error = events[i].events & (EPOLLERR | EPOLLHUP);

      if (events[i].data.fd == listener) {
        if (has_error)
          err(1, "i/o error on raw socket");

        do {
          total_len = recvfrom(listener, buffer, sizeof(buffer), 0,
                               &_addr, &_addr_len);
          if (total_len >= 0)
            forward_packet(buffer, total_len);
          if (total_len < 0 && !error_is_eagain(errno))
            warn("error reading from raw socket");
        } while (total_len >= 0);
      } else if (has_error) {
        // TODO: How do we report the specific error?
        warn("epoll error");
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


int
main(void) /*int argc, const char **argv)*/
{
  initialize();
  run_event_loop();
  return EXIT_SUCCESS;
}
