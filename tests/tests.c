#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#include "checksum.h"
#include "localaddrs.h"
#include "segments.h"
#include "sessions.h"

void
test_localaddrs(void)
{
    uint32_t *addrs = load_local_addresses();

    assert(addrs != NULL);
    assert(is_local_address(addrs, 0x7f000001));  /* localhost */
    assert(!is_local_address(addrs, 0x08080808)); /* Google's DNS. */

    free(addrs);
}

void
test_adjust_seq(void)
{
    /* Sequence numbers outside of the window are invalid */
    assert(adjust_seq(1, 1) == 1);
    assert(adjust_seq(1, 0) == 1);
    assert(adjust_seq(0, 1) == SEQ_INVALID);

    /* Wrapped-around sequence numbers are corrected */
    assert(adjust_seq(0, 0xffffffff) == 0x100000000);
    assert(adjust_seq(0x0fffffff, 0xffffffff) == SEQ_INVALID);
    assert(adjust_seq(1, 0x2ffffffff) == 0x300000001);
}

void
test_checksums(void)
{
    uint8_t valid_bytes[] = {
        0x45, 0x20, 0x00, 0x34, 0xc4, 0xef, 0x00, 0x00, 0x38, 0x06,
        0xc1, 0x8d, 0x4a, 0x7d, 0xef, 0x72, 0xc0, 0xa8, 0x01, 0x8f,
        0x01, 0xbb, 0x82, 0x48, 0x67, 0x6a, 0xbd, 0x7d, 0x69, 0x88,
        0x07, 0x28, 0x80, 0x10, 0x04, 0xdd, 0x6c, 0x2e, 0x00, 0x00,
        0x01, 0x01, 0x08, 0x0a, 0x1a, 0xf1, 0xb6, 0x42, 0x00, 0x98,
        0x1e, 0x23
    };
    uint8_t invalid_bytes[] = {
        0x45, 0x00, 0x00, 0x48, 0xf3, 0x23, 0x40, 0x00, 0x40, 0x06,
        0x49, 0x8a, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01,
        0x9c, 0x89, 0x1f, 0x40, 0xa5, 0x6d, 0x9f, 0x1c, 0x79, 0x66,
        0x02, 0xed, 0x80, 0x18, 0x01, 0x56, 0xfe, 0x3c, 0x00, 0x00,
        0x01, 0x01, 0x08, 0x0a, 0x00, 0xa5, 0xd0, 0x81, 0x00, 0xa4,
        0xd6, 0x7c, 0x61, 0x64, 0x66, 0x61, 0x64, 0x73, 0x6c, 0x66,
        0x69, 0x75, 0x61, 0x68, 0x77, 0x70, 0x6f, 0x33, 0x69, 0x32,
        0x6a, 0x0a
    };
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;

    ip_header = (struct iphdr *)valid_bytes;
    tcp_header = (struct tcphdr *)(valid_bytes + ip_header->ihl * 4);

    assert(is_ip_checksum_valid(ip_header));
    assert(is_tcp_checksum_valid(ip_header, tcp_header));

    ip_header = (struct iphdr *)invalid_bytes;
    tcp_header = (struct tcphdr *)(invalid_bytes + ip_header->ihl * 4);

    assert(is_ip_checksum_valid(ip_header));
    assert(!is_tcp_checksum_valid(ip_header, tcp_header));
}

void
test_sessiontable(void)
{
    struct sessiontable *table;
    struct session *s[10];

    assert((table = sessiontable_create()) != NULL);
    assert((s[0] = session_allocate(table, 0x7f000001, 8000, 1)) != NULL);
    s[1] = session_find(table, 0x7f000001, 8000);
    assert(s[0] == s[1]);

    assert((s[1] = session_allocate(table, 0x7f000001, 8001, 1)) != NULL);
    s[2] = session_find(table, 0x7f000001, 8001);
    assert(s[1] == s[2]);

    session_release(table, s[1]);
    assert(session_find(table, 0x7f000001, 8001) == NULL);

    assert((s[1] = session_allocate(table, 0x7f000001, 8001, 1)) != NULL);
    s[2] = session_find(table, 0x7f000001, 8001);
    assert(s[1] == s[2]);

    sessiontable_destroy(table);
}

static struct segment *
create_dummy_segment(uint64_t seq, size_t length)
{
    struct segment *segment;

    assert((segment = segment_create(length)) != NULL);

    segment->seq = seq;
    segment->length = length;
    segment->dataptr = segment->bytes;
    segment->fin = 0;
    segment->rst = 0;

    return segment;
}

void
test_session(void)
{
    struct sessiontable *table;
    struct session *session;
    struct segment *segment[10];
    uint32_t source_ip = 0x7f000001;
    uint16_t source_port = 9000;

    assert((table = sessiontable_create()) != NULL);
    assert((session = session_allocate(table, source_ip, source_port,
                1)) != NULL);

    /* A segment with a sequence number matching the next expected number
       should be returned by session_peek. */
    assert((segment[0] = create_dummy_segment(1, 256)) != NULL);
    assert(session_insert(table, session, segment[0]) == 0);
    assert(session_peek(session) == segment[0]);
    session_pop(session);
    assert(session_peek(session) == NULL);

    assert(session->next_seq == 257);

    /* A segment with a no content inside of the receive window (ie. seq < rwnd
       and seq + length <= rwnd) should be dropped instead of inserted. */
    // XXX: Move window checking logic into session_insert.

    /* A segment with a sequence number that is higher than the next expected
       number should not be returned until all prior segments are available. */
    assert((segment[1] = create_dummy_segment(512, 100)) != NULL);
    assert(session_insert(table, session, segment[1]) == 0);
    assert(session_peek(session) == NULL);

    assert((segment[2] = create_dummy_segment(257, 255)) != NULL);
    assert(session_insert(table, session, segment[2]) == 0);
    assert(session_peek(session) == segment[2]);
    session_pop(session);
    assert(session_peek(session) == segment[1]);
    session_pop(session);

    assert(session->next_seq == 612);

    /* A segment that overlaps the receive window should be returned with its
       data pointer adjusted to point to the next previously-unreceived byte. */
    assert((segment[3] = create_dummy_segment(556, 128)) != NULL);
    assert(session_insert(table, session, segment[3]) == 0);
    assert(session_peek(session) == segment[3]);
    assert(segment[3]->dataptr == segment[3]->bytes + 56);
    session_pop(session);

    assert(session->next_seq == 684);

    /* Duplicate packets should be discarded, instead of returning empty
       packets. */
    assert((segment[4] = create_dummy_segment(684, 54)) != NULL);
    assert(session_insert(table, session, segment[4]) == 0);
    assert((segment[5] = create_dummy_segment(684, 54)) != NULL);
    assert(session_insert(table, session, segment[5]) == 0);
    assert(session_peek(session) == segment[4] ||
           session_peek(session) == segment[5]);
    session_pop(session);
    assert(session_peek(session) == NULL);

    session_release(table, session);
    sessiontable_destroy(table);
}

int
main(void)
{
    test_adjust_seq();
    test_checksums();
    test_localaddrs();
    test_sessiontable();
    test_session();

    puts("All tests passed");

    return EXIT_SUCCESS;
}
