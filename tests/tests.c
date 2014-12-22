#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "addrset.h"
#include "checksum.h"
#include "sessions.h"
#include "util.h"

static uint32_t LISTEN_IPS[] = { 0x7f000001, 0x00 };


void
test_localaddrs(void)
{
    uint32_t *addrs = addrset_local();

    assert(addrs != NULL);
    assert(addrset_contains(addrs, 0x7f000001));  /* localhost */
    assert(!addrset_contains(addrs, 0x08080808)); /* Google's DNS. */

    free(addrs);
}

void
test_adjust_seq(void)
{
    /* Sequence numbers within half of the number range are not adjusted. */
    assert(adjust_seq(1, 1) == 1);
    assert(adjust_seq(1, 0) == 1);
    assert(adjust_seq(0, 1) == 0);

    /* Wrapped-around sequence numbers are corrected */
    assert(adjust_seq(0, 0xffffffff) == 0x100000000);
    assert(adjust_seq(0x08f000001, 0xfffffffff) == 0xf8f000001);
    assert(adjust_seq(0x07f000000, 0xfffffffff) == 0x107f000000);
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

uint32_t *
parse_const_ips(const char *immutable)
{
    uint32_t *ips;
    char *mutable;

    mutable = strdup(immutable);
    assert(mutable != NULL);
    ips = addrset_from_string(mutable);
    free(mutable);

    return ips;
}

void
test_parse_ips(void)
{
    uint32_t *ips;

    ips = parse_const_ips("");
    assert(ips[0] == 0x00);
    free(ips);

    ips = parse_const_ips("127.0.0.1");
    assert(ips[0] == 0x7f000001);
    assert(ips[1] == 0x00);
    free(ips);

    ips = parse_const_ips("127.0.0.1 8.8.8.8");
    assert(ips[0] == 0x7f000001);
    assert(ips[1] == 0x08080808);
    assert(ips[2] == 0x00);
    free(ips);

    ips = parse_const_ips("127.0.0.1\t8.8.8.8");
    assert(ips[0] == 0x7f000001);
    assert(ips[1] == 0x08080808);
    assert(ips[2] == 0x00);
    free(ips);

    ips = parse_const_ips("foobar");
    assert(ips == NULL);
}

void
test_config(void)
{
    FILE *fp;
    char *key, *value;
    int lineno;
    char input1[] =
        "\n"
        "# this comment is ignored\n"
        " # indented comments are ignored too\n"
        "a-key value\n"
        "  keys can be indented\n"
        "\n"
        "spaces   are stripped from value \n"
        "#comments can be interleaved \n"
        "with\tkeys and values\n"
        "values-are-strictly-optional\n"
        " \teven-with-extra-whitespace    \n";
    char input2[] =
        "some#keys might contain #";

    assert((fp = fmemopen(input1, sizeof(input1), "r")) != NULL);
    lineno = 0;

    assert(config_read(fp, &key, &value, &lineno) > 0);
    assert(lineno == 4);
    assert(!strcmp(key, "a-key"));
    assert(!strcmp(value, "value"));
    free(key);
    free(value);

    assert(config_read(fp, &key, &value, &lineno) > 0);
    assert(lineno == 5);
    assert(!strcmp(key, "keys"));
    assert(!strcmp(value, "can be indented"));
    free(key);
    free(value);

    assert(config_read(fp, &key, &value, &lineno) > 0);
    assert(lineno == 7);
    assert(!strcmp(key, "spaces"));
    assert(!strcmp(value, "are stripped from value"));
    free(key);
    free(value);

    assert(config_read(fp, &key, &value, &lineno) > 0);
    assert(lineno == 9);
    assert(!strcmp(key, "with"));
    assert(!strcmp(value, "keys and values"));
    free(key);
    free(value);

    assert(config_read(fp, &key, &value, &lineno) > 0);
    assert(lineno == 10);
    assert(!strcmp(key, "values-are-strictly-optional"));
    assert(!strcmp(value, ""));
    free(key);
    free(value);

    assert(config_read(fp, &key, &value, &lineno) > 0);
    assert(lineno == 11);
    assert(!strcmp(key, "even-with-extra-whitespace"));
    assert(!strcmp(value, ""));
    free(key);
    free(value);

    assert(config_read(fp, &key, &value, &lineno) == 0);
    assert(fclose(fp) == 0);

    assert((fp = fmemopen(input2, sizeof(input2), "r")) != NULL);
    lineno = 0;

    assert(config_read(fp, &key, &value, &lineno) > 0);
    assert(lineno == 1);
    assert(!strcmp(key, "some#keys"));
    assert(!strcmp(value, "might contain #"));
    free(key);
    free(value);

    assert(config_read(fp, &key, &value, &lineno) == 0);
    assert(fclose(fp) == 0);
}

void
setup_context(struct context *ctx)
{
    memset(ctx, 0, sizeof(&ctx));
    ctx->listen_ips = LISTEN_IPS;
    ctx->listen_port = 9001;
    ctx->forward_percentage = 100;
    ctx->max_connections = 200;
    ctx->window_size_bytes = 256000;
    ctx->timeout_seconds = 30;
    assert(context_init(ctx, ctx->max_connections) != NULL);
}

void
test_context(void)
{
    struct context ctx;
    struct session *s[10];

    setup_context(&ctx);

    assert((s[0] = session_allocate(&ctx, 0x7f000001, 8000, 1)) != NULL);
    s[1] = session_find(&ctx, 0x7f000001, 8000);
    assert(s[0] == s[1]);

    assert((s[1] = session_allocate(&ctx, 0x7f000001, 8001, 1)) != NULL);
    s[2] = session_find(&ctx, 0x7f000001, 8001);
    assert(s[1] == s[2]);

    session_release(&ctx, s[1]);
    assert(session_find(&ctx, 0x7f000001, 8001) == NULL);

    assert((s[1] = session_allocate(&ctx, 0x7f000001, 8001, 1)) != NULL);
    s[2] = session_find(&ctx, 0x7f000001, 8001);
    assert(s[1] == s[2]);

    context_teardown(&ctx);
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
    struct context ctx;
    struct session *session;
    struct segment *segment[3];
    uint32_t source_ip = 0x7f000001;
    uint16_t source_port = 9000;

    setup_context(&ctx);
    session = session_allocate(&ctx, source_ip, source_port, 1);
    assert(session != NULL);

    /* A segment with a sequence number matching the next expected number
       should be returned by session_peek. */
    assert((segment[0] = create_dummy_segment(1, 256)) != NULL);
    session_insert(&ctx, session, segment[0]);
    assert(session_peek(session) == segment[0]);
    session_pop(session);
    assert(session_peek(session) == NULL);

    assert(session->next_seq == 257);

    /* A segment with a sequence number that is higher than the next expected
       number should not be returned until all prior segments are available. */
    assert((segment[0] = create_dummy_segment(512, 100)) != NULL);
    session_insert(&ctx, session, segment[0]);
    assert(session_peek(session) == NULL);

    assert((segment[1] = create_dummy_segment(257, 255)) != NULL);
    session_insert(&ctx, session, segment[1]);
    assert(session_peek(session) == segment[1]);
    session_pop(session);
    assert(session_peek(session) == segment[0]);
    session_pop(session);

    assert(session->next_seq == 612);

    /* A segment that overlaps the receive window should be returned with its
       data pointer adjusted to point to the next previously-unreceived byte. */
    assert((segment[0] = create_dummy_segment(556, 128)) != NULL);
    session_insert(&ctx, session, segment[0]);
    assert(session_peek(session) == segment[0]);
    assert(segment[0]->dataptr == segment[0]->bytes + 56);
    session_pop(session);

    assert(session->next_seq == 684);

    /* Duplicate packets should be discarded, instead of returning empty
       packets. */
    assert((segment[0] = create_dummy_segment(684, 54)) != NULL);
    assert((segment[1] = create_dummy_segment(684, 54)) != NULL);
    session_insert(&ctx, session, segment[0]);
    session_insert(&ctx, session, segment[1]);
    assert(session_peek(session) == segment[0] ||
           session_peek(session) == segment[1]);
    session_pop(session);
    assert(session_peek(session) == NULL);

    /* Duplicate packets should be discarded even if they arrive after a
       missing or corrupted packet. */
    assert((segment[0] = create_dummy_segment(738, 100)) != NULL);
    assert((segment[1] = create_dummy_segment(838, 31)) != NULL);
    assert((segment[2] = create_dummy_segment(838, 31)) != NULL);
    session_insert(&ctx, session, segment[1]);
    session_insert(&ctx, session, segment[2]);
    assert(session_peek(session) == NULL);
    session_insert(&ctx, session, segment[0]);
    assert(session_peek(session) == segment[0]);
    session_pop(session);
    assert(session_peek(session) == segment[1] ||
           session_peek(session) == segment[2]);
    session_pop(session);
    assert(session_peek(session) == NULL);

    /* A segment with a no content inside of the receive window (ie. seq < rwnd
       and seq + length <= rwnd) should be dropped instead of inserted. */
    assert((segment[0] = create_dummy_segment(700, 31)) != NULL);
    session_insert(&ctx, session, segment[0]);
    assert(session_peek(session) == NULL);

    assert((segment[0] = create_dummy_segment(700 + 2 * ctx.window_size_bytes,
                31)) != NULL);
    session_insert(&ctx, session, segment[0]);
    assert(session_peek(session) == NULL);

    /* A segment that falls within another segment should be discarded. */
    assert((segment[0] = create_dummy_segment(872, 100)) != NULL);
    assert((segment[1] = create_dummy_segment(869, 120)) != NULL);
    session_insert(&ctx, session, segment[0]);
    session_insert(&ctx, session, segment[1]);
    assert(session_peek(session) == segment[1]);
    session_pop(session);
    assert(session_peek(session) == NULL);

    /* A session should be removed from the session context when a FIN or
       RST becomes sendable (ie. there is an unbroken series of segments
       preceding it.) */
    assert((segment[0] = create_dummy_segment(989, 3)) != NULL);
    assert((segment[1] = create_dummy_segment(992, 0)) != NULL);
    segment[1]->fin = 1;
    session_insert(&ctx, session, segment[1]);
    assert(session_find(&ctx, source_ip, source_port) == session);
    session_insert(&ctx, session, segment[0]);
    assert(session_find(&ctx, source_ip, source_port) == NULL);
    session_pop(session);
    session_pop(session);

    session_release(&ctx, session);
    context_teardown(&ctx);
}

int
main(void)
{
    test_adjust_seq();
    test_checksums();
    test_parse_ips();
    test_config();
    test_localaddrs();
    test_context();
    test_session();

    puts("All tests passed");

    return EXIT_SUCCESS;
}
