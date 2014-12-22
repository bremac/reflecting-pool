#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>

#include <sys/types.h>

#include <err.h>
#include <stdlib.h>
#include <string.h>

#include "localaddrs.h"
#include "util.h"

/* XXX: rename localaddr -> addrset */

static void *
xrealloc(void *ptr, size_t size)
{
    void *result;
    result = realloc(ptr, size);
    if (result == NULL)
        err(1, "xrealloc");
    return result;
}

static int
valid_address(struct ifaddrs *ifaddr)
{
    return ifaddr->ifa_addr != NULL && ifaddr->ifa_addr->sa_family == AF_INET;
}

uint32_t *
parse_ips(char *s)
{
    struct in_addr addr;
    uint32_t *ips;
    char *tok;
    size_t length, capacity;

    length = 0;
    capacity = 4;
    ips = xrealloc(NULL, sizeof(uint32_t) * capacity);
    tok = strtok(s, " \t");

    while (tok) {
        length++;

        if (length + 1 >= capacity) {  /* save room for trailing NULL */
            capacity *= 2;
            ips = xrealloc(ips, sizeof(uint32_t) * capacity);
        }

        if (inet_pton(AF_INET, tok, &addr) == 0) {
            log_msg("invalid IPv4 address: %s", tok);
            free(ips);
            return NULL;
        }

        ips[length - 1] = ntohl(addr.s_addr);
        tok = strtok(NULL, " \t");
    }

    ips[length] = 0x00;
    return ips;
}

uint32_t *
load_local_addresses(void)
{
    struct sockaddr_in *sockaddr_in;
    struct ifaddrs *first, *cur;
    size_t i = 0;
    uint32_t *addrs;

    if (getifaddrs(&first)) {
        log_error("failed to get interface addresses");
        return NULL;
    }

    for (cur = first; cur != NULL; cur = cur->ifa_next) {
        if (valid_address(cur))
            i++;
    }

    /* The terminator is 0.0.0.0, which is an invalid address. */
    addrs = calloc(i + 1, sizeof(uint32_t));

    if (addrs == NULL) {
        log_msg("failed to allocate space for interface addresses");
        return NULL;
    }

    i = 0;
    for (cur = first; cur != NULL; cur = cur->ifa_next) {
        if (valid_address(cur)) {
            sockaddr_in = (struct sockaddr_in *)cur->ifa_addr;
            addrs[i++] = ntohl(sockaddr_in->sin_addr.s_addr);
        }
    }

    freeifaddrs(first);

    return addrs;
}

int
is_local_address(uint32_t *addrs, uint32_t addr)
{
    for (; *addrs; addrs++) {
        if (*addrs == addr)
            return 1;
    }

    return 0;
}
