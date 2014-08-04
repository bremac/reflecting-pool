#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <linux/filter.h>

#include <err.h>
#include <stdlib.h>


static struct sock_filter *
bpf_extend(struct sock_fprog *bpf, size_t *capacity, uint16_t code,
           uint8_t jt, uint8_t jf, uint32_t k)
{
    struct sock_filter *filter;

    bpf->len++;

    if (bpf->len >= *capacity) {
        *capacity *= 2;
        bpf->filter = realloc(bpf->filter,
                              *capacity * sizeof(struct sock_filter));
        if (bpf->filter == NULL)
            err(1, "failed to allocate memory for bpf");
    }

    filter = &bpf->filter[bpf->len - 1];
    filter->code = code;
    filter->jt = jt;
    filter->jf = jf;
    filter->k = k;

    return filter;
}

static inline uint8_t
jump_target(struct sock_fprog *bpf, struct sock_filter *from)
{
    return &bpf->filter[bpf->len] - from - 1;
}


#define LDBIND    (BPF_LD | BPF_B | BPF_IND)
#define LDHIND    (BPF_LD | BPF_H | BPF_IND)
#define LDWABS    (BPF_LD | BPF_W | BPF_ABS)
#define LDMSHXB   (BPF_LDX | BPF_B | BPF_MSH)
#define JAND      (BPF_JMP | BPF_JSET | BPF_K)
#define JEQ       (BPF_JMP | BPF_JEQ | BPF_K)
#define RET       (BPF_RET | BPF_K)

#define FLAGS     13

#define DEST_IP   16
#define DEST_PORT  2

#define SRC_IP    12
#define SRC_PORT   0

#define RET_FAIL   0
#define RET_PASS  -1


void
bpf_attach(int raw_fd, uint32_t *addrs, uint16_t listen_port)
{
    struct sock_fprog bpf;
    struct sock_filter *check_port, *check_rst;
    size_t capacity;
    int addr_count, i;
    uint32_t rst = 0x20;

    for (addr_count = 0; addrs[addr_count]; addr_count++)
        ;

    capacity = 16;
    bpf.len = 0;
    bpf.filter = calloc(capacity, sizeof(struct sock_filter));

    if (bpf.filter == NULL)
        err(1, "failed to allocate space for packet filter");

    bpf_extend(&bpf, &capacity, LDMSHXB, 0, 0, 0);
    bpf_extend(&bpf, &capacity, LDBIND,  0, 0, FLAGS);
    check_rst = bpf_extend(&bpf, &capacity, JAND, 0, -1, rst);

    /* If RST, check that it's from the monitored port. */
    bpf_extend(&bpf, &capacity, LDHIND, 0, 0, SRC_PORT);
    check_port = bpf_extend(&bpf, &capacity, JEQ, 0, -1, listen_port);
    bpf_extend(&bpf, &capacity, LDWABS, 0, 0, SRC_IP);

    for (i = 0; i < addr_count; i++)
        bpf_extend(&bpf, &capacity, JEQ, addr_count - i, 0, addrs[i]);

    check_port->jf = jump_target(&bpf, check_port);
    bpf_extend(&bpf, &capacity, RET, 0, 0, RET_FAIL);
    bpf_extend(&bpf, &capacity, RET, 0, 0, RET_PASS);

    /* If !RST, check that it's to the monitored port. */
    check_rst->jf = jump_target(&bpf, check_rst);
    bpf_extend(&bpf, &capacity, LDHIND, 0, 0, DEST_PORT);
    check_port = bpf_extend(&bpf, &capacity, JEQ, 0, -1, listen_port);
    bpf_extend(&bpf, &capacity, LDWABS, 0, 0, DEST_IP);

    for (i = 0; i < addr_count; i++)
        bpf_extend(&bpf, &capacity, JEQ, addr_count - i, 0, addrs[i]);

    check_port->jf = jump_target(&bpf, check_port);
    bpf_extend(&bpf, &capacity, RET, 0, 0, RET_FAIL);
    bpf_extend(&bpf, &capacity, RET, 0, 0, RET_PASS);

    if (setsockopt(raw_fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0)
        err(1, "failed to attach packet filter");

    free(bpf.filter);
}
