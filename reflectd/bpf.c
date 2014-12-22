#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <linux/filter.h>

#include <err.h>
#include <stdlib.h>


static void
bpf_extend(struct sock_fprog *bpf, size_t *capacity, uint16_t code, uint32_t k)
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
    filter->jt = 0;
    filter->jf = 0;
    filter->k = k;
}

static inline void
bpf_set_jt(struct sock_fprog *bpf, size_t position)
{
    bpf->filter[position].jt = bpf->len - position - 1;
}

static inline void
bpf_set_jf(struct sock_fprog *bpf, size_t position)
{
    bpf->filter[position].jf = bpf->len - position - 1;
}

#define LDIND_B   (BPF_LD | BPF_B | BPF_IND)
#define LDIND_H   (BPF_LD | BPF_H | BPF_IND)
#define LDABS_W   (BPF_LD | BPF_W | BPF_ABS)
#define LDMSHX_B  (BPF_LDX | BPF_B | BPF_MSH)
#define JAND      (BPF_JMP | BPF_JSET | BPF_K)
#define JEQ       (BPF_JMP | BPF_JEQ | BPF_K)
#define RET       (BPF_RET | BPF_K)

#define FLAGS     13

#define DEST_IP   16
#define DEST_PORT  2

#define SRC_IP    12
#define SRC_PORT   0

void
bpf_attach(int raw_fd, uint32_t *addrs, uint16_t listen_port)
{
    struct sock_fprog bpf;
    size_t check_dest_port, check_src_port, check_rst;
    size_t check_src_ip, check_dest_ip;
    size_t capacity;
    int addr_count, i;

    for (addr_count = 0; addrs[addr_count]; addr_count++)
        ;

    capacity = 16;
    bpf.len = 0;
    bpf.filter = calloc(capacity, sizeof(struct sock_filter));

    if (bpf.filter == NULL)
        err(1, "failed to allocate space for packet filter");

    /*   LDMSHX.B 0
     *   LDIND.B  FLAGS
     *   JNAND    RST, CheckDest */
    bpf_extend(&bpf, &capacity, LDMSHX_B, 0);
    bpf_extend(&bpf, &capacity, LDIND_B, FLAGS);
    check_rst = bpf.len;
    bpf_extend(&bpf, &capacity, JAND, 0x20);

    /*   LDIND.H  SRC_PORT
     *   JNE      LISTEN_PORT, CheckDest
     *   LDABS.W  SRC_IP */
    bpf_extend(&bpf, &capacity, LDIND_H, SRC_PORT);
    check_src_port = bpf.len;
    bpf_extend(&bpf, &capacity, JEQ, listen_port);
    bpf_extend(&bpf, &capacity, LDABS_W, SRC_IP);

    /*   JEQ      ADDR_0, Pass
     *   JEQ      ADDR_1, Pass
     *   ... */
    check_src_ip = bpf.len;
    for (i = 0; i < addr_count; i++)
        bpf_extend(&bpf, &capacity, JEQ, addrs[i]);

    /* CheckDest: */
    bpf_set_jf(&bpf, check_rst);
    bpf_set_jf(&bpf, check_src_port);

    /*   LDIND.H  DEST_PORT
     *   JNE      LISTEN_PORT, Fail
     *   LDABS.W  DEST_IP */
    bpf_extend(&bpf, &capacity, LDIND_H, DEST_PORT);
    check_dest_port = bpf.len;
    bpf_extend(&bpf, &capacity, JEQ, listen_port);
    bpf_extend(&bpf, &capacity, LDABS_W, DEST_IP);

    /*   JEQ      ADDR_0, Pass
     *   JEQ      ADDR_1, Pass
     *   ... */
    check_dest_ip = bpf.len;
    for (i = 0; i < addr_count; i++)
        bpf_extend(&bpf, &capacity, JEQ, addrs[i]);

    /* Fail:
     *   RET      0 */
    bpf_set_jf(&bpf, check_dest_port);
    bpf_extend(&bpf, &capacity, RET, 0);

    /* Pass:
     *   RET      -1 */
    for (i = 0; i < addr_count; i++) {
        bpf_set_jt(&bpf, check_src_ip + i);
        bpf_set_jt(&bpf, check_dest_ip + i);
    }

    bpf_extend(&bpf, &capacity, RET, -1);

    if (setsockopt(raw_fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0)
        err(1, "failed to attach packet filter");

    free(bpf.filter);
}
