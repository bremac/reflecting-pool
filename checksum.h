#ifndef _CHECKSUM_H_
#define _CHECKSUM_H_

int is_ip_checksum_valid(struct iphdr *);
int is_tcp_checksum_valid(struct iphdr *, struct tcphdr *);
int are_checksums_valid(struct iphdr *, struct tcphdr *);

#endif /* _CHECKSUM_H_ */
