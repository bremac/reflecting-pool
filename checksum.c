#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <stdint.h>
#include <stdio.h> // TESTING


static uint16_t
ip_checksum(uint16_t *p, size_t len, uint32_t sum)
{
  for (; len > 1; len -= 2)
    sum += *p++;

  if (len > 0)
    sum += *(uint8_t *)p;

  sum = (sum & 0xffff) + (sum >> 16);
  sum += (sum >> 16);
  return ~sum;
}

int
is_ip_checksum_valid(struct iphdr *ip_header)
{
  uint32_t sum;
  uint16_t received_sum;

  received_sum = ip_header->check;
  ip_header->check = 0;

  sum = ip_checksum((uint16_t *)ip_header, ip_header->ihl * 4, 0);

  ip_header->check = received_sum;

  return received_sum == sum;
}

int
is_tcp_checksum_valid(struct iphdr *ip_header, struct tcphdr *tcp_header)
{
  uint32_t sum = 0;
  uint16_t len;
  uint16_t received_sum;

  received_sum = tcp_header->check;
  tcp_header->check = 0;

  len = ntohs(ip_header->tot_len) - ip_header->ihl * 4;

  sum += ((uint16_t *)&ip_header->saddr)[0];
  sum += ((uint16_t *)&ip_header->saddr)[1];
  sum += ((uint16_t *)&ip_header->daddr)[0];
  sum += ((uint16_t *)&ip_header->daddr)[1];
  sum += htons(ip_header->protocol);
  sum += htons(len);

  sum = ip_checksum((uint16_t *)tcp_header, len, sum);
  tcp_header->check = received_sum;

  return received_sum == sum;
}

int
are_checksums_valid(struct iphdr *ip_header, struct tcphdr *tcp_header)
{
  return (is_ip_checksum_valid(ip_header) &&
          is_tcp_checksum_valid(ip_header, tcp_header));
}
