#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netinet/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "capture_utils.h"
#include "netlink_msg.h"
#include "netlink_utils.h"
#include "conf_utils.h"

#include <pcap.h>

pcap_t *pcap = NULL;
pcap_dumper_t *pcap_dumper = NULL;

// 消息处理器加锁
static pthread_mutex_t capture_handler_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t capture_handler_cond = PTHREAD_COND_INITIALIZER;

int get_interface_index(const char *if_name) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        // perror("socket");
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1) {
        // perror("ioctl");
        close(sock);
        return -1;
    }

    close(sock);
    return ifr.ifr_ifindex;
}

int filter_rules_load(const char *interface, const char *filters) {
    int ret = 0;
    int ifindex = -1;   // -1不匹配网卡
    char *token;
    char *tmp_token;
    char str[BUFFER_SIZE];
    if (interface == NULL || filters == NULL || strlen(filters) <= 0) {
        return -1;
    }

    // 检查网卡index
    if (strlen(interface) != 0) {
        ifindex = get_interface_index(interface);
        if (ifindex == -1) {
            return -1;
        }
    }

    strncpy(str, filters, sizeof(str));
    token = strtok(str, ";");
    do {
        RuleConfig conf;
        FilterRule *rule = &(conf.rule);
        char protocal_str[64];
        char saddr_str[128];
        char daddr_str[128];
        if (sscanf(token, "%63s %127s %127s", protocal_str, saddr_str, daddr_str) != 3) {
            ret = -1;
            break;
        }

        memset(&conf, 0, sizeof(conf));

        // 匹配网卡
        if (ifindex != -1) {
            rule->ifdev = ifindex;
            rule->match_flags |= FILLTER_MATCH_IFDEV;
        }

        // 解析协议
        if (strcmp(protocal_str, "ICMP") == 0) {
            rule->protocol = IPPROTO_ICMP;
            rule->match_flags |= FILLTER_MATCH_PROTO;
        }
        else if (strcmp(protocal_str, "UDP") == 0) {
            rule->protocol = IPPROTO_UDP;
            rule->match_flags |= FILLTER_MATCH_PROTO;
        }
        else if (strcmp(protocal_str, "TCP") == 0) {
            rule->protocol = IPPROTO_TCP;
            rule->match_flags |= FILLTER_MATCH_PROTO;
        }
        else if (strcmp(protocal_str, "ANY") == 0) {
            rule->match_flags &= ~FILLTER_MATCH_PROTO;
        }
        else {
            ret = -1;
            break;
        }
        // 解析源地址
        if (strlen(saddr_str) != 0) {
            // 匹配端口
            tmp_token = saddr_str;
            while (tmp_token[0] != ':' && tmp_token[0] != '\0') {
                tmp_token++;
            }
            if (tmp_token[0] == ':') {
                tmp_token[0] = '\0';
                tmp_token++;
            }
            unsigned short port = 0;
            sscanf(tmp_token, "%hu", &port);
            if (port != 0) {
                rule->sport = htons(port);
                rule->match_flags |= FILLTER_MATCH_SPORT;
            }
            // 匹配前缀
            tmp_token = saddr_str;
            while (tmp_token[0] != '/' && tmp_token[0] != '\0') {
                tmp_token++;
            }
            if (tmp_token[0] == '/') {
                tmp_token[0] = '\0';
                tmp_token++;
            }
            unsigned char prefix = 32;
            sscanf(tmp_token, "%hhu", &prefix);
            if (prefix > 32) {
                ret = -1;
                break;
            }
            rule->sprefixlen = prefix;
            struct in_addr addr;
            addr.s_addr = 0;
            if (strlen(saddr_str) != 0 && inet_pton(AF_INET, saddr_str, &addr) != 1) {
                ret = -1;
                break;
            }
            rule->saddr = addr.s_addr;
            rule->match_flags |= FILLTER_MATCH_SADDR;
        }
        else {
            ret = -1;
            break;
        }
        // 解析目的地址
        if (strlen(daddr_str) != 0) {
            // 匹配端口
            tmp_token = daddr_str;
            while (tmp_token[0] != ':' && tmp_token[0] != '\0') {
                tmp_token++;
            }
            if (tmp_token[0] == ':') {
                tmp_token[0] = '\0';
                tmp_token++;
            }
            unsigned short port = 0;
            sscanf(tmp_token, "%hu", &port);
            if (port != 0) {
                rule->dport = htons(port);
                rule->match_flags |= FILLTER_MATCH_DPORT;
            }
            // 匹配前缀
            tmp_token = daddr_str;
            while (tmp_token[0] != '/' && tmp_token[0] != '\0') {
                tmp_token++;
            }
            if (tmp_token[0] == '/') {
                tmp_token[0] = '\0';
                tmp_token++;
            }
            unsigned char prefix = 32;
            sscanf(tmp_token, "%hhu", &prefix);
            if (prefix > 32) {
                ret = -1;
                break;
            }
            rule->dprefixlen = prefix;
            struct in_addr addr;
            addr.s_addr = 0;
            if (strlen(daddr_str) != 0 && inet_pton(AF_INET, daddr_str, &addr) != 1) {
                ret = -1;
                break;
            }
            rule->daddr = addr.s_addr;
            rule->match_flags |= FILLTER_MATCH_DADDR;
        }
        else {
            ret = -1;
            break;
        }
        // 检查规则是否合理
        // ICMP不需要端口
        if ((rule->match_flags & FILLTER_MATCH_PROTO) != 0) {
            if (rule->protocol == IPPROTO_ICMP
            && (((rule->match_flags & FILLTER_MATCH_SPORT) != 0) 
            || ((rule->match_flags & FILLTER_MATCH_DPORT) != 0))) {
                ret = -1;
                break;
            }
        }
        // 将规则写入内核
        if (config_rule_insert(&conf) != 0) {
            ret = -1;
            break;
        }
    } while ((token = strtok(NULL, ";")) != NULL);

    return ret;
}

int nl_msg_capture_handler(struct nl_msg_struct *msg) {
    int packet_len;
    struct iphdr *ip_header;
    int ret = 0;
    if (msg == NULL || msg->msg_type != NL_MSG_CAPTURED) {
        return -1;
    }
    packet_len = msg->msg_size-sizeof(struct nl_msg_struct);
    ip_header = (struct iphdr *)NL_MSG_DATA(msg);

    pthread_mutex_lock(&capture_handler_mutex);
    
    if (pcap_dumper != NULL) {
        struct pcap_pkthdr header;
        const u_char *packet = (const u_char *)ip_header;

        header.len = header.caplen = packet_len;
        pcap_dump((u_char *)pcap_dumper, &header, packet);
    }

    switch (ip_header->protocol) {
        case IPPROTO_ICMP:
            printf("[ICMP] %s->",
                inet_ntoa(*(struct in_addr *)&ip_header->saddr));
            printf("%s\n",
                inet_ntoa(*(struct in_addr *)&ip_header->daddr));
            break;
        case IPPROTO_TCP:
            struct tcphdr *tcp_header = (struct tcphdr *)((void *)ip_header + ip_header->ihl*4);
            printf("[TCP] %s:%hu->",
                 inet_ntoa(*(struct in_addr *)&ip_header->saddr),
                 ntohs(tcp_header->source));
            printf("%s:%hu\n",
                inet_ntoa(*(struct in_addr *)&ip_header->daddr),
                 ntohs(tcp_header->dest));
            break;
        case IPPROTO_UDP:
            struct udphdr *udp_header = (struct udphdr *)((void *)ip_header + ip_header->ihl*4);
            printf("[UDP] %s:%hu->",
                 inet_ntoa(*(struct in_addr *)&ip_header->saddr),
                 ntohs(udp_header->source));
            printf("%s:%hu\n", inet_ntoa(*(struct in_addr *)&ip_header->daddr),
                 ntohs(udp_header->dest));
            break;
        default:
            printf("[IP] %s->",
                inet_ntoa(*(struct in_addr *)&ip_header->saddr));
            printf("%s\n",
                inet_ntoa(*(struct in_addr *)&ip_header->daddr));
            break;
    }

    // 详细模式
    if (config.verbose_mode == 1) {
        for (int i = 0; i < packet_len; i++) {
            if (i % 16 == 0 && i != 0) {
                printf("\n");
            }
            printf("%02x ", *((unsigned char *)NL_MSG_DATA(msg)+i));
        }
        printf("\n\n");
    }

    pthread_mutex_unlock(&capture_handler_mutex);
    return ret;
}
