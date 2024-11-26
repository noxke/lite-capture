#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/semaphore.h>

#include "log_utils.h"
#include "netlink_msg.h"
#include "netlink_utils.h"
#include "module_utils.h"
#include "netfilter_hook.h"
#include "capture_utils.h"

FilterNode *capture_link = NULL;
struct rw_semaphore capture_link_rw_sem;  // 信号量，用于避免读时写

#define addr4_match(a1, a2, prefixlen) \
    (((prefixlen) == 0 || ((((a1) ^ (a2)) & htonl(~0UL << (32 - (prefixlen)))) == 0)) ? 0 : -1)

void get_ip_pack_info(struct sk_buff *skb, IpPackInfo *info) {
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    if (skb == NULL || info == NULL) {
        return;
    }
    ip_header = ip_hdr(skb);
    info->protocol = ip_header->protocol;
    info->saddr = ip_header->saddr;
    info->daddr = ip_header->daddr;
    switch (info->protocol) {
        case IPPROTO_ICMP:
            break;
        case IPPROTO_TCP:
            tcp_header = tcp_hdr(skb);
            info->sport = tcp_header->source;
            info->dport = tcp_header->dest;
            break;
        case IPPROTO_UDP:
            udp_header = udp_hdr(skb);
            info->sport = udp_header->source;
            info->dport = udp_header->dest;
            break;
        default:
            break;
    }
}

RuleConfig *capture_match(IpPackInfo *info) {
    FilterNode *rule_next;
    RuleConfig *rule_conf;
    RuleConfig *matched_conf;
    FilterRule *rule;
    if (capture_link == NULL || info == NULL) {
        return NULL;
    }

    matched_conf = NULL;

    // 获取读sem
    down_read(&capture_link_rw_sem);

    rule_next = capture_link;
    while (rule_next != NULL) {
        rule_conf = &(rule_next->rule_conf);
        rule = &(rule_conf->rule);
        rule_next = rule_next->next;
        if (((rule->match_flags & FILLTER_MATCH_IFDEV) != 0) && (rule->ifdev != info->ifdev)) {
            continue;
        }
        if (((rule->match_flags & FILLTER_MATCH_PROTO) != 0) && (rule->protocol != info->protocol)) {
            continue;
        }
        if (((rule->match_flags & FILLTER_MATCH_SADDR) != 0) && addr4_match(rule->saddr, info->saddr, rule->sprefixlen) != 0) {
            continue;
        }
        if (((rule->match_flags & FILLTER_MATCH_DADDR) != 0) && addr4_match(rule->daddr, info->daddr, rule->dprefixlen) != 0) {
            continue;
        }
        if (((rule->match_flags & FILLTER_MATCH_SPORT) != 0) && (rule->sport != info->sport)) {
            continue;
        }
        if (((rule->match_flags & FILLTER_MATCH_DPORT) != 0) && (rule->dport != info->dport)) {
            continue;
        }
        matched_conf = rule_conf;
        break;
    }

    // 释放读sem
    up_read(&capture_link_rw_sem);

    return matched_conf;
}

void capture_matched(RuleConfig *matched_rule, struct sk_buff *skb) {
    unsigned int skb_len;
    struct nl_msg_struct *msg;

    if (matched_rule == NULL || skb == NULL) {
        return;
    }

    skb_len = skb->len;

    // 报文发送给用户态
    msg = (struct nl_msg_struct *)kmalloc(NL_MSG_SIZE(skb_len), GFP_KERNEL);
    if (msg == NULL) {
        return;
    }
    msg->msg_type = NL_MSG_CAPTURED;
    msg->msg_size = NL_MSG_SIZE(skb_len);
    memcpy(NL_MSG_DATA(msg), skb->data, skb_len);
    nl_send_msg(msg);
    kfree(msg);
}

void capture_insert(RuleConfig *conf) {
    FilterNode *next;
    FilterNode *new_node;

    if (conf == NULL) {
        return;
    }
    new_node = (FilterNode *)kmalloc(sizeof(FilterNode), GFP_KERNEL);
    if (new_node == NULL) {
        return;
    }
    memcpy(&(new_node->rule_conf), conf, sizeof(new_node->rule_conf));
    new_node->next = NULL;

    // 获取写sem
    down_write(&capture_link_rw_sem);

    if (capture_link == NULL) {
        capture_link = new_node;
    }
    else {
        next = capture_link;
        while (next->next != NULL) {
            next = next->next;
        }
        next->next = new_node;
    }

    // 释放写sem
    up_write(&capture_link_rw_sem);
}


void capture_clear() {
    FilterNode *rm_node;
    FilterNode *next;

    // 获取写sem
    down_write(&capture_link_rw_sem);

    next = capture_link;
    capture_link = NULL;
    while (next != NULL) {
        rm_node = next;
        next = rm_node->next;
        kfree(rm_node);
    }

    // 释放写sem
    up_write(&capture_link_rw_sem);
}
