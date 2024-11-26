#ifndef __CAPTURE_UTILS_H__ // __CAPTURE_UTILS_H__
#define __CAPTURE_UTILS_H__
// 过滤器规则接口

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/semaphore.h>

#include "filter_rule.h"

extern FilterNode *capture_link;
extern struct rw_semaphore capture_link_rw_sem;  // 信号量，用于避免读时写

void get_ip_pack_info(struct sk_buff *skb, IpPackInfo *info);

RuleConfig *capture_match(IpPackInfo *info);

void capture_matched(RuleConfig *matched_rule, struct sk_buff *skb);

extern void capture_insert(RuleConfig *conf);

extern void capture_clear(void);

#endif // __CAPTURE_UTILS_H__