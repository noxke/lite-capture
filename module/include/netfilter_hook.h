#ifndef __NETFILLTER_HOOK_H__ // __NETFILLTER_HOOK_H__
#define __NETFILLTER_HOOK_H__
// netfilter接口

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include "capture_utils.h"

// 由于测试使用docker网络，优先级需要低于docker的优先级，否则存在报文重复
// #define NF_HOOK_PRIORITY NF_IP_PRI_FIRST
#define NF_HOOK_PRIORITY NF_IP_PRI_LAST

extern int nf_hook_init(void);
extern void nf_hook_exit(void);

#endif // __NETFILLTER_HOOK_H__