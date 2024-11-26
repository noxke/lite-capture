#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/netdevice.h>
#include <linux/semaphore.h>

#include "log_utils.h"
#include "netfilter_hook.h"
#include "capture_utils.h"

// Hook function for LOCALIN chain
unsigned int hook_localin_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct net_device *indev = state->in;
    IpPackInfo info;
    RuleConfig *matched_rule;

    memset(&info, 0, sizeof(info));
    // 解析ip数据包信息
    get_ip_pack_info(skb, &info);
    if (indev != 0) {
        info.ifdev = indev->ifindex;
    }
    else {
        info.ifdev = -1;
    }

    matched_rule = capture_match(&info);
    if (matched_rule != NULL) {
        capture_matched(matched_rule, skb);
    }

    return NF_ACCEPT;
}

// Hook function for LOCALOUT chain
unsigned int hook_localout_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct net_device *outdev = state->out;
    IpPackInfo info;
    RuleConfig *matched_rule;

    memset(&info, 0, sizeof(info));
    // 解析ip数据包信息
    get_ip_pack_info(skb, &info);
    if (outdev != 0) {
        info.ifdev = outdev->ifindex;
    }
    else {
        info.ifdev = -1;
    }

    matched_rule = capture_match(&info);
    if (matched_rule != NULL) {
        capture_matched(matched_rule, skb);
    }

    return NF_ACCEPT;
}

// Hook function for FORWARD chain
unsigned int hook_forward_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct net_device *indev = state->in;
    IpPackInfo info;
    RuleConfig *matched_rule;

    memset(&info, 0, sizeof(info));
    // 解析ip数据包信息
    get_ip_pack_info(skb, &info);
    if (indev != 0) {
        info.ifdev = indev->ifindex;
    }
    else {
        info.ifdev = -1;
    }

    matched_rule = capture_match(&info);
    if (matched_rule != NULL) {
        capture_matched(matched_rule, skb);
    }

    return NF_ACCEPT;
}

struct nf_hook_ops nf_hook_localin_ops = {
    .hook = hook_localin_func,
    .pf = PF_INET,
    .hooknum = NF_INET_LOCAL_IN,
    .priority = NF_HOOK_PRIORITY,
};

struct nf_hook_ops nf_hook_localout_ops = {
    .hook = hook_localout_func,
    .pf = PF_INET,
    .hooknum = NF_INET_LOCAL_OUT,
    .priority = NF_HOOK_PRIORITY,
};

struct nf_hook_ops nf_hook_forward_ops = {
    .hook = hook_forward_func,
    .pf = PF_INET,
    .hooknum = NF_INET_FORWARD,
    .priority = NF_HOOK_PRIORITY,
};


int nf_hook_init() {
    // 初始化规则
    capture_link = NULL;
    // 初始化信号量
    init_rwsem(&capture_link_rw_sem);
    // 注册钩子
    nf_register_net_hook(&init_net, &(nf_hook_localin_ops));
    nf_register_net_hook(&init_net, &(nf_hook_localout_ops));
    nf_register_net_hook(&init_net, &(nf_hook_forward_ops));

    return 0;
}

void nf_hook_exit() {
    // 卸载钩子
    nf_unregister_net_hook(&init_net, &(nf_hook_localin_ops));
    nf_unregister_net_hook(&init_net, &(nf_hook_localout_ops));
    nf_unregister_net_hook(&init_net, &(nf_hook_forward_ops));
    capture_clear();
}