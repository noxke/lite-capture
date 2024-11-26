#ifndef __CAPTURE_UTILS_H__ // __CAPTURE_UTILS_H__
#define __CAPTURE_UTILS_H__
// 报文捕获器接口

#include <netinet/ip.h>
#include <linux/types.h>

typedef unsigned int u_int;
typedef unsigned short u_short;
typedef unsigned char u_char;
#include <pcap.h>

#include "filter_rule.h"
#include "netlink_msg.h"

#define BUFFER_SIZE 1024
#define MAX_PATH 256

// lite-capture配置
struct capture_config_struct{
    int verbose_mode;
    char interface[MAX_PATH];
    char filters[BUFFER_SIZE];
    char out_file[MAX_PATH];
};

extern pcap_t *pcap;
extern pcap_dumper_t *pcap_dumper;

extern struct capture_config_struct config;

extern int get_interface_index(const char *if_name);

extern int filter_rules_load(const char *interface, const char *filters);

extern int nl_msg_capture_handler(struct nl_msg_struct *msg);

#endif // __CAPTURE_UTILS_H__