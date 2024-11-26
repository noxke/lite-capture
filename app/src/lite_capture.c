#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>

#include "capture_utils.h"
#include "netlink_msg.h"
#include "netlink_utils.h"
#include "conf_utils.h"

// lite-capture配置
struct capture_config_struct config;

// 退出标识
volatile sig_atomic_t exit_flag = 0;

void help() {
    puts("lite-capture v1.0");
    puts("");
    puts("Usage: lite-capture [-hv] [-i interface] [-f file] [-w file]");
    puts("Options:");
    puts("  -h");
    puts("    show help infomation");
    puts("  -v");
    puts("    verbose mode, show captured packet ditails");
    puts("  -i interface");
    puts("    interface for capturing packets, default all interface");
    puts("  -f filters");
    puts("     filter rules for capture");
    puts("  -w file");
    puts("    output pcap file");
    puts("");
    puts("Filters:");
    puts("  PROTOCAL SRC_ADDR DST_ADDR[;PROTOCAL SRC_ADDR DST_ADDR]");
    puts("    PROTOCAL: ICMP UDP TCP ANY");
    puts("    ADDR: 0.0.0.0/0:0");
    puts("    example: 'ICMP 192.168.0.0/16 10.0.0.0/8;TCP 0.0.0.0/0:0 0.0.0.0/0:0;UDP 192.168.0.1:1234 0.0.0.0/0:0'");
    puts("    example: 'ANY 0.0.0.0/0:0 0.0.0.0/0:0'");
    exit(0);
}

// 命令行参数解析
int arg_parser(int argc, char *argv[]) {
    int opt;
    int ret = 0;
    if (argc < 2) {
        help();
    }

    memset(&config, 0, sizeof(config));

    // 使用getopt解析参数
    while ((opt = getopt(argc, argv, "hvi:f:w:")) != -1) {
        switch (opt) {
            case 'h':
                help();
                break;
            case 'v':
                config.verbose_mode = 1;
                break;
            case 'i':
                strncpy(config.interface, optarg, sizeof(config.interface));
                break;
            case 'f':
                strncpy(config.filters, optarg, sizeof(config.filters));
                break;
            case 'w':
                strncpy(config.out_file, optarg, sizeof(config.out_file));
                break;
            default:
                ret = -1;
                break;
        }
    }

    return ret;
}

int service_init() {
    // 初始化netlink
    if (netlink_init() != 0) {
        goto _service_netlink_init;
    }

    // 设置过滤器配置
    netlink_set_msg_handler(NL_MSG_CONF, (void *)nl_msg_config_handler);

    // 捕获报文接口
    netlink_set_msg_handler(NL_MSG_CAPTURED, (void *)nl_msg_capture_handler);

    goto _service_all_init;

_service_netlink_init:
    return -1;
_service_all_init:
    return 0;
}

void service_exit() {
    netlink_exit();
}


void sigint_handler(int signum) {
    exit_flag = 1;
}

int service_main() {
    int ret = 0;

    signal(SIGINT, sigint_handler);

    if (service_init() != 0) {
        printf("Connect lite_capture module failed\n");
        ret = -1;
    }
    else {
        // 初始化pcap
        pcap_dumper = NULL;
        pcap = NULL;
        if (strlen(config.out_file) != 0) {
            // 打开PCAP文件
            pcap = pcap_open_dead(DLT_RAW, NL_MAX_MSG_SIZE);
            if (pcap == NULL) {
                ret = -1;
            }
            else {
                pcap_dumper = pcap_dump_open(pcap, config.out_file);
            }
            if (pcap_dumper == NULL) {
                ret = -1;
            }
        }

        // 清除原有规则
        if (ret == 0 && config_rule_clear() != 0) {
            exit_flag = 1;
            ret = -1;
        }

        // 添加规则
        if (ret == 0 && filter_rules_load(config.interface, config.filters) != 0) {
            printf("lite-capture: Invalid filter rule: %s\n", config.filters);
            exit_flag = 1;
            ret = -1;
        }

        // 等待Ctrl-C退出
        while (ret == 0 && exit_flag == 0) {
            sleep(1);
        }

        // 清除规则
        if (ret == 0 && config_rule_clear() != 0) {
            exit_flag = 1;
            ret = -1;
        }

        service_exit();

        if (pcap_dumper != NULL) {
            pcap_dump_close(pcap_dumper);
            pcap_dumper = NULL;
        }
        if (pcap != NULL) {
            pcap_close(pcap);
            pcap = NULL;
        }
    }

    return ret;
}

int main(int argc, char *argv[], char *envp[]) {
    if (geteuid() != 0) {
        puts("lite-capture: Operation not permitted");
        return -1;
    }
    if (arg_parser(argc, argv) != 0) {
        puts("lite-capture: Invalid usage");
        return -1;
    }
    if (service_main() != 0) {
        puts("lite-capture: Internal Error");
        return -1;
    }
    return 0;
}