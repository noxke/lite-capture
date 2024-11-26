#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/slab.h>

#include "netlink_msg.h"
#include "netlink_utils.h"
#include "log_utils.h"
#include "capture_utils.h"

#include "module_utils.h"

int nl_msg_config_handler(struct nl_msg_struct *msg) {
    void *conf = (void *)NL_MSG_DATA(msg);
    int config_type = *(int *)conf;
    switch (config_type) {
        case CONF_LOG_SET:
        case CONF_LOG_GET:
            log_config((LogConfig *)conf);
            break;
        case CONF_RULE_INSERT:
            capture_insert((RuleConfig *)conf);
            break;
        case CONF_RULE_CLEAR:
            capture_clear();
            break;
    }
    return 0;
}