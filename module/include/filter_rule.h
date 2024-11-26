#ifndef __FILLTER_RULE_H__ // __FILLTER_RULE_H__
#define __FILLTER_RULE_H__
// 过滤器规则接口

#define DEFAULT_STR_SIZE 256

typedef unsigned char u8;
typedef unsigned long long u64;

enum FILLTER_MATCH_FLAGS {
    FILLTER_MATCH_IFDEV =    0b0000001,
    FILLTER_MATCH_PROTO =    0b0000010,
    FILLTER_MATCH_SADDR =    0b0000100,
    FILLTER_MATCH_DADDR =    0b0001000,
    FILLTER_MATCH_SPORT =    0b0010000,
    FILLTER_MATCH_DPORT =    0b0100000,
};


typedef struct {
    int ifdev;
    __be32 saddr;
    __be32 daddr;
    unsigned char protocol;
    __be16 sport;
    __be16 dport;
} IpPackInfo;

typedef struct {
    int ifdev;
    __be32 saddr;
    __be32 daddr;
    u8 sprefixlen;
    u8 dprefixlen;
    unsigned char protocol;
    __be16 sport;
    __be16 dport;
    unsigned int match_flags;
} FilterRule;

typedef struct {
    int config_type;
    FilterRule rule;
} RuleConfig;

typedef struct _FilterNode {
    RuleConfig rule_conf;
    struct _FilterNode *next;
} FilterNode;

#endif // __FILLTER_RULE_H__