#pragma once

#include <linux/types.h>

struct cmd_line_dpdk
{
    __u16 queues;
    unsigned int promisc : 1;
};

void parse_cmd_line_dpdk(struct cmd_line_dpdk *cmd_dpdk, int argc, char **argv);