#pragma once

#include  <linux/types.h>

#include <dpdk_common.h>

#include <cmd_line.h>
#include <config.h>

#include "cmd_line.h"
#include "main.h"

#define MAX_PCKT_LEN 0xFFFF
#define MAX_THREADS 4096
#define MAX_PCKT_BURST 32

// If the below is defined, only static data will be supported, but will ignore all dynamic checks in while loop increasing performance.
//#define MAX_STATIC_PERF
// If the below is defined, sequence count/time and verbose mode is not put into account. However, increases performance.
//#define MAX_PERF

struct thread_info
{
    const char device[MAX_NAME_LEN];
    struct sequence seq;
    __u16 seq_cnt;
    struct cmd_line cmd;
    struct cmd_line_dpdk cmd_dpdk;
    int id;
    struct xsk_socket_info *xsk_info;
    unsigned int tx_ports[MAX_TX_PORTS_PER_LCORE];
    unsigned int tx_ports_cnt;
    unsigned int tx_queues[RTE_MAX_ETHPORTS][MAX_TX_QUEUES_PER_PORT];
    unsigned int tx_queues_cnt[RTE_MAX_ETHPORTS];
};

struct port_remains
{
    unsigned int lcores[RTE_MAX_LCORE];
    unsigned int lcores_cnt;
    unsigned idx;
};

void seq_send(const char *interface, struct sequence seq, __u16 seqc, struct cmd_line cmd, struct cmd_line_dpdk cmd_dpdk);