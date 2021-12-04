#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include <dpdk_common.h>

#include "cmd_line.h"

static const struct option long_opts[] =
{
    {"portmask", required_argument, NULL, 1},
    {"queues", required_argument, NULL, 2},
    {"promisc", no_argument, NULL, 3},
    {NULL, 0, NULL, 0}
};

/**
 * Parses DPDK-specific command line.
 * 
 * @param cmd_dpdk A pointer to the cmd_line_dpdk structure to put values in.
 * @param argc The argument count.
 * @param argv A pointer reference to the argument value char.
 * 
 * @return Void
**/
void parse_cmd_line_dpdk(struct cmd_line_dpdk *cmd_dpdk, int argc, char **argv)
{
    int c = -1;
    struct dpdkc_ret ret = dpdkc_ret_init();

    while ((c = getopt_long(argc, argv, "", long_opts, NULL)) != -1)
    {
        switch (c)
        {
            case 1:
                ret = dpdkc_parse_arg_port_mask(optarg);

                if (enabled_port_mask == 0)
                {
                    rte_exit(EXIT_FAILURE, "Invalid portmask specified with -p or --portmask.\n");
                }

                break;

            case 2:
                ret = dpdkc_parse_arg_queues(optarg, 0, 1);
                
                if (rx_queue_pp == 0)
                {
                    rte_exit(EXIT_FAILURE, "Invalid queue number argument with -q or --queues.\n");
                }

                cmd_dpdk->queues = rx_queue_pp;

                break;

            case 3:
                cmd_dpdk->promisc = 1;

                break;
        }
    }
}