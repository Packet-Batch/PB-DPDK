#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/types.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>

#include <dpdk_common.h>

#include <utils.h>
#include <cmd_line.h>
#include <config.h>

#include "sequence.h"
#include "cmd_line.h"
#include "main.h"

void sign_hdl(int tmp)
{
    quit = 1;
}

int main(int argc, char **argv)
{
    // Initialiize result variables.
    struct dpdkc_ret ret = dpdkc_ret_init();

    // Initialize EAL and check.
    ret = dpdkc_eal_init(argc, argv);

    dpdkc_check_ret(&ret);

    // Retrieve number of arguments to adjust.
    int arg_adj = (int)ret.data;

    // Calculate difference in arguments due to EAL init.
    argc -= arg_adj;
    argv += arg_adj;

    // getopt.h changes the order of the command line which breaks parse_cmd_line_dpdk() later on
    // and all suggestions such as prepending '-' or '+' to the short list and setting optind to 0 or 1 does not work. 
    // Therefore, copy the original arguments after EAL (DPDK appears to do this as well).
    char **origargs = calloc(argc + 1, sizeof(*argv));

    int argi;

    for (argi = 0; argi < argc; argi++)
    {
        origargs[argi] = strdup(argv[argi]);
    }

    origargs[argi++] = NULL;

    // Create command line structure.
    opterr = 0;
    struct cmd_line cmd = {0};

    // Parse command line and store values into cmd.
    parse_cmd_line(argc, argv, &cmd);

    // Help menu.
    if (cmd.help)
    {
        fprintf(stdout, "Usage: pcktseq -c <configfile> [-v -h]\n\n" \
            "-c --cfg => Path to YAML file to parse.\n" \
            "-l --list => Print basic information about sequences.\n"
            "-v --verbose => Provide verbose output.\n" \
            "-h --help => Print out help menu and exit program.\n" \
            "--portmask => The port mask to use with the DPDK application.\n" \
            "--queues => The amount of TX queues to setup per port (default and recommended is 1).\n" \
            "--promisc => Whether to enable promiscuous mode on all enabled ports.\n" \
            "--burstsize => The max TX buffer burst size (default 32).\n" \
            "--useall => Load balances all ports and TX queues to l-cores in round-robin fashion and vice versa.\n");

        return EXIT_SUCCESS;
    }

    // Create AF_XDP-specific command line variable and set defaults.
    struct cmd_line_dpdk cmd_dpdk =
    {
        .queues = 1,
        .promisc = 0
    };

    // Parse AF_XDP-specific command line.
    optind = 0;

    parse_cmd_line_dpdk(&cmd_dpdk, argc, origargs);

    // Check if config is specified.
    if (cmd.config == NULL)
    {
        // Copy default values.
        cmd.config = "/etc/pcktbatch/pcktbatch.yaml";

        // Let us know if we're using the default config when the verbose flag is specified.
        if (cmd.verbose)
        {
            fprintf(stdout, "No config specified. Using default: %s.\n", cmd.config);
        }
    }

    // Create config structure.
    struct config cfg = {0};
    int seq_cnt = 0;

    // Set default values on each sequence.
    for (int i = 0; i < MAX_SEQUENCES; i++)
    {
        clear_sequence(&cfg, i);
    }

    // Attempt to parse config.
    __u8 log = 1;

    if (cmd.cli)
    {
        fprintf(stdout, "Using command line...\n");
        log = 0;    
    }

    parse_config(cmd.config, &cfg, 0, &seq_cnt, log);

    if (cmd.cli)
    {
        parse_cli(&cmd, &cfg);

        seq_cnt++;
    }

    // Check for list option. If so, print helpful information for configuration.
    if (cmd.list)
    {
        fprintf(stdout, "Found %d sequences.\n", seq_cnt);

        fprintf(stdout, "Got interface => %s.\n", cfg.interface);

        fprintf(stdout, "Sequences:\n\n--------------------------\n");

        for (int i = 0; i < seq_cnt; i++)
        {
            fprintf(stdout, "Sequence #%d:\n\n", i);

            fprintf(stdout, "Includes =>\n");

            if (cfg.seq[i].include_count > 0)
            {
                for (int j = 0; j < cfg.seq[i].include_count; j++)
                {
                    fprintf(stdout, "\t- %s\n", cfg.seq[i].includes[j]);
                }
            }

            fprintf(stdout, "Block => %s\n", (cfg.seq[i].block) ? "True" : "False");
            fprintf(stdout, "Count => %llu\n", cfg.seq[i].count);
            fprintf(stdout, "Time => %llu\n", cfg.seq[i].time);
            fprintf(stdout, "Delay => %llu\n", cfg.seq[i].delay);
            fprintf(stdout, "Threads => %u\n", cfg.seq[i].threads);

            fprintf(stdout, "\n\n");
        }

        return EXIT_SUCCESS;
    }

    // Setup signal.
    quit = 0;
    signal(SIGINT, sign_hdl);
    signal(SIGTERM, sign_hdl);

    if (cmd.verbose)
    {
        fprintf(stdout, "\n\n*DPDK Configuration *\n\n");

        fprintf(stdout, "Port mask => 0x%x.\n", enabled_port_mask);
        fprintf(stdout, "TX queues per port => %d (%d).\n", rx_queue_pp, cmd_dpdk.queues);
        fprintf(stdout, "Promisc => %d.", cmd_dpdk.promisc);
        fprintf(stdout, "Packet Burst Size => %u.\n", packet_burst_size);

        fprintf(stdout, "\nStarting the DPDK application...\n\n");
    }

    // Retrieve the amount of l-cores and check.
    ret = dpdkc_get_available_lcore_count();

    dpdkc_check_ret(&ret);

    // Retrieve the amount of ethernet ports and check.
    ret = dpdkc_get_nb_ports();

    dpdkc_check_ret(&ret);

    // Make sure port mask is valid.
    ret = dpdkc_ports_are_valid();

    dpdkc_check_ret(&ret);

    // Initialize mbuf pool.
    ret = dpdkc_create_mbuf();

    dpdkc_check_ret(&ret);

    // Initialize each port.
    ret = dpdkc_ports_queues_init(cmd_dpdk.promisc, 0, tx_queue_pp);

    // Check for error and fail with it if there is.
    dpdkc_check_ret(&ret);

    // Initialize the port and l-core mappings.
    ret = dpdkc_ports_queues_mapping();

    dpdkc_check_ret(&ret);

    // Check for available ports.
    ret = dpdkc_ports_available();

    dpdkc_check_ret(&ret);

    // Check port link status for all ports.
    dpdkc_check_link_status();

    // Assign destination ports.
    RTE_ETH_FOREACH_DEV(port_id)
    {
        ports[port_id].tx_port = port_id;
    }

    // Loop through each sequence found.
    for (int i = 0; i < seq_cnt; i++)
    {
        seq_send(cfg.interface, cfg.seq[i], seq_cnt, cmd, cmd_dpdk);
    }

    // Stop all ports.
    ret = dpdkc_port_stop_and_remove();

    dpdkc_check_ret(&ret);

    // Cleanup EAL.
    ret = dpdkc_eal_cleanup();

    dpdkc_check_ret(&ret);

    // Print number of sequences completed at end.
    fprintf(stdout, "Completed %d sequences!\n", seq_cnt);

    // Free original arguments.
    free(origargs);

    // Close program successfully.
    return EXIT_SUCCESS;
}