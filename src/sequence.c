#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/sysinfo.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <linux/types.h>

#include <dpdk_common.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_icmp.h>

#include <utils.h>
#include <cmd_line.h>
#include <config.h>

#include "sequence.h"

__u64 count[MAX_SEQUENCES];
__u64 total_data[MAX_SEQUENCES];
__u16 seq_cnt;

/**
 * Calculates the ICMP header's checksum.
 * 
 * @param addr A pointer to the start of the ICMP header.
 * @param len The ICMP header's length including payload data.
 * 
 * @return The 16-bit checksum.
**/
__u16 icmp_csum (__u16 *addr, int len)
{
	int count = len;
	register __u32 sum = 0;
	__u16 answer = 0;

	// Sum up 2-byte values until none or only one byte left.
	while (count > 1) 
	{
		sum += *(addr++);
		count -= 2;
	}

	// Add left-over byte, if any.
	if (count > 0) 
	{
		sum += *(__u8 *) addr;
	}

	// Fold 32-bit sum into 16 bits; we lose information by doing this,
	// increasing the chances of a collision.
	// sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
	while (sum >> 16) 
	{
		sum = (sum & 0xffff) + (sum >> 16);
	}

	// Checksum is one's compliment of sum.
	answer = ~sum;

	return (answer);
}

/**
 * Retrieve gateway MAC address and store it in dst_mac.
 * 
 * @param dst_mac A pointer to the source MAC address (struct rte_ether_addr).
 * 
 * @return Void
**/
void get_gw_mac_address(struct rte_ether_addr *dst_mac)
{
    char cmd[] = "ip neigh | grep \"$(ip -4 route list 0/0|cut -d' ' -f3) \"|cut -d' ' -f5|tr '[a-f]' '[A-F]'";

    FILE *fp =  popen(cmd, "r");

    if (fp != NULL)
    {
        char line[18];

        if (fgets(line, sizeof(line), fp) != NULL)
        {
            sscanf(line, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &dst_mac->addr_bytes[0], &dst_mac->addr_bytes[1], &dst_mac->addr_bytes[2], &dst_mac->addr_bytes[3], &dst_mac->addr_bytes[4], &dst_mac->addr_bytes[5]);
        }

        pclose(fp);
    }
}

/**
 * The main function executed on each l-core.
 * 
 * @param temp Data (struct thread_info) for the sequence.
 * 
 * @return 0 on success and -1 on error.
**/
static int thread_hdl(void *temp)
{
    // Cast data as thread info.
    struct thread_info *ti = (struct thread_info *)temp;

    // Let's parse some config values before creating the socket so we know what we're doing.
    __u8 protocol = IPPROTO_UDP;
    struct rte_ether_addr src_mac;
    struct rte_ether_addr dst_mac;
    __u8 payload[MAX_PCKT_LEN];
    __u16 exact_pl_len = 0;
    __u16 data_len;

    // Allocate memory for our packet and check.
    struct rte_mbuf *pckt = rte_pktmbuf_alloc(pcktmbuf_pool);

    if (pckt == NULL)
    {
        fprintf(stderr, "Error initializing packet buffer from memory pool.\n");

        return -1;
    }

    // Retrieve the l-core ID.
    unsigned lcore_id = rte_lcore_id();

    // Iteration variables.
    unsigned i;
    unsigned j;

    // the port ID and number of packets from RX queue.
    unsigned port_id;
    unsigned nb_rx;

    // The specific RX queue config for the l-core.
    struct lcore_queue_conf *qconf = &lcore_queue_conf[lcore_id];

    // Pointer to TX buffer.
    struct rte_eth_dev_tx_buffer *buffer;

    // Create timer variables.
    __u64 prevtsc = 0;
    __u64 difftsc;
    __u64 curtsc;

    // For TX draining.
    const __u64 draintsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;

    // If we have no RX ports under this l-core, return because the l-core has nothing else to do.
    if (qconf->num_rx_ports == 0)
    {
        RTE_LOG(INFO, USER1, "lcore %u has nothing to do.\n", lcore_id);

        return -1;
    }

    // Log message.
    RTE_LOG(INFO, USER1, "Looping lcore %u with %u TX port(s) and %d TX queue(s) per port.\n", lcore_id, qconf->num_rx_ports, ti->cmd_dpdk.queues);

    // Let's first start off by checking if the source MAC address is set within the config.
    if (ti->seq.eth.src_mac != NULL)
    {
        sscanf(ti->seq.eth.src_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &src_mac.addr_bytes[0], &src_mac.addr_bytes[1], &src_mac.addr_bytes[2], &src_mac.addr_bytes[3], &src_mac.addr_bytes[4], &src_mac.addr_bytes[5]);
    }

    // Now check the destination MAC address.
    if (ti->seq.eth.dst_mac != NULL)
    {
        sscanf(ti->seq.eth.dst_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &dst_mac.addr_bytes[0], &dst_mac.addr_bytes[1], &dst_mac.addr_bytes[2], &dst_mac.addr_bytes[3], &dst_mac.addr_bytes[4], &dst_mac.addr_bytes[5]);
    }

    // Now match the protocol (we exclude UDP since that's default).
    if (ti->seq.ip.protocol != NULL && !strcmp(lower_str(ti->seq.ip.protocol), "tcp"))
    {
        protocol = IPPROTO_TCP;
    }
    else if (ti->seq.ip.protocol != NULL && !strcmp(lower_str(ti->seq.ip.protocol), "icmp"))
    {
        protocol = IPPROTO_ICMP;
    }

    // Now check for the payload.
    if (ti->seq.pl.exact != NULL)
    {
        char *pl_str = NULL;

        // Check if payload is file.
        if (ti->seq.pl.is_file)
        {
            FILE *fp = fopen(ti->seq.pl.exact, "rb");
            __u64 len = 0;

            // Check if our file is invalid. If so, print error and set empty payload string.
            if (fp == NULL)
            {
                fprintf(stderr, "Unable to open payload file (%s) :: %s.\n", ti->seq.pl.exact, strerror(errno));

                pl_str = malloc(sizeof(char) * 2);
                strcpy(pl_str, "");

                goto skippayload;
            }

            // Read file and store it in payload string.
            fseek(fp, 0, SEEK_END);
            len = ftell(fp);
            fseek(fp, 0, SEEK_SET);

            pl_str = malloc(len);

            if (pl_str)
            {
                if (fread(pl_str, 1, len, fp) < 1)
                {
                    fprintf(stderr, "WARNING - read below one byte from the payload file.\n");
                }
            }

            fclose(fp);
        }
        else
        {
            pl_str = strdup(ti->seq.pl.exact);
        }
        
        skippayload:;

        // Check if we want to parse the actual string.
        if (ti->seq.pl.is_string)
        {
            exact_pl_len = strlen(pl_str);

            memcpy(payload, pl_str, exact_pl_len);
        }
        else
        {
            // Split argument by space.
            char *split;
            char *rest = pl_str;

            while ((split = strtok_r(rest, " ", &rest)))
            {
                sscanf(split, "%2hhx", &payload[exact_pl_len]);
                
                exact_pl_len++;
            }
        }

        free(pl_str);
    }

    // Check if source MAC address is set properly. If not, let's get the MAC address of the interface we're sending packets out of.
    if (src_mac.addr_bytes[0] == 0 && src_mac.addr_bytes[1] == 0 && src_mac.addr_bytes[2] == 0 && src_mac.addr_bytes[3] == 0 && src_mac.addr_bytes[4] == 0 && src_mac.addr_bytes[5] == 0)
    {
        // Copy source MAC address of first port if we have only one per l-core.
        if (qconf->num_rx_ports == 1)
        {
            port_id = qconf->rx_port_list[0];
            rte_ether_addr_copy(&ports_eth[port_id], &src_mac);

            if (src_mac.addr_bytes[0] == 0 && src_mac.addr_bytes[1] == 0 && src_mac.addr_bytes[2] == 0 && src_mac.addr_bytes[3] == 0 && src_mac.addr_bytes[4] == 0 && src_mac.addr_bytes[5] == 0)
            {
                fprintf(stdout, "WARNING - Source MAC address retrieved is 00:00:00:00:00:00.\n");
            }
        }
    }

    // Check if destination MAC is set and if not, get the default gateway's MAC address.
    if (dst_mac.addr_bytes[0] == 0 && dst_mac.addr_bytes[1] == 0 && dst_mac.addr_bytes[2] == 0 && dst_mac.addr_bytes[3] == 0 && dst_mac.addr_bytes[4] == 0 && dst_mac.addr_bytes[5] == 0)
    {
        // Retrieve the default gateway's MAC address and store it in dst_mac.
        get_gw_mac_address(&dst_mac);
    }

    if (ti->cmd.verbose)
    {
        printf("Source MAC address (%d) => %hhx:%hhx:%hhx:%hhx:%hhx:%hhx.\n", ti->id, src_mac.addr_bytes[0], src_mac.addr_bytes[1], src_mac.addr_bytes[2], src_mac.addr_bytes[3], src_mac.addr_bytes[4], src_mac.addr_bytes[5]);
        printf("Destination MAC address (%d) => %hhx:%hhx:%hhx:%hhx:%hhx:%hhx.\n", ti->id, dst_mac.addr_bytes[0], dst_mac.addr_bytes[1], dst_mac.addr_bytes[2], dst_mac.addr_bytes[3], dst_mac.addr_bytes[4], dst_mac.addr_bytes[5]);
    }

    /* Our goal below is to set as many things before the while loop as possible since any additional instructions inside the while loop will impact performance. */

    // Some variables to help decide the randomness of our packets.
    __u8 need_csum = 1;
    __u8 need_l4_csum = 1;
    __u8 need_len_recal = 1;

    // Create rand_r() seed.
    unsigned int seed;

    // Common packet characteristics.
    __u8 l4_len;

    // Source IP string for a random-generated IP address.
    char s_ip[32];

    // Initialize Ethernet header.
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(pckt, struct rte_ether_hdr *);

    // Initialize IP header.
    struct rte_ipv4_hdr *iph = (struct rte_ipv4_hdr *)((char *)eth + sizeof(struct rte_ether_hdr));

    // Initialize UDP, TCP, and ICMP headers. Declare them as NULL until we know what protocol we're dealing with.
    struct rte_udp_hdr *udph = NULL;
    struct rte_tcp_hdr *tcph = NULL;
    struct rte_icmp_hdr *icmph = NULL;

    // Fill out Ethernet header.
    eth->ether_type = htons(ETH_P_IP);
    rte_ether_addr_copy(&src_mac, &eth->src_addr);
    rte_ether_addr_copy(&dst_mac, &eth->dst_addr);

    // Fill out IP header generic fields.
    iph->ihl = 5;
    iph->version = 4;
    iph->next_proto_id = protocol;
    iph->fragment_offset = 0;
    iph->type_of_service = ti->seq.ip.tos;

    // Check for static TTL.
    if (ti->seq.ip.min_ttl == ti->seq.ip.max_ttl)
    {
        iph->time_to_live = ti->seq.ip.max_ttl;
    }

    // Check for static ID.
    if (ti->seq.ip.min_id == ti->seq.ip.max_id)
    {
        iph->packet_id = htons(ti->seq.ip.max_id);
    }

    // Check for static source IP.
    if (ti->seq.ip.src_ip != NULL)
    {
        struct in_addr saddr;
        inet_aton(ti->seq.ip.src_ip, &saddr);

        iph->src_addr = saddr.s_addr; 
    }

    // Destination IP.
    struct in_addr daddr;
    inet_aton(ti->seq.ip.dst_ip, &daddr);

    iph->dst_addr = daddr.s_addr;

    // Handle layer-4 header (UDP, TCP, or ICMP).
    switch (protocol)
    {
        case IPPROTO_UDP:
            udph = (struct rte_udp_hdr *)((char *)eth + sizeof(struct rte_ether_hdr) + (iph->ihl * 4));
            l4_len = sizeof(struct rte_udp_hdr);

            // Check for static source/destination ports.
            if (ti->seq.udp.src_port > 0)
            {
                udph->src_port = htons(ti->seq.udp.src_port);
            }

            if (ti->seq.udp.dst_port > 0)
            {
                udph->dst_port = htons(ti->seq.udp.dst_port);
            }

            // If we have static/same payload length, let's set the UDP header's length here.
            if ((exact_pl_len > 0 || ti->seq.pl.is_static) || ti->seq.pl.min_len == ti->seq.pl.max_len)
            {
                data_len = (exact_pl_len > 0) ? exact_pl_len : ti->seq.pl.max_len;

                udph->dgram_len = htons(l4_len + data_len);

                // If we have static payload length/data or our source/destination IPs/ports are static, we can calculate the UDP header's outside of while loop.
                if ((ti->seq.udp.src_port > 0 && ti->seq.udp.dst_port > 0 && ti->seq.ip.src_ip != NULL) && (exact_pl_len > 0 || ti->seq.pl.is_static))
                {
                    need_l4_csum = 0;
                }

                need_len_recal = 0;
            }

            break;
        
        case IPPROTO_TCP:
            tcph = (struct rte_tcp_hdr *)((char *)eth + sizeof(struct rte_ether_hdr) + (iph->ihl * 4));

            tcph->data_off = 5;
            l4_len = (tcph->data_off * 4);

            // Check for static source/destination ports.
            if (ti->seq.tcp.src_port > 0)
            {
                tcph->src_port = htons(ti->seq.tcp.src_port);
            }

            if (ti->seq.tcp.dst_port > 0)
            {
                tcph->dst_port = htons(ti->seq.tcp.dst_port);
            }

            // Flags.
            tcph->tcp_flags |= (ti->seq.tcp.syn) ? (1 << 7) : 0;
            tcph->tcp_flags |= (ti->seq.tcp.ack) ? (1 << 4) : 0;
            tcph->tcp_flags |= (ti->seq.tcp.psh) ? (1 << 5) : 0;
            tcph->tcp_flags |= (ti->seq.tcp.fin) ? (1 << 8) : 0;
            tcph->tcp_flags |= (ti->seq.tcp.rst) ? (1 << 6) : 0;
            tcph->tcp_flags |= (ti->seq.tcp.urg) ? (1 << 3) : 0;

            // Check if we need to do length recalculation later on.
            if ((exact_pl_len > 0 || ti->seq.pl.is_static) || ti->seq.pl.min_len == ti->seq.pl.max_len)
            {
                data_len = (exact_pl_len > 0) ? exact_pl_len : ti->seq.pl.max_len;

                need_len_recal = 0;
            }

            // If we have static payload length/data or our source/destination IPs/ports are static, we can calculate the TCP header's checksum here.
            if (!need_len_recal && (ti->seq.tcp.src_port > 0 && ti->seq.tcp.dst_port > 0 && ti->seq.ip.src_ip != NULL) && (exact_pl_len > 0 || ti->seq.pl.is_static))
            {
                need_l4_csum = 0;
            }

            break;

        case IPPROTO_ICMP:
            icmph = (struct rte_icmp_hdr *)((char *)eth + sizeof(struct rte_ether_hdr) + (iph->ihl * 4));
            l4_len = sizeof(struct rte_icmp_hdr);

            // Set code and type.
            icmph->icmp_code = ti->seq.icmp.code;
            icmph->icmp_type = ti->seq.icmp.type;

            // If we have static payload length/data, we can calculate the ICMP header's checksum outside of while loop.
            if ((exact_pl_len > 0 || ti->seq.pl.is_static) || ti->seq.pl.min_len == ti->seq.pl.max_len)
            {
                data_len = (exact_pl_len > 0) ? exact_pl_len : ti->seq.pl.max_len;

                need_len_recal = 0;

                if (exact_pl_len > 0 || ti->seq.pl.is_static)
                {
                    need_l4_csum = 0;
                }
            }

            break;
    }

    // Check if we can set static IP header length.
    if (!need_len_recal)
    {
        iph->total_length = htons((iph->ihl * 4) + l4_len + data_len);
    }

    // Check if we need to calculate the IP checksum later on or not. If not, calculate now.
    if (ti->seq.ip.min_ttl == ti->seq.ip.max_ttl && ti->seq.ip.min_id == ti->seq.ip.max_id && ti->seq.ip.src_ip != NULL && !need_len_recal)
    {
        need_csum = 0;

        if (ti->seq.ip.csum)
        {
            iph->hdr_checksum = 0;
            iph->hdr_checksum = rte_ipv4_cksum(iph);
        }
    }

    // Initialize payload data.
    unsigned char *pl_data = (unsigned char *)((char *)eth + sizeof(struct rte_ether_hdr) + (iph->ihl * 4) + l4_len);

    // Check for exact payload.
    if (exact_pl_len > 0)
    {
        for (i = 0; i < exact_pl_len; i++)
        {
            *(pl_data + i) = payload[i];
        }

        // Calculate UDP and ICMP header's checksums.
        if (!need_l4_csum && protocol == IPPROTO_UDP && ti->seq.l4_csum)
        {
            udph->dgram_cksum = 0;
            udph->dgram_cksum = rte_ipv4_udptcp_cksum(iph, udph);
        }
        else if (!need_l4_csum && protocol == IPPROTO_TCP && ti->seq.l4_csum)
        {
            tcph->cksum = 0;
            tcph->cksum = rte_ipv4_udptcp_cksum(iph, tcph);
        }
        else if (!need_l4_csum && protocol == IPPROTO_ICMP && ti->seq.l4_csum)
        {
            icmph->icmp_cksum = 0;
            icmph->icmp_cksum = icmp_csum((__u16 *)icmph, l4_len + data_len);
        }
    }

    // Check for static payload.
    if (exact_pl_len < 1 && ti->seq.pl.is_static)
    {
        data_len = rand_num(ti->seq.pl.min_len, ti->seq.pl.max_len, seed);

        // Fill out payload with random characters.
        for (i = 0; i < data_len; i++)
        {
            *(pl_data + i) = rand_r(&seed);
        }

        // Recalculate UDP/ICMP checksums and ensure we don't calculate them again in while loop since we don't need to (will improve performance).
        if (!need_len_recal)
        {
            if (protocol == IPPROTO_UDP && ti->seq.l4_csum)
            {
                udph->dgram_cksum = 0;
                udph->dgram_cksum = rte_ipv4_udptcp_cksum(iph, udph);
            }
            if (protocol == IPPROTO_TCP && ti->seq.l4_csum)
            {
                tcph->cksum = 0;
                tcph->cksum = rte_ipv4_udptcp_cksum(iph, tcph);
            }
            else if (protocol == IPPROTO_ICMP && ti->seq.l4_csum)
            {
                icmph->icmp_cksum = 0;
                icmph->icmp_cksum = icmp_csum((__u16 *)icmph, l4_len + data_len);
            }

            need_l4_csum = 0;
        }
    }

    // Set ending time.
    time_t end = time(NULL) + ti->seq.time;

    // If we only have one port, assign port and buffer now.
    unsigned dst_port;
    
    if (qconf->num_rx_ports == 1)
    {
        dst_port = dst_ports[qconf->rx_port_list[0]];
        buffer = tx_buffer[dst_port];
    }

    __u16 pckt_len;

    // If our packet is completely static (no layer 3/4 checksum calculations outside of while loop), set opacket length.
    if (!need_csum && !need_l4_csum)
    {
        pckt_len = ntohs(iph->total_length) + sizeof(struct rte_ether_hdr);

        pckt->data_len = pckt_len;
        pckt->pkt_len = pckt_len;
    }

    // Loop.
    while (!quit)
    {
        // Get current timestamp.
        curtsc = rte_rdtsc();

        // Calculate the difference.
        difftsc = curtsc - prevtsc;

        // Check if we need to train the buffer.
        if (unlikely(difftsc > draintsc))
        {
            // Loop through all TX ports.
            for (i = 0; i < qconf->num_rx_ports; i++)
            {
                // If we have more than one TX port, reassign port ID (dst_port) and buffer.
                if (qconf->num_rx_ports > 1)
                {
                    dst_port = dst_ports[qconf->rx_port_list[i]];
                    buffer = tx_buffer[dst_port];
                }

                // Loop through all TX queues.
                for (j = 0; j < ti->cmd_dpdk.queues; j++)
                {
                    rte_eth_tx_buffer_flush(dst_port, j, buffer);
                }
            }

            // Assign prevtsc.
            prevtsc = curtsc;
        }

        // Increase count and check.
        if (ti->seq.count > 0 || ti->seq.track_count)
        {
            if (ti->seq.count > 0 && count[ti->seq_cnt] >= ti->seq.count)
            {
                break;
            }

            __sync_add_and_fetch(&count[ti->seq_cnt], 1);
        }

        // Check time.
        if (ti->seq.time > 0 && time(NULL) >= end)
        {
            break;
        }

        // Recalculate the seed based off of count and time.
        seed = time(NULL) ^ count[ti->seq_cnt];

        /* Assign random IP header values if need to be. */

        // Check for random TTL.
        if (ti->seq.ip.min_ttl != ti->seq.ip.max_ttl)
        {
            iph->time_to_live = rand_num(ti->seq.ip.min_ttl, ti->seq.ip.max_ttl, seed);
        }

        // Check for random ID.
        if (ti->seq.ip.min_id != ti->seq.ip.max_id)
        {
            iph->packet_id = htons(rand_num(ti->seq.ip.min_id, ti->seq.ip.max_id, seed));
        }

        // Check if source IP is defined. If not, get a random IP from the ranges and assign it to the IP header's source IP.
        if (ti->seq.ip.src_ip == NULL)
        {
            // Check if there are ranges.
            if (ti->seq.ip.range_count > 0)
            {
                __u16 ran = rand_num(0, (ti->seq.ip.range_count - 1), seed);

                // Ensure this range is valid.
                if (ti->seq.ip.ranges[ran] != NULL)
                {
                    if (ti->seq.count < 1 && !ti->seq.track_count)
                    {
                        count[ti->seq_cnt]++;
                    }
    
                    char *randip = rand_ip(ti->seq.ip.ranges[ran], &count[ti->seq_cnt]);

                    if (randip != NULL)
                    {
                        strcpy(s_ip, randip);
                    }
                    else
                    {
                        goto fail;
                    }
                }
                else
                {
                    fail:
                    fprintf(stderr, "ERROR - Source range count is above 0, but string is NULL. Please report this! Using localhost...\n");

                    strcpy(s_ip, "127.0.0.1");
                }
            }
            else
            {
                // This shouldn't happen, but since it did, just assign localhost and warn the user.
                fprintf(stdout, "WARNING - No source IP or source range(s) specified. Using localhost...\n");

                strcpy(s_ip, "127.0.0.1");
            }

            // Copy 32-bit IP address to IP header in network byte order.
            struct in_addr s_addr;
            inet_aton(s_ip, &s_addr);

            iph->src_addr = s_addr.s_addr;
        }
        
        // Check if we need to calculate random payload.
        if (exact_pl_len < 1 && !ti->seq.pl.is_static)
        {
            data_len = rand_num(ti->seq.pl.min_len, ti->seq.pl.max_len, seed);

            // Fill out payload with random characters.
            for (__u16 i = 0; i < data_len; i++)
            {
                *(pl_data + i) = rand_r(&seed);
            }
        }

        // Check layer-4 protocols and assign random characteristics if need to be.
        if (protocol == IPPROTO_UDP)
        {
            // Check for random source port.
            if (ti->seq.udp.src_port == 0)
            {
                udph->src_port = htons(rand_num(1, 65535, seed));
            }

            // Check for random destination port.
            if (ti->seq.udp.dst_port == 0)
            {
                udph->src_port = htons(rand_num(1, 65535, seed));
            }

            // Check for UDP length recalculation.
            if (need_len_recal)
            {
                udph->dgram_len = htons(l4_len + data_len);
            }

            // Check for UDP checksum recalculation.
            if (need_l4_csum && ti->seq.l4_csum)
            {
                udph->dgram_cksum = 0;
                udph->dgram_cksum = rte_ipv4_udptcp_cksum(iph, udph);
            }
        }
        else if (protocol == IPPROTO_TCP)
        {
            if (ti->seq.tcp.src_port == 0)
            {
                tcph->src_port = htons(rand_num(1, 65535, seed));
            }

            if (ti->seq.tcp.dst_port == 0)
            {
                tcph->dst_port = htons(rand_num(1, 65535, seed));
            }

            // Check if we need to calculate checksum.
            if (need_l4_csum && ti->seq.l4_csum)
            {
                tcph->cksum = 0;
                tcph->cksum = rte_ipv4_udptcp_cksum(iph, tcph);  
            }
        }
        else if (protocol == IPPROTO_ICMP)
        {
            if (need_l4_csum && ti->seq.l4_csum)
            {
                icmph->icmp_cksum = 0;
                icmph->icmp_cksum = icmp_csum((__u16 *)icmph, l4_len + data_len);
            }
        }
        
        // Check for length recalculation for IP header.
        if (need_len_recal)
        {
            iph->total_length = htons((iph->ihl * 4) + l4_len + data_len);
        }

        // Check if we need to calculate IP checksum.
        if (need_csum && ti->seq.ip.csum)
        {
            iph->hdr_checksum = 0;
            iph->hdr_checksum = rte_ipv4_cksum(iph);
        }

        // Set new packet length if need to be.
        if (need_len_recal)
        {
            // We need to recalculate our packet length.
            pckt_len = ntohs(iph->total_length) + sizeof(struct rte_ether_hdr);

            // We need to update the mbuf.
            pckt->data_len = pckt_len;
            pckt->pkt_len = pckt_len;
        }

        // Loop through each TX port on this l-core.
        for (i = 0; i < qconf->num_rx_ports; i++)
        {
            // If we have more than one port on this l-core, we need to copy the source MAC address and retrieve the port ID.
            if (qconf->num_rx_ports > 1)
            {
                // Retrieve the port ID.
                dst_port = qconf->rx_port_list[i];

                // Retrieve buffer.
                buffer = tx_buffer[dst_port];

                // Copy source MAC address of specific port.
                rte_ether_addr_copy(&ports_eth[dst_port], &eth->src_addr);

                // Check the source MAC address.
                if (eth->src_addr.addr_bytes[0] == 0 && eth->src_addr.addr_bytes[1] == 0 && eth->src_addr.addr_bytes[2] == 0 && eth->src_addr.addr_bytes[3] == 0 && eth->src_addr.addr_bytes[4] == 0 && eth->src_addr.addr_bytes[5] == 0)
                {
                    fprintf(stdout, "WARNING - Source MAC address on port %d retrieved as 00:00:00:00:00:00.\n", i);
                }
            }

            // Loop through the TX queues and buffer the packet.
            for (j = 0; j < ti->cmd_dpdk.queues; j++)
            {
                rte_eth_tx_buffer(dst_port, j, buffer, pckt);
            }
        }

        // Check if we want to send verbose output or not.
        if (ti->cmd.verbose)
        {
            // Retrieve source and destination ports for UDP/TCP protocols.
            __u16 srcport = 0;
            __u16 dstport = 0;

            if (protocol == IPPROTO_UDP)
            {
                srcport = ntohs(udph->src_port);
                dstport = ntohs(udph->dst_port);
            }
            else if (protocol == IPPROTO_TCP)
            {
                srcport = ntohs(tcph->src_port);
                dstport = ntohs(tcph->dst_port);
            }

            fprintf(stdout, "Sent %d bytes of data from %s:%d to %s:%d.\n", pckt_len, (ti->seq.ip.src_ip != NULL) ? ti->seq.ip.src_ip : s_ip, srcport, ti->seq.ip.dst_ip, dstport);
        }

        // Check data.
        if (ti->seq.max_data > 0)
        {
            if (total_data[ti->seq_cnt] >= ti->seq.max_data)
            {
                break;
            }

            __sync_add_and_fetch(&total_data[ti->seq_cnt], pckt_len);
        }

        // Check for delay.
        if (ti->seq.delay > 0)
        {
            usleep(ti->seq.delay);
        }
    }

    return 0;
}

/**
 * Starts a sequence in send mode. 
 * 
 * @param interface The networking interface to send packets out of.
 * @param seq A singular sequence structure containing relevant information for the packet.
 * @param seq_cnt2 The sequence counter from the main program.
 * @param cmd The command line structure.
 * @param cmd_dpdk The DPDK command line structure.
 * 
 * @return Void
**/
void seq_send(const char *interface, struct sequence seq, __u16 seq_cnt2, struct cmd_line cmd, struct cmd_line_dpdk cmd_dpdk)
{
    // First, let's check if the destination IP is set.
    if (seq.ip.dst_ip == NULL)
    {
        fprintf(stdout, "Destination IP not set on sequence #%u. Not moving forward with this sequence.\n", seq_cnt2);

        return;
    }

    // Create new thread_info structure to pass to threads.
    struct thread_info ti = {0};

    // Assign correct values to thread info.
    strcpy((char *)&ti.device, interface);
    memcpy(&ti.seq, &seq, sizeof(struct sequence));

    // Copy command line.
    ti.cmd = cmd;
    ti.cmd_dpdk = cmd_dpdk;

    // Create the threads needed.
    int threads = (seq.threads > 0) ? seq.threads : get_nprocs();

    // Reset count and total data for this sequence.
    count[seq_cnt] = 0;
    total_data[seq_cnt] = 0;

    ti.seq_cnt = seq_cnt2;

    // We'll want to execute 'thread_hdl' on each l-core and wait for them to finish the job.
    rte_eal_mp_remote_launch(thread_hdl, (void *)&ti, CALL_MAIN);

    RTE_LCORE_FOREACH_WORKER(lcore_id)
    {
        if (rte_eal_wait_lcore(lcore_id) < 0)
        {
            break;
        }
    }

    seq_cnt++;
}