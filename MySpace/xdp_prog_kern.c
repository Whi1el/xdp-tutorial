/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"

/* Defines xdp_stats_map */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"


SEC("xdp_TTL_rewrite")
int xdp_TTL_rewrite_func(struct xdp_md *ctx)
{
    int action              = XDP_PASS;
    void *data_end          = (void *)(long)ctx->data_end;
    void *data              = (void *)(long)ctx->data;
    struct hdr_cursor nh    = { .pos = data };
    struct ethhdr* eth_hdr = NULL;
    struct iphdr* ip_hdr = NULL;
    struct ipv6hdr* ipv6_hdr = NULL;
    
    /*解析网络层和传输层协议的版本*/
    int eth_type = 0;
    int ip_protocol_num = -1;
    eth_type = parse_ethhdr(&nh, data_end, &eth_hdr);
    if (eth_type == bpf_htons(ETH_P_IP))
    {
        //TODO: 基于IPv4判断传输层协议
        ip_protocol_num = parse_iphdr(&nh, data_end, &ip_hdr);

    }
    else if (eth_type == bpf_htons(ETH_P_IPV6))
    {
        //TODO: 基于IPv6判断传输层协议
        ip_protocol_num = parse_ip6hdr(&nh, data_end, &ipv6_hdr);
    }
    else
    {
        //TODO: 其他协议目前暂不处理
        goto out;
    }

    bpf_printk("eth_type %d.ip_protocol_num %d\n", eth_type, ip_protocol_num);
    
out:
    return xdp_stats_record_action(ctx, action);
}

SEC("xdp")
int  xdp_prog_simple(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";