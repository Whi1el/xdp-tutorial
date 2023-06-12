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




static __always_inline void update_iph_checksum(struct iphdr *iph) 
{
    __u16 *next_iph_u16 = (__u16 *)iph;
    __u32 csum = 0;
    iph->check = 0;
#pragma clang loop unroll(full)
    for (__u32 i = 0; i < sizeof(*iph) >> 1; i++) 
    {
        csum += *next_iph_u16++;
    }   
 
    int i = 0;
    while (csum >> 16 && i < 4)
    {
        csum = (csum & 0xffff) + (csum >> 16);
        i++;
    }
    iph->check = (__u16) ~csum;
}


static __always_inline void confusion_ipv4_tcp(__u16 eth_type_num, __u8 ip_protocol_num, int* flag, void* data_statr, void* data_end)
{
    if(*flag || eth_type_num != bpf_htons(ETH_P_IP) || ip_protocol_num != IPPROTO_TCP) 
    {
        // bpf_printk("ERROE.\n");
        return;
    }
    *flag = 1;

    /*解析数据包*/
    struct hdr_cursor nh = { .pos = data_statr };
    struct ethhdr* eth_hdr = NULL;
    struct iphdr* ip_hdr = NULL;
    struct tcphdr* tcp_hdr = NULL;
    if (parse_ethhdr(&nh, data_end, &eth_hdr) != -1)
    {
        // bpf_printk("eth_hdr %d.\n", eth_hdr->h_proto);
        
    } else {
        return;
    }

    if (parse_iphdr(&nh, data_end, &ip_hdr) != -1)
    {
        bpf_printk("ip_hdr %d.\n", ip_hdr->protocol);
        bpf_printk("TTL %d.\n", ip_hdr->ttl);
        bpf_printk("ip_hdr->check1 %d.\n", ip_hdr->check);
        ip_hdr->ttl = 10;
        update_iph_checksum(ip_hdr);
    } else {
        return;
    }
    
    int data_len = parse_tcphdr(&nh, data_end, &tcp_hdr);
    if (data_len != -1)
    {
        __u64 csum = 0;
        tcp_hdr->check = 0;
        int tcplen = bpf_ntohs(ip_hdr->tot_len) - ip_hdr->ihl * 4;
        ipv4_l4_csum((void *)tcp_hdr, (__u32)tcplen, &csum, ip_hdr, data_end);
        bpf_printk("tcp_hdr->check2 %d.\n", csum);
    } else {
        return;
    }

    /*重新计算校验和*/

    
}

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
    __u16 eth_type = 0;
    __u8 ip_protocol_num = -1;
    eth_type = parse_ethhdr(&nh, data_end, &eth_hdr);
    if (eth_type == bpf_htons(ETH_P_IP))
    {
        //TODO: 基于IPv4判断传输层协议
        ip_protocol_num = parse_iphdr(&nh, data_end, &ip_hdr);
        // bpf_printk("IPv4\n");

    }
    else if (eth_type == bpf_htons(ETH_P_IPV6))
    {
        //TODO: 基于IPv6判断传输层协议
        ip_protocol_num = parse_ip6hdr(&nh, data_end, &ipv6_hdr);
        // bpf_printk("IPv6\n");
    }
    else
    {
        //TODO: 其他协议目前暂不处理
        // bpf_printk("Other\n");
        goto out;
    }
    
    int flag = 0;
    confusion_ipv4_tcp(eth_type, ip_protocol_num, &flag, data, data_end);
    // confusion_ipv4_udp(eth_type, ip_protocol_num, &flag, data, data_end);
    // confusion_ipv6_tcp(eth_type, ip_protocol_num, &flag, data, data_end);
    // confusion_ipv6_udp(eth_type, ip_protocol_num, &flag, data, data_end);

out:
    return xdp_stats_record_action(ctx, action);
}

SEC("xdp")
int  xdp_prog_simple(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";