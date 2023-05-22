/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
/* Defines xdp_stats_map from packet04 */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

/*vlan 头结构体*/
struct vlan_hdr
{
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

/* Packet parsing helpers.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in host byte order.
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	/*
	* |<---目的地址--->|<---源地址--->|<-类型->|<--------...数据...--------->|<--CRC-->|
	*/
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;

	return eth->h_proto; /* network-byte-order */
}

/* Assignment 2: Implement and use this */
static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr)
{
    struct ipv6hdr *ip6h = nh->pos;
    if (ip6h+1 > data_end)
    {
        return -1;
    }
    nh->pos = ip6h + 1;
    *ip6hdr = ip6h;

    return ip6h->nexthdr;
}

/* Assignment 3: Implement and use this */
static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmp6hdr **icmp6hdr)
{
	struct icmp6hdr *icmp6 = nh->pos;
	if (icmp6+1 > data_end) 
	{
		return -1;
	}
	nh->pos = icmp6 + 1;
	*icmp6hdr = icmp6;

	return icmp6->icmp6_sequence;
}

/*确定以太网头中包裹的协议是 VLAN*/
static __always_inline int proto_is_vlan(__u16 h_proto)
{
        return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
                  h_proto == bpf_htons(ETH_P_8021AD));
}

/*解析VLAN包*/
static __always_inline int parse_vlan(struct hdr_cursor *nh, void *data_end, struct vlan_hdr **vlanhdr)
{
	struct vlan_hdr *point_vlan = nh->pos;
	if (point_vlan+1 > data_end)
	{
		return -1;
	}
	nh->pos = point_vlan+1;
	*vlanhdr = point_vlan;

	return point_vlan->h_vlan_encapsulated_proto;
}

/*解析IPv4包*/
static __always_inline int parse_ip(struct hdr_cursor *nh, void *data_end, struct iphdr **iphdr)
{
	struct iphdr *pointer_ip = nh->pos;
	if (pointer_ip+1 > data_end)
	{
		return -1;
	}
	int hdrsize = pointer_ip->ihl * 4;
	if (nh->pos + hdrsize > data_end)
	{
		return -1;
	}
	nh->pos += hdrsize;
	return pointer_ip->protocol;
}

/*解析ICMP协议*/
// static __always_inline int parse_icmphdr(struct hdr_cursor *nh, void *data_end, struct icmphdr **icmphdr)
// {
// 	struct icmphdr *icmp4 = nh->pos;

// 	if (icmp4+1 > data_end) 
// 	{
// 		return -1;
// 	}
// 	*icmphdr = nh->pos;
// 	return icmp4->type;
// }

SEC("xdp_packet_parser")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;
	struct vlan_hdr *vlan;
	struct iphdr *ipv4;
	struct ipv6hdr *ipv6;
	// struct icmphdr *icmp;
	struct icmp6hdr *icmp6;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

        /* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type, nexthdr, seqnumber;
	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_ethhdr(&nh, data_end, &eth);

	/*判断若不是IPV6协议、不是IPv4协议且不是vlan协议，则直接放行*/
	if ( nh_type != bpf_htons(ETH_P_IPV6) && !proto_is_vlan(nh_type) && nh_type != bpf_htons(ETH_P_IP)) 
	{
		goto out;
	}

	if ( nh_type == bpf_htons(ETH_P_IPV6) ) 
	{
		/* Assignment additions go below here */
		nexthdr = parse_ip6hdr(&nh, data_end, &ipv6);
		if (nexthdr != IPPROTO_ICMPV6)					// 8位值不涉及大端序和小端序的问题。
			goto out;

		seqnumber = parse_icmp6hdr(&nh, data_end, &icmp6);
		if (bpf_ntohs(seqnumber)%2 == 1)
			goto out;
	}

	if ( nh_type == bpf_htons(ETH_P_IP) ) 
	{
		/* Assignment additions go below here */
		nexthdr = parse_ip(&nh, data_end, &ipv4);
		if (nexthdr == IPPROTO_ICMP)					// 8位值不涉及大端序和小端序的问题。
			goto out;

		// icmp_type = parse_icmphdr(&nh, data_end, &icmp);
		// if (icmp_type != ICMP_ECHO)
		// 	goto out;
	}

	if (proto_is_vlan(nh_type))
	{
		/*处理 VLAN tag*/
		nh_type = parse_vlan(&nh, data_end, &vlan);
		/*判断是否是IPV6协议*/
		if (nh_type != bpf_htons(ETH_P_IPV6))
			goto out;
		/*解析IPV6头，并判断是否是ICMPV6*/
		nexthdr = parse_ip6hdr(&nh, data_end, &ipv6);
		if (nexthdr != IPPROTO_ICMPV6)					// 8位值不涉及大端序和小端序的问题。
			goto out;
		/*解析ICMPV6头，判断序列号是否是偶数*/
		seqnumber = parse_icmp6hdr(&nh, data_end, &icmp6);
		if (bpf_ntohs(seqnumber)%2 == 1)
			goto out;

	}

	action = XDP_DROP;
out:
	return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
}

char _license[] SEC("license") = "GPL";
