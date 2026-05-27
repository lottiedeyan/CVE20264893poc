#!/usr/bin/env python3
"""DNS ECS responder using Scapy without DNSRROPT_ECS.

Listens on a UDP port and replies to DNS queries with an OPT record
containing an RFC7871 EDNS Client Subnet (option code 8). The ECS rdlen
is computed from the provided source prefix (normal behaviour).
"""

import argparse
import socket
import struct
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send, sniff


def ecs_option_data(
    ip_str: str,
    src_prefix: int,
    scope_prefix: int,
    family: int = 1,
    rdlen_override: int | None = None,
) -> bytes:
    # family: 1 for IPv4, 2 for IPv6
    # pack family (2 bytes), srcmask (1), scopemask (1), then address bytes (ceil(src_prefix/8))
    if family == 1:
        addr_bin = socket.inet_aton(ip_str)
    else:
        addr_bin = socket.inet_pton(socket.AF_INET6, ip_str)

    addr_len = (src_prefix + 7) // 8
    addr_trunc = addr_bin[:addr_len]

    ecs_data = struct.pack("!HBB", family, src_prefix, scope_prefix) + addr_trunc

    if rdlen_override is None:
        return ecs_data

    if rdlen_override < 0:
        return ecs_data

    if len(ecs_data) >= rdlen_override:
        return ecs_data[:rdlen_override]

    return ecs_data + (b"\x00" * (rdlen_override - len(ecs_data)))


def build_opt_rr(ecs_data: bytes, udp_payload_size: int = 4096) -> DNSRR:
    """Build an OPT RR with ECS option (code 8) as raw rdata."""
    rdata = struct.pack("!HH", 8, len(ecs_data)) + ecs_data
    return DNSRR(rrname=b".", type=41, rclass=udp_payload_size, ttl=0, rdata=rdata)


def build_dns_response(pkt, ecs_ip, src_prefix, scope_prefix, rdlen_override):
    dns = pkt[DNS]
    qname = dns.qd.qname if dns.qd else b"."
    qtype = dns.qd.qtype if dns.qd else 1

    # Simple A answer; adjust as needed
    answer = DNSRR(rrname=qname, type=qtype, ttl=60, rdata="1.2.3.4")

    # Build ECS option data
    ecs_data = ecs_option_data(ecs_ip, src_prefix, scope_prefix, family=1, rdlen_override=rdlen_override)
    opt = build_opt_rr(ecs_data, udp_payload_size=4096)

    resp = (
        IP(src=pkt[IP].dst, dst=pkt[IP].src)
        / UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)
        / DNS(
            id=dns.id,
            qr=1,
            aa=1,
            rd=dns.rd,
            ra=1,
            qd=dns.qd,
            an=answer,
            ar=opt,
        )
    )

    return resp


def build_dns_payload(dns_pkt, ecs_ip, src_prefix, scope_prefix, rdlen_override):
    """Build a DNS layer (no IP/UDP) to send over a UDP socket."""
    dns = dns_pkt
    qname = dns.qd.qname if dns.qd else b"."
    qtype = dns.qd.qtype if dns.qd else 1

    answer = DNSRR(rrname=qname, type=qtype, ttl=60, rdata="1.2.3.4")
    ecs_data = ecs_option_data(ecs_ip, src_prefix, scope_prefix, family=1, rdlen_override=rdlen_override)
    opt = build_opt_rr(ecs_data, udp_payload_size=4096)

    resp = DNS(
        id=dns.id,
        qr=1,
        aa=1,
        rd=dns.rd,
        ra=1,
        qd=dns.qd,
        an=answer,
        ar=opt,
    )

    return resp


def udp_server(listen_port, ecs_ip, src_prefix, scope_prefix, rdlen_override):
    """Simple UDP server to receive DNS queries and reply without requiring root."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", listen_port))
    print(f"UDP socket server listening on port {listen_port}")
    while True:
        try:
            data, addr = sock.recvfrom(4096)
        except KeyboardInterrupt:
            break
        if not data:
            continue
        try:
            dns_req = DNS(data)
        except Exception:
            continue
        if dns_req.qr != 0:
            continue
        dns_resp = build_dns_payload(dns_req, ecs_ip, src_prefix, scope_prefix, rdlen_override)
        try:
            sock.sendto(bytes(dns_resp), addr)
        except Exception:
            continue


def handle_packet(pkt, listen_port, ecs_ip, src_prefix, scope_prefix, rdlen_override):
    if DNS not in pkt or UDP not in pkt or IP not in pkt:
        return
    if pkt[UDP].dport != listen_port:
        return
    if pkt[DNS].qr != 0:
        return

    resp = build_dns_response(pkt, ecs_ip, src_prefix, scope_prefix, rdlen_override)
    send(resp, verbose=False)


def main():
    parser = argparse.ArgumentParser(description="DNS ECS responder for testing.")
    parser.add_argument("--iface", default=None, help="Interface to sniff on")
    parser.add_argument("--port", type=int, default=53535, help="UDP port to listen (non-privileged default)")
    parser.add_argument("--ecs-ip", default="8.8.8.8", help="ECS client subnet IP to include")
    parser.add_argument("--src-prefix", type=int, default=24, help="ECS source prefix length")
    parser.add_argument("--scope-prefix", type=int, default=0, help="ECS scope prefix length")
    parser.add_argument("--ecs-rdlen", type=int, default=None, help="Override ECS option rdlen (bytes)")
    parser.add_argument("--use-socket", action="store_true", help="Use UDP socket server (no root required)")
    args = parser.parse_args()

    print(f"Listening on UDP port {args.port}, ECS {args.ecs_ip}/{args.src_prefix}, scope {args.scope_prefix}")

    if args.use_socket:
        udp_server(args.port, args.ecs_ip, args.src_prefix, args.scope_prefix, args.ecs_rdlen)
    else:
        sniff(
            iface=args.iface,
            filter=f"udp port {args.port}",
            prn=lambda p: handle_packet(p, args.port, args.ecs_ip, args.src_prefix, args.scope_prefix, args.ecs_rdlen),
            store=0,
        )


if __name__ == "__main__":
    main()
