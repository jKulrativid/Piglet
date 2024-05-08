from snortparser.snortparser import Parser

import binascii
import socket

from p4_template import template

HOMENET = "192.168.56.3"
RULE_NEED = 200
filename="snort-3-rules/snort3-community.rules"

class FiveTuples:
    def __init__(self, proto, src_ip, dst_ip, src_port, dst_port):
        self.proto = proto
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port

def ipv4_to_hex(ipv4):
    return "0x" + binascii.hexlify(socket.inet_aton(ipv4)).decode()

def generate_p4_condition(ftp : FiveTuples):
    mapper = {"$HOME_NET": HOMENET, "$EXTERNAL_NET": HOMENET}
    rules = []
    if ftp.src_ip is not None and ftp.src_ip != "any":
        sign = "=" if ftp.src_ip != "$EXTERNAL_NET" else "!"
        cmp_ip = ftp.src_ip if "$" not in ftp.src_ip else mapper[ftp.src_ip]
        rules.append("hdr.ipv4.src {}= {}".format(sign, ipv4_to_hex(cmp_ip)))
    if ftp.dst_ip is not None and ftp.dst_ip != "any":
        sign = "=" if ftp.dst_ip != "$EXTERNAL_NET" else "!"
        cmp_ip = ftp.dst_ip if "$" not in ftp.dst_ip else mapper[ftp.dst_ip]
        rules.append("hdr.ipv4.dst {}= {}".format(sign, ipv4_to_hex(cmp_ip)))
    
    if ftp.proto in ["tcp", "udp"]:
        if ftp.src_port is not None and ftp.src_port != "any":
            if int(ftp.src_port) <= 65535 or int(ftp.dst_port) > 0:
                rules.append("hdr.{}.src_port == {}".format(ftp.proto, ftp.src_port))
        if ftp.dst_port is not None and ftp.dst_port != "any":
            if int(ftp.dst_port) <= 65535 or int(ftp.dst_port) > 0:
                rules.append("hdr.{}.dst_port == {}".format(ftp.proto, ftp.dst_port))

    return "is_safe = is_safe || ({});".format(" && ".join(rules))

ip_conditions = []
tcp_conditions = []
udp_conditions = []

with open(filename, "r") as f:
    rule_idx = 0
    valid_rule_cnt = 0
    for line in f.readlines():
        try:
            ph = Parser(line).header

            proto = ph["proto"]
            src_ip = ph["source"][1] if ph["source"] else None
            dst_ip = ph["destination"][1] if ph["destination"] else None
            src_port = ph["src_port"][1] if ph["src_port"] else None
            dst_port = ph["dst_port"][1] if ph["dst_port"] else None

            ftp = FiveTuples(proto, src_ip, dst_ip, src_port, dst_port)

            cond = generate_p4_condition(ftp)

            if proto == "ip":
                ip_conditions.append(cond)
            elif proto == "tcp":
                tcp_conditions.append(cond)
            elif proto == "udp":
                udp_conditions.append(cond)
        
            valid_rule_cnt += 1
            if valid_rule_cnt >= RULE_NEED:
                break
         
        except Exception as e:
            print("error at {} : {}".format(rule_idx, e))
        rule_idx += 1

with open("piglet.p4", "w") as f:
    new_p4 = template.format(ip_rules="\n".join(ip_conditions), udp_rules="\n".join(udp_conditions), tcp_rules="\n".join(tcp_conditions))
    f.write(new_p4)
