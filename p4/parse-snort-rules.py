from snortparser.snortparser import Parser

import binascii
import socket

from p4_template import template

OUT_FILE = "piglet-200.p4"
RULE_NEED = 200
filename="snort-3-rules/snort3-community.rules"

ip_map = {
    "$HOME_NET": "192.168.1.0/24",
    "$EXTERNAL_NET": "0.0.0.0/32",
    "any": "0.0.0.0/32"
}

port_map = {
    "$HTTP_PORTS": "80",
    "any": ":"
}

class FiveTuples:
    def __init__(self, proto, src_ip, dst_ip, src_port, dst_port):
        self.proto = proto
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
    
    def tostring(self):
        return "A-{}|B-{}|C-{}|D-{}|E-{}".format(
            self.proto,
            self.src_ip,
            self.dst_ip,
            self.src_port,
            self.dst_port
        )

def ipv4_to_hex(ipv4):
    return "0x" + binascii.hexlify(socket.inet_aton(ipv4)).decode()

def gen_ip_rule(src_or_dst, ip):
    if "$" in ip or ip == "any":
        ip = ip_map.get(ip, None)
        if ip is None:
            raise Exception("given IP variable not found in the map")
    
    ip, cidr = ip.split("/")
    if cidr == "":
        return "hdr.ipv4.{}  == {}".format(src_or_dst, ipv4_to_hex(ip))
    else:
        cidr = int(cidr, 10)
        ip = ipv4_to_hex(ip)
        mask_binary = "1"*(32-cidr)  + "0"*cidr
        mask_hex = hex(int(mask_binary, 2))
        return "((hdr.ipv4.{} & {}) == {})".format(src_or_dst, mask_hex, ipv4_to_hex(ip))

def gen_port_rule(proto, src_or_dst, port_desc):
    varname = "hdr.{}.{}".format(proto, src_or_dst)
    if "$" in port_desc or port_desc == "any":
        port_desc = port_map.get(port_desc, None)
        if port_desc is None:
            raise Exception("given PORT variable not found in the map")
    
    ports = port_desc.split(",")
    
    port_cmps = []
    for p in ports:
        cmp = ""
        if ":" in p:
            rangecmp = []
            start, end = p.split(":")
            if start != "":
                rangecmp.append("{} >= {}".format(varname, int(start)))
            if end != "":
                rangecmp.append("{} <= {}".format(varname, int(end)))
            
            if len(rangecmp) > 0:
                port_cmps.append("(" + " && ".join(rangecmp) + ")")
        else:
            port_cmps.append("({} == {})".format(varname, int(p)))


    return " || ".join(port_cmps)

def generate_p4_condition(ftp : FiveTuples):
    rules = []
    if ftp.src_ip is not None:
        rules.append(gen_ip_rule("src", ftp.src_ip))
    if ftp.dst_ip is not None:
        rules.append(gen_ip_rule("dst", ftp.dst_ip))
    
    if ftp.proto in ["tcp", "udp"]:
        if ftp.src_port is not None:
            r = gen_port_rule(ftp.proto, "src", ftp.src_port)
            if r != "":
                rules.append(r)
        if ftp.dst_port is not None:
            r = gen_port_rule(ftp.proto, "dst", ftp.dst_port)
            if r != "":
                rules.append(r)

    if len(rules) == 0:
        raise Exception("rule do nothing")
    return "is_safe = is_safe && !({});".format(" && ".join(rules))


unique_checker = {"hello": 1}    

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
            src_ip = ph["source"][1] if ph["source"][0] else None
            dst_ip = ph["destination"][1] if ph["destination"][0] else None
            src_port = ph["src_port"][1] if ph["src_port"][0] else None
            dst_port = ph["dst_port"][1] if ph["dst_port"][0] else None

            if isinstance(src_port, list):
                src_port = ",".join([x[1] for x in src_port])
            if isinstance(dst_port, list):
                dst_port = ",".join([x[1] for x in dst_port])
            
            ftp = FiveTuples(proto, src_ip, dst_ip, src_port, dst_port)
            
            unique_checker[ftp.tostring()] = 1

            cond = generate_p4_condition(ftp)

            if unique_checker.get(cond, 0) == 1:
                raise Exception("redundant rules")
            
            unique_checker[cond] = 1

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

with open(OUT_FILE, "w") as f:
    new_p4 = template.format(ip_rules="\n".join(ip_conditions), udp_rules="\n".join(udp_conditions), tcp_rules="\n".join(tcp_conditions))
    f.write(new_p4)
