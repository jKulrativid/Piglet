from snortparser.snortparser import Parser

filename="snort-3-rules/snort3-community.rules"

parsed_rules = []

i = 1

with open(filename, "r") as f:
    for line in f.readlines():
        try:
            parsed_rules.append(Parser(line))
        except Exception as e:
            print("error at {} : {}".format(i, e))
        i+=1

h0 = parsed_rules[0].header
print(h0)
print(h0['action'], h0['proto'], h0['source'], h0['src_port'], h0['destination'], h0['dst_port'])