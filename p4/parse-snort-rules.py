from snortparser.snortparser import Parser

filename="snort3-community.rules"

parsed_rules = []

i = 1

with open(filename, "r") as f:
    for line in f.readlines():
        try:
            parsed_rules.append(Parser(line))
        except Exception as e:
            print("error at {} : {}".format(i, e))
        i+=1

print(parsed_rules[0].all)