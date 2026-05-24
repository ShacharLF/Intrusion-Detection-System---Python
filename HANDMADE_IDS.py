import json
from scapy.all import *
from datetime import datetime

from scapy.layers.inet import IP, TCP, UDP, ICMP

ALERT_MODE = "console"  # global variables, we will use it later in the output engine function to save the alerts
ALERT_FILE_PATH = None


def rule_parser_to_json(path_to_rules_txt_file):  # function that takes rule_database.txt and converts it to json
    json_dict = []
    clean_chars = ' "()'
    f = open(path_to_rules_txt_file)  # opening the rules file
    for row in f:
        row = row.strip()
        if row == "" or row.startswith("#"):
            continue

        header, options = row.split('(', 1)  # split the rules to header and options sections
        options = options.rstrip(')')  # limit options to the final )
        header_split = header.split()  # split the header to its constant fields by spaces
        action = header_split[0]
        protocol = header_split[1]
        src_ip = header_split[2]
        src_port = header_split[3]
        direction = header_split[4]
        dst_ip = header_split[5]
        dst_port = header_split[6]
        options_key_value_pair = options.split(";")  # first split to options by ; and later we will split by :
        options_dict = {}  # creating dict to append the key and values after we will split by :
        for item in options_key_value_pair:
            if item == "":
                continue
            key, value = item.split(":", 1)

            key = key.strip(clean_chars)
            value = value.strip(clean_chars)
            if value.isdigit():
                value = int(value)

            options_dict[key] = value  # appending to options_dict the key and values we created by the split by :
        dict_to_append = {  # building the final dict to return from this function and later we will write it to json
            "action": action,
            "protocol": protocol,
            "src_ip": src_ip,
            "src_port": src_port,
            "direction": direction,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "options": options_dict # pay attention this is not constant value like the others we built it thi value is a dictionary of the key-value pairs that we seprated by : earlier

        }

        json_dict.append(dict_to_append)  # we appended

    f.close()

    return json_dict


def write_rules_to_json(json_dict, path_to_json): # taking a dict in a json format which is python object and load it into json file in a target path
    with open(path_to_json, "w") as f:
        json.dump(json_dict, f)
    f.close()


def rule_manager(json_file_path): # takes json file and from him categorizing the rules by protocol for easier accsess by the engine later
    with open(json_file_path, "r") as file:
        rules_dot_json = json.load(file) #opening the file and load it using json
    valid_rules = [] # will add rules later
    supported_protocols = {"tcp", "udp", "icmp"}
    for rule in rules_dot_json:
        protocol = rule.get("protocol")
        if not protocol:
            print("Warning - This rule not contains Protocol")
            continue

        elif not rule.get("options"): # if it cant get the value in the optins sections which supoosed to be a
            # dictionary as we know, the rule probably missing "options"
            print("Warning - this rule contains only header, options is missing")
            continue
        elif "sid" not in rule["options"]:
            print("Warning- this rule is not containing sid")
            continue
        else:
            protocol = protocol.lower().strip() # normalize it to one format
            rule["protocol"] = protocol # so earlier in the code we defined that protocol = rule.get("protocol") so its from the rules database and now we are saying after we checked the rule is valid rule["protocol"] = normalized protocol so for example tcp = tcp
            if protocol not in supported_protocols:
                print(f"Warning - unsupported protocol: {protocol}")
                continue
            valid_rules.append(rule)

    rules_by_protocol = {
        "tcp": [],
        "udp": [],
        "icmp": []
    }

    for rule in valid_rules:
        rule_protocol = rule["protocol"] # for example rule["protocol"] == tcp so now rile_protocol == tcp
        rules_by_protocol[rule_protocol].append(rule) # for example rules_by_protocol[tcp].append(rule)

    return rules_by_protocol  # now the detection engine can do initial matching by protocol


def build_alert(pkt, rule): # function that recives a packet and rule, will be used at the end of the detection engine to build alert on malicios traffic in one format after we have matching between packet and rule
    return {
        "sid": rule['options']["sid"],
        "msg": rule['options']["msg"],
        "src_ip": pkt[IP].src,
        "dst_ip": pkt[IP].dst,
        "timestamp": datetime.now()
    }


def detection_engine(pkt, rules_by_protocol): #gets a packet and the rules categorizing by protocol for example tcp is an inside list that contains all the tcp rules in the dictionary format from earlier
    if not pkt.haslayer(IP): # to stop the code from failing when we sniffing packet that is not IP like ARP or something
        return
    protocol = None
    if pkt.haslayer(TCP):
        protocol = "tcp"
    elif pkt.haslayer(UDP):
        protocol = "udp"
    elif pkt.haslayer(ICMP):
        protocol = "icmp"
    if not protocol:
        return
    rules = rules_by_protocol.get(protocol)
    if not rules:
        return

    else:

        for rule in rules:
            if rule["src_ip"] != "any":  # header checking basic - if its not matching the rule just continue, for better understanding read the rules
                if pkt[IP].src != rule["src_ip"]:
                    continue

            if rule["dst_ip"] != "any":
                if pkt[IP].dst != rule["dst_ip"]:
                    continue

            if protocol in ("tcp", "udp"):

                if rule["src_port"] != "any":
                    if pkt.sport != int(rule["src_port"]):
                        continue

                if rule["dst_port"] != "any":
                    if pkt.dport != int(rule["dst_port"]):
                        continue

            rule_matched = True  #setting a bool variable that always true besides event that not matches between packets and the rules for example when we have a flags option in a rule and its value is "S" but in the tcp packet the flag is diffrent, we have a mismatch so we dont wanna detect it so we changing the boolian value and breaking and we will do detection only for the events where rule_matched == True

            for option, value in rule['options'].items(): # for every key and value inside the inside dictionary which is the value of the key options in the original rule dictionary

                if option == "msg" or option == "sid" or option == "rev":
                    continue

                if option == "flags":
                    if not pkt.haslayer(TCP):
                        rule_matched = False
                        break

                    if value == "S":
                        if not pkt[TCP].flags & 0x02:
                            rule_matched = False
                            break

                if option == "content":
                    if not pkt.haslayer(Raw):
                        rule_matched = False
                        break

                    payload = pkt[Raw].load
                    if value.encode() not in payload:
                        rule_matched = False
                        break

            if rule_matched:
                alert = build_alert(pkt, rule)
                output_engine(alert)


def output_engine(alert):
    if ALERT_MODE == "console": # global variable from the start of the code, used to know how to show the alert
        print("[ALERT]", alert)

    elif ALERT_MODE == "file":
        with open(ALERT_FILE_PATH, "a") as f: # the user defined the path at the main function and we are writing
            # the output locally to the path he gave
            f.write(str(alert) + "\n")


def print_banner():   #printing banner for the start of the main function
    print("\033[91m")  # RED

    print(r"""
██╗  ██╗ █████╗ ███╗   ██╗██████╗ ███╗   ███╗ █████╗ ██████╗ ███████╗
██║  ██║██╔══██╗████╗  ██║██╔══██╗████╗ ████║██╔══██╗██╔══██╗██╔════╝
███████║███████║██╔██╗ ██║██║  ██║██╔████╔██║███████║██║  ██║█████╗  
██╔══██║██╔══██║██║╚██╗██║██║  ██║██║╚██╔╝██║██╔══██║██║  ██║██╔══╝  
██║  ██║██║  ██║██║ ╚████║██████╔╝██║ ╚═╝ ██║██║  ██║██████╔╝███████╗
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝


██╗██████╗ ███████╗
██║██╔══██╗██╔════╝
██║██║  ██║███████╗
██║██║  ██║╚════██║
██║██████╔╝███████║
╚═╝╚═════╝ ╚══════╝


INTRUSION DETECTION SYSTEM
---------------------------
Monitoring network traffic for malicious
patterns and cyber threat indicators.

Based on a pre-made SNORT-like
network detection rules database
that will be updated and expanded in the future.

Currently detecting:
• TCP SYN Scan Detection
• HTTP Path Traversal Detection
• ICMP Echo Request Detection

Built for learning. Designed for defense.

Created by: Shachar Levi Friedman
    """)

    print("\033[0m")  # RESET COLOR


def main():
    print_banner()
    global ALERT_MODE, ALERT_FILE_PATH # importing these global variables inside the function
    ALERT_MODE = input(
        "Choose alert output mode (console / file): "
    ).strip().lower()

    if ALERT_MODE == "file":
        ALERT_FILE_PATH = input(
            "Enter path for alert log file: "
        ).strip().strip('"')

    path_to_rules = input("Where are your rules located? - path - ").strip().strip('"')
    path_to_json = input("Give the path you want to save the rules json file - ").strip().strip('"')
    pcap_or_sniff = input("Do you wanna monitor traffic from a pcap or from live sniffing on your "
                          "interface?, for pcap press p , and for sniffing press s - ")
    if pcap_or_sniff == "p":
        pcap_location = input("Give the local location of the PCAP file - ").strip().strip('"')
        rules_in_json_dict = rule_parser_to_json(path_to_rules)  # creating from their rules.txt file json dictionary which is python object
        write_rules_to_json(rules_in_json_dict, path_to_json)  # takes the dictionary and from the content and format
        # creating a json file in the json path they gave.

        rules_listed_by_protocol = rule_manager(path_to_json)  # this function takes the json file and listing and categorizing the rules
        # by protocol for easier categorization by the detection engine
        packets = rdpcap(pcap_location)  # read his pcap
        for pkt in packets:
            detection_engine(pkt, rules_listed_by_protocol)

    elif pcap_or_sniff == "s":

        interface = input(
            "Enter the interface NAME exactly as shown in show_interfaces(), if you dont know how its called you can"
            "run the show_interfaces command thorugh this tool by typing run - "
            "type run - : "
        ).strip()

        if interface == "run":
            show_interfaces()
            interface = input(" From this output, choose the interface you want to sniff and check the traffic"
                              "using the rules - ")

        rules_in_json_dict = rule_parser_to_json(path_to_rules)  # creating from their rules.txt file json dictionary which is python object

        write_rules_to_json(rules_in_json_dict, path_to_json) # takes the dictionary and from the content and format creating a json file in the json path they gave.
        rules_listed_by_protocol = rule_manager(path_to_json)  # this function takes the json file and listing and categorizing the rules
        # by protocol for easier categorization by the detection engine
        sniff(
            iface=interface,
            prn=lambda pkt: detection_engine(pkt, rules_listed_by_protocol), # lambadas is an empty function for holding so the prn could handle a fucntion that gets 2 values, as you can see our function detection engine which is the prn gets pkt and rules_listed_by_protocol
            store=False
        )


if __name__ == "__main__":
    main()
