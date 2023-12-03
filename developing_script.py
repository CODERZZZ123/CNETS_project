# Current status , we are able to get the Connection data , which is packets,ports,IP,bytes,flags,wrong_fragmnets,connection_state,service,protocol_type

import pyshark
import time
from sys import argv
from collections import defaultdict
import csv


class Connection_Host_Client:
    def __init__(self, packet_list, idx):
        self.packet_list = packet_list
        self.idx = idx
        self.dst_port = None
        self.src_port = None
        self.protocol_type = None
        self.service = None
        self.status_flag = None
        self.src_bytes = 0
        self.dst_bytes = 0
        self.land = 0
        self.wrong_fragment = 0
        self.urgent = 0
        self.timestamp = packet_list[-1].sniff_timestamp
        self.duration = 0
        self.dst_ip = None
        self.src_ip = None
        self.hot = 0
        self.num_failed_logins = 0
        self.logged_in = 0
        self.num_compromised = 0
        self.root_shell = 0
        self.su_attempted = 0
        self.num_root = 0
        self.num_file_creations = 0
        self.num_access_files = 0
        self.num_outbound_cmds = 0
        self.is_hot_login = 0
        self.is_guest_login = 0
        self.long_services = {}
        self.srv_long_hosts = {}
        self.long_count = 0
        self.long_serror_count = 0
        self.long_rerror_count = 0
        self.long_same_services = 0
        self.long_diff_services = 0
        self.long_same_src_ports = 0
        self.srv_long_count = 0
        self.srv_long_serror_count = 0
        self.srv_long_rerror_count = 0
        self.srv_long_diff_hosts = 0

    def process(self, service_mapping):
        if "udp" in self.packet_list[0] or "UDP" in self.packet_list[0]:
            self.protocol_type = "UDP"
            self.src_port = int(self.packet_list[0][self.protocol_type].srcport)
            self.dst_port = int(self.packet_list[0][self.protocol_type].dstport)
            self.duration = float(self.packet_list[-1].udp.time_relative)
            self._process_udp(service_mapping)
        elif "icmp" in self.packet_list[0] or "ICMP" in self.packet_list[0]:
            self.protocol_type = "ICMP"
            self.src_port = int(self.packet_list[0][self.protocol_type].srcport)
            self.dst_port = int(self.packet_list[0][self.protocol_type].dstport)
            self._process_icmp()
        elif "tcp" in self.packet_list[0] or "TCP" in self.packet_list[0]:
            self.protocol_type = "TCP"
            self.src_port = int(self.packet_list[0][self.protocol_type].srcport)
            self.dst_port = int(self.packet_list[0][self.protocol_type].dstport)
            self.duration = float(self.packet_list[-1].tcp.time_relative)
            self._process_tcp(service_mapping)
        else:
            return "None"
        # self.src_port = int(self.packet_list[0][self.protocol_type].srcpo_type
        self._process_common()
        self.operations_data()

    def _process_common(self):
        self._process_bytes_land_wrong_urgent_timestamp()
        self._process_status_flag_IP()

    def _process_tcp(self, service_mapping):
        if self.src_port <= self.dst_port:
            if ("TCP", self.src_port) not in service_mapping.keys():
                self.service = "Unassigned"
            else:
                self.service = service_mapping[("TCP", self.src_port)]
        else:
            if ("TCP", self.dst_port) not in service_mapping.keys():
                self.service = "Unassigned"
            else:
                self.service = service_mapping[("TCP", self.dst_port)]

        pass

    def _process_udp(self, service_mapping):
        if self.src_port <= self.dst_port:
            if ("UDP", self.src_port) not in service_mapping.keys():
                self.service = "Unassigned"
            else:
                self.service = service_mapping[("UDP", self.src_port)]
        else:
            if ("UDP", self.dst_port) not in service_mapping.keys():
                self.service = "Unassigned"
            else:
                self.service = service_mapping[("UDP", self.dst_port)]
        pass

    def _process_icmp(self):
        self.service = "eco_i"
        # for other services we will see what to do
        pass

    def _process_bytes_land_wrong_urgent_timestamp(self):
        if self.src_ip == self.dst_ip and self.src_port == self.dst_port:
            self.land = 1
        else:
            self.land = 0

        self.timestamp = self.packet_list[-1].sniff_timestamp

        for packet in self.packet_list:
            if (
                "ip" in self.packet_list[0]
                or "IP" in self.packet_list[0]
                or "Ip" in self.packet_list[0]
            ):
                if self.src_ip == packet.ip.src:
                    self.src_bytes += int(packet.length.size)
                else:
                    self.dst_bytes += int(packet.length.size)
            else:
                if self.src_ip == packet.ipv6.src:
                    self.src_bytes += int(packet.length.size)
                else:
                    self.dst_bytes += int(packet.length.size)

            if self.protocol_type == "TCP":
                if packet.tcp.flags_urg == "1":
                    self.urgent += 1
                if packet.tcp.checksum_status != "2":
                    self.wrong_frag += 1

            elif self.protocol_type == "UDP":
                if packet.udp.checksum_status != "2":
                    self.wrong_frag += 1

            elif self.protocol_type == "ICMP":
                if packet.icmp.checksum_status != "2":
                    self.wrong_frag += 1

        pass

    def Connection_type_flags_status(self, ipv4=True):
        if (
            "udp" in self.packet_list[0]
            or "icmp" in self.packet_list[0]
            or "UDP" in self.packet_list[0]
            or "ICMP" in self.packet_list[0]
        ):
            return "SF"

        def process_packet_key(packet, source_ip):
            flags = (
                packet.tcp.flags_syn,
                packet.tcp.flags_ack,
                packet.tcp.flags_reset,
                packet.tcp.flags_fin,
            )
            return (
                ("1" if source_ip == packet.ip.src else "0", *flags)
                if ipv4
                else ("1" if source_ip == packet.ipv6.src else "0", *flags)
            )

        conn = {
            "INIT": {
                (0, 1, 1, 0, 0): "S4",
                (1, 0, 0, 0, 1): "SH",
                (1, 1, 0, 0, 0): "S0",
            },
            "S4": {(0, 0, 0, 1, 0): "SHR", (0, 0, 0, 0, 1): "RSTRH"},
            "SH": {},
            "SHR": {},
            "RSTRH": {},
            "OTH": {},
            "S0": {
                (0, 1, 1, 0, 0): "S1",
                (0, 0, 0, 1, 0): "REJ",
                (1, 0, 0, 1, 0): "RST0S0",
            },
            "REJ": {},
            "RST0S0": {},
            "RST0": {},
            "RSTR": {},
            "S1": {
                (1, 0, 1, 0, 0): "ESTAB",
                (1, 0, 0, 1, 0): "RST0",
                (0, 0, 0, 1, 0): "RSTR",
            },
            "ESTAB": {(1, 0, 1, 0, 1): "S2", (0, 0, 1, 0, 1): "S3"},
            "S2": {(0, 0, 1, 0, 0): "SF"},
            "S3": {(1, 0, 1, 0, 0): "SF"},
            "SF": {},
        }
        # print("----------" , self.packet_list[0] , "------------------")
        source_ip = self.packet_list[0].ip.src if ipv4 else self.packet_list[0].ipv6.src

        connection_status = "INIT"

        for packet in self.packet_list:
            key = process_packet_key(packet, source_ip)
            try:
                connection_status = conn[connection_status][key]
            except KeyError:
                status_mapping = {
                    "INIT": "OTH",
                    "SH": "SH",
                    "SHR": "SHR",
                    "RSTRH": "RSTRH",
                    "OTH": "OTH",
                    "REJ": "REJ",
                    "RST0S0": "RST0S0",
                    "RST0": "RST0",
                    "RSTR": "RSTR",
                    "SF": "SF",
                }
                return status_mapping.get(connection_status, "OTH")

        return connection_status
    def hex_extract(self,hex_payload):
            command = None
            if len(hex_payload) % 2 != 0:
                hex_payload = "0" + hex_payload

            try:
                # Convert hex to bytes and then decode to string
                command_bytes = bytes.fromhex(hex_payload)
                command = command_bytes.decode().lower()

                # Now 'command' holds the string representation of the hex payload
                print("Command:", command)
            except ValueError as e:
                try:
                    # Convert hex to bytes
                    payload_bytes = bytes.fromhex(hex_payload)

                    # Convert bytes to string by ignoring non-ASCII characters
                    payload_string = "".join(chr(byte) if 32 <= byte < 127 else '?' for byte in payload_bytes)

                    return payload_string
                except ValueError as e:
                    print("Error decoding hex payload:", e)
                    return "Nan"
            return command



    def num_failed_login_func(self):
        failed_login_patterns = [
            "failed login",
            "login failed",
            "authentication failed",
            "invalid login",
            "incorrect password",
            "access denied",
            "login error",
            "unsuccessful login",
            "login attempt failed",
            "bad credentials",
            "login incorrect",
            "authentication error",
            "authentication unsuccessful",
            "login failed for user",
            "invalid username or password",
            "incorrect login",
        ]

        for packet in self.packet_list:
            try:
                # Extract payload and convert to lowercase for case-insensitive matching
                payload = getattr(packet.tcp, "payload", None)
                if payload is not None:
                    command_list = packet.tcp.payload.replace(":", "")
                    command = self.hex_extract(command_list)
                    if any(pattern in command for pattern in failed_login_patterns):
                        self.num_failed_logins = self.num_failed_logins + 1
                    # You can further analyze or log the event here
                else:
                    print("Payload attribute is missing for this packet.")
            except AttributeError:
                continue

    def root_related(self):
        root_access_patterns = [
            "root",
            "sudo",
            "su",
            "login as root",
            "privileged",
            "admin",
            "superuser",
            "elevate",
            "escalate",
            "become root",
        ]
        for packet in self.packet_list:
            try:
                # Extract payload and convert to lowercase for case-insensitive matching
                payload = getattr(packet.tcp, "payload", None)
                if payload is not None:
                    command_list = packet.tcp.payload.replace(":", "")
                    command = self.hex_extract(command_list)
                    # Check for root access patterns
                    if any(pattern in command for pattern in root_access_patterns):
                        self.root_shell = 1
                        self.su_attempted = 1
                        self.num_root = self.num_root + 1
                else:
                    print("Payload attribute is missing for this packet.")
                    # You can further analyze or log the event here
            except AttributeError:
                continue

    def files_related(self):
        file_creation_patterns = [
            "create file",
            "touch",
            "echo",
            "write file",
            "new file",
            "write to file",
            "edit file",
            "make file",
            "append file",
            "generate file",
        ]

        file_patterns  = [
            "open_file",
            "read_file",
            "write_file",
            "file_access",
            "file_operation",
            "delete_file",
            "copy_file",
            "move_file",
            "create_file",
            "file_download",
            "file_upload",
            "file_permission_change",
            "file_attribute_change",
            "file_execute",
            "file_listing",
            "file_locking",
        ]
        for packet in self.packet_list:
            try:
                # Extract payload and convert to lowercase for case-insensitive matching
                payload = getattr(packet.tcp, "payload", None)
                if payload is not None:
                    command_list = packet.tcp.payload.replace(":", "")
                    command = self.hex_extract(command_list)
                    if any(pattern in command for pattern in file_creation_patterns):
                        self.num_file_creations += 1
                    # Continue with processing payload_lower
                else:
                    # Handle the case where 'payload' attribute is missing
                    print("Payload attribute is missing for this packet.")
                # Check for file creation patterns

            except AttributeError:
                continue

        for packet in self.packet_list:
            # Assuming the payload contains information about file access
            payload = getattr(packet.tcp, "payload", None)
            if payload is not None:
                command_list = packet.tcp.payload.replace(":", "")
                command = self.hex_extract(command_list)
                if any(pattern in command for pattern in file_patterns):
                    self.num_file_creations += 1
                # Continue with processing payload_lower
            else:
                # Handle the case where 'payload' attribute is missing
                print("Payload attribute is missing for this packet.")

            # Check for specific patterns or keywords indicating file access

    def logged_in_func(self):
        successful_login_patterns = [
            "successful login",
            "login successful",
            "logged in",
            "authentication successful",
            "login accepted",
            "user authenticated",
            "access granted",
            "login confirmed",
            "authorized access",
            "session established",
            "login complete",
            "authentication passed",
            "user session started",
            "authenticated successfully",
            "login approved",
            "validated login",
            "user logged on",
            "access permitted",
            "login authorized",
            "user access granted",
            "login successful from",
            "authenticated user",
            "access allowed",
        ]
        for packet in self.packet_list:
            try:
                payload = getattr(packet.tcp, "payload", None)
                if payload is not None:
                    command_list = packet.tcp.payload.replace(":", "")
                    command = self.hex_extract(command_list)
                    # Extract payload and convert to lowercase for case-insensitive matching
                    # Check for file creation patterns
                    if any(
                        pattern in command for pattern in successful_login_patterns
                    ):
                        self.logged_in = 1
                else:
                    print("Payload attribute is missing for this packet.")

            except AttributeError:
                continue

    def compromised(self):
        compromised_patterns = [
            "exploit",
            "malware",
            "backdoor",
            "trojan",
            "compromised host",
            "unauthorized access",
            "security breach",
            "suspicious activity",
            "infected system",
            "compromise detected",
            "anomaly detected",
            "intrusion attempt",
            "security alert",
            "unusual behavior",
            "threat detected",
            "command and control",
            "payload execution",
            "abnormal traffic",
            "suspicious payload",
            "anomalous behavior",
            "compromised account",
            "data exfiltration",
            "unauthorized activity",
            "malicious activity",
        ]
        for packet in self.packet_list:
            try:
                # Extract payload and convert to lowercase for case-insensitive matching
                payload = getattr(packet.tcp, "payload", None)

                if payload is not None:
                    command_list = packet.tcp.payload.replace(":", "")
                    command = self.hex_extract(command_list)
                    # Check for file creation patterns
                    if any(pattern in command for pattern in compromised_patterns):
                        self.num_compromised = self.num_compromised + 1
                else:
                    print("Payload attribute is missing for this packet.")

            except AttributeError:
                continue

    def logged_in_root_failed(self):
        for packet in self.packet_list:
            try:
                # Get the ASCII output
                command_list = packet.tcp.payload.replace(":", "")
                command = self.hex_extract(command_list)

                print(command, end="")

                # First check if for login attempt successful or not
                if self.logged_in == 1:
                    # User is logged in, try to get the prompt!
                    if "#" in command:
                        self.root_shell = 1
                    if "$" or "#" in command:
                        print(command, end="")
                else:
                    # User is NOT logged in
                    if "Last login" in command:
                        self.logged_in = 1
                    if "failed" in command:
                        self.num_failed_logins += 1
            except UnicodeDecodeError:
                continue
            except AttributeError:
                continue

    def operations_data(self):
        if self.protocol_type == "TCP":
            self.compromised()
            # self.logged_in = self.logged_in_func()
            # self.num_failed_logins = self.num_failed_login_func()
            self.root_related()
            self.files_related()
            self.logged_in_root_failed()
    def calculate_long_count(connections, current_connection):
        dst_ip = current_connection["dst_ip"]
        long_count = 0

        for connection in connections:
            if connection["dst_ip"] == dst_ip:
                long_count += 1

        return long_count
    def calculate_long_count(self,connections):
        for connection in connections:
            if connection.dst_ip == self.dst_ip:
                self.long_count += 1
                self.R_error_S_error(connection)
            else : 
                self.other_feature(connection)
        if self.long_count > 0:
            self.long_serror_rate = self.long_serror_count / self.long_count
            self.long_rerror_rate = self.long_rerror_count / self.long_count
            if self.long_diff_services > 1:
                self.long_diff_srv_rate = self.long_diff_services / self.long_count
            else:
                self.long_diff_srv_rate = 0
            self.long_same_srv_rate = self.long_same_services / self.long_count
            self.long_same_src_port_rate = self.long_same_src_ports / self.long_count

        else:
            self.long_serror_rate = 0
            self.long_rerror_rate = 0
            self.long_diff_srv_rate = 0
            self.long_same_srv_rate = 0
            self.long_same_src_port_rate = 0

        if self.srv_long_count > 0:
            self.srv_long_serror_rate = self.srv_long_serror_count / self.srv_long_count
            self.srv_long_rerror_rate = self.srv_long_rerror_count / self.srv_long_count
            if self.srv_long_diff_hosts > 1:
                self.srv_long_diff_host_rate = self.srv_long_diff_hosts / self.srv_long_count
            else:
                self.srv_long_diff_host_rate = 0
        else:
            self.srv_long_serror_rate = 0
            self.srv_long_rerror_rate = 0
        self.srv_long_diff_host_rate = 0


    
    def other_feature(self,connection):
        if self.service == connection.service:
            self.srv_long_count += 1
            # count various errors
            if connection.status_flag != "SF":
                if 'S' in connection.status_flag:
                    self.srv_long_serror_count += 1
                elif 'R' in connection.status_flag : 
                    self.srv_long_rerror_count += 1

            if self.srv_long_count == 1:
                self.srv_long_hosts[self.srv_long_diff_hosts] = connection.dst_ip
                self.srv_long_diff_hosts += 1
            else:
                j = 0
                for j in range(0, self.srv_long_diff_hosts, 1):
                    if self.srv_long_hosts[j] == connection.dst_ip:
                        break
                if j == self.srv_long_diff_hosts:
                    self.srv_long_hosts[self.srv_long_diff_hosts] = connection.dst_ip
                    self.srv_long_diff_hosts += 1


    def R_error_S_error(self,connection):
            if connection.dst_ip == self.dst_ip:
                if self.status_flag != "SF":
                    if 'S' in connection.status_flag:
                        self.long_serror_count += 1
                    elif 'R' in connection.status_flag:
                        self.ong_rerror_count += 1
                if self.service == connection.service:
                        self.long_same_services += 1

                if self.long_count == 1:
                    self.long_services[self.long_diff_services] = connection.service
                    self.long_diff_services += 1
                else:
                    j = 0
                    for j in range(0, self.long_diff_services, 1):
                        if self.long_services[j] == connection.service:
                            break
                    if j == self.long_diff_services:
                        self.long_services[self.long_diff_services] = connection.service
                        self.long_diff_services += 1

                if self.src_port == connection.src_port:
                    self.long_same_src_ports += 1
                


    def derive_host_features(self, connections, hosts):
        # print(self.timestamp)
        self.calculate_long_count(connections)

    

        

    def _process_status_flag_IP(self):
        if (
            "ip" in self.packet_list[0]
            or "IP" in self.packet_list[0]
            or "Ip" in self.packet_list[0]
        ):
            self.src_ip = self.packet_list[0].ip.src
            self.dst_ip = self.packet_list[0].ip.dst
            self.status_flag = self.Connection_type_flags_status()
        else:
            self.src_ip = self.packet_list[0].ipv6.src
            self.dst_ip = self.packet_list[0].ipv6.dst
            self.status_flag = self.Connection_type_flags_status(False)
        pass

    def __str__(self):
        return (
            f"{self.timestamp},{self.src_ip},{self.src_port},"
            f"{self.dst_ip},{self.dst_port},{self.idx},"
            f"{self.duration},{self.protocol_type},{self.service},{self.status_flag},"
            f"{self.src_bytes},{self.dst_bytes},{self.land},{self.wrong_fragment},{self.urgent},"
            f"{self.hot},{self.num_failed_logins},{self.logged_in},"
            f"{self.num_compromised},{self.root_shell},{self.su_attempted},"
            f"{self.num_root},{self.num_file_creations},{self.num_access_files},"
            f"{self.num_outbound_cmds},{self.is_hot_login},{self.is_guest_login},"
            f"{self.long_services},{self.srv_long_hosts},{self.long_count},{self.long_serror_count},"
            f"{self.long_rerror_count},{self.long_same_services},{self.long_diff_services},{self.long_same_src_ports},"
            f"{self.srv_long_count},{self.srv_long_serror_count},{self.srv_long_rerror_count},{self.srv_long_diff_hosts}"
        )


class NetworkPacketSniffer:
    def __init__(self, pcap_file1, filename):
        self.file1 = pcap_file1
        self.service_mapping = {}
        self.service_map_file = filename
        self.records = [
            [
                "timestamp",
                "src_ip",
                "src_port",
                "dst_ip",
                "dst_port",
                "idx",
                "duration",
                "protocol_type",
                "service",
                "flag",
                "src_bytes",
                "dst_bytes",
                "land",
                "wrong_fragment",
                "urgent",
                "num_failed_logins",
                "logged_in",
                "num_compromised",
                "root_shell",
                "su_attempted",
                "num_root",
                "num_file_creations",
                "num_access_files",
                "num_outbound_cmds",
                "is_hot_login",
                "is_guest_login",
                "srv_long_hosts",
                "long_count",
                "long_serror_count",
                "long_rerror_count",
                "long_same_services",
                "long_diff_services",
                "long_same_src_ports",
                "srv_long_count",
                "srv_long_serror_count",
                "srv_long_rerror_count",
                "srv_long_diff_hosts"
            ]
        ]

    def _get_connection_key(self, packet):
        # print(str(packet).lower())
        # print("-------------------------------")
        if "tcp" in packet or "TCP" in packet:
            return "tcp_conn" + packet.tcp.stream
        elif "udp" in packet or "UDP" in packet:
            return "udp_conn" + packet.udp.stream
        elif "icmp" in packet or "ICMP" in packet:
            return f"icmp_conn_{packet.ip.src}_{packet.ip.dst}_{packet.icmp.type}"
        else:
            # for other protocol , we will sort out what to do with this case
            pass

    def create_connection_records(self):
        cap = pyshark.FileCapture(
            self.file1
        )  # this method directly gets the packet already capture , using FIlecapture can also acheive real time but with few sec delay
        # cap = pyshark.LiveCapture(interface='wlp4s0')

        # figuring out how to stop this and continue the feature extraction process
        # Also focus on parallelize "the packet read" and "feature extract process" if time permits

        raw_connections = defaultdict(list)

        for packet in cap:
            # print(packet)
            key = self._get_connection_key(packet)
            raw_connections[key].append(packet)
            # print("--------------------------------------------------")
            # print(key)
            # print(raw_connections[key])

        return dict(raw_connections)

    def get_protocol_port_service(self):
        filename = self.service_map_file
        with open(filename, "r", newline="") as csvfile:
            csvreader = csv.reader(csvfile)
            for row in csvreader:
                try:
                    service = row[2]
                    port = int(row[1])
                    protocol = row[0]
                    print(service)
                    print(port)
                    if service and port and protocol:
                        port_protocol_tuple = (protocol, port)
                        self.service_mapping[port_protocol_tuple] = service
                        # print(self.service_mapping)
                except (IndexError, ValueError):
                    continue

    def connection_to_setup(self, raw_connections):
        connections = []
        idx = 0

        for key, packet_list in raw_connections.items():
            connection = Connection_Host_Client(packet_list, idx)
            connection.process(self.service_mapping)
            if connection.status_flag == None :
                continue
            connections.append(connection)
            
            idx += 1
        # print(self.records)
        return connections

    def process_packets(self):
        self.get_protocol_port_service()
        raw_connections = self.create_connection_records()
        connections = self.connection_to_setup(raw_connections)

        for host_client in connections : 
            host_client.derive_host_features(connections , len(connections))
            print("-------------------------------")
            self.records.append(str(host_client))
        # other feature like host features and server feature to be added soon

        return connections

    def save_records_to_csv(self, filename="record_self.csv"):
        with open(filename, "w+", newline="") as out:
            csv_writer = csv.writer(out)

            # Write the header row
            csv_writer.writerow(self.records[0])

            # Write the data rows
            for record in self.records[1:]:
                record_split = record.split(",")
                csv_writer.writerow(record_split)


def main():
    service_file = "service_map.csv"
    if len(argv) == 1:
        file_captures = None
        sniffer = NetworkPacketSniffer("pcap_file1.pcap", service_file)
    elif len(argv) == 2:
        file_captures = argv[1]
        sniffer = NetworkPacketSniffer(file_captures, service_file)
    else:
        print(
            "-------------------------=-----------------------------------------------------------------------"
        )
        return

    connections = sniffer.process_packets()
    sniffer.save_records_to_csv()
    print(
        "##################################THE-END#######################################"
    )


if __name__ == "__main__":
    main()
