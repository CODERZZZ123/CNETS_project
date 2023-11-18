# Current status , we are able to get the Connection data , which is packets,ports,IP,bytes,flags,wrong_fragmnets,connection_state,service,protocol_type

import pyshark
import time
from sys import argv
from collections import defaultdict
import csv


class ConnectionRecord:
    def __init__(self, packet_list, idx):
        self.packet_list = packet_list
        self.idx = idx
        self.dst_port = None
        self.scr_port = None
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

    def process(self, service_mapping):
        if "tcp" in self.packet_list[0]:
            self.protocol_type = "tcp"
            self.duration = float(self.packet_list[-1].tcp.time_relative)
            self._process_tcp(service_mapping)
        elif "udp" in self.packet_list[0]:
            self.protocol_type = "udp"
            self.duration = float(self.packet_list[-1].udp.time_relative)
            self._process_udp(service_mapping)
        elif "icmp" in self.packet_list[0]:
            self.protocol_type = "icmp"
            self._process_icmp()
        else:
            return

        self._process_common(service_mapping)

    def _process_common(self):
        self.src_port = int(self.packet_list[0][self.protocol_type].srcport)
        self.dst_port = int(self.packet_list[0][self.protocol_type].dstport)
        self._process_bytes_land_wrong_urgent_timestamp()
        self._process_status_flag_IP()

    def _process_tcp(self, service_mapping):
        if self.src_port <= self.dst_port:
            if ("tcp", self.src_port) not in service_mapping.keys():
                self.service = "Unassigned"
            else:
                self.service = service_mapping[("tcp", self.src_port)]
        else:
            if ("tcp", self.dst_port) not in service_mapping.keys():
                self.service = "Unassigned"
            else:
                self.service = service_mapping[("tcp", self.dst_port)]

        pass

    def _process_udp(self, service_mapping):
        if self.src_port <= self.dst_port:
            if ("udp", self.src_port) not in service_mapping.keys():
                self.service = "Unassigned"
            else:
                self.service = service_mapping[("udp", self.src_port)]
        else:
            if ("udp", self.dst_port) not in service_mapping.keys():
                self.service = "Unassigned"
            else:
                self.service = service_mapping[("udp", self.dst_port)]
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
            if "ip" in self.packet_list[0]:
                if self.src_ip == packet.ip.src:
                    self.src_bytes += int(packet.length.size)
                else:
                    self.dst_bytes += int(packet.length.size)
            else:
                if self.src_ip == packet.ipv6.src:
                    self.src_bytes += int(packet.length.size)
                else:
                    self.dst_bytes += int(packet.length.size)

            if self.protocol == "tcp":
                if packet.tcp.flags_urg == "1":
                    self.urgent += 1
                if packet.tcp.checksum_status != "2":
                    self.wrong_frag += 1

            elif self.protocol == "udp":
                if packet.udp.checksum_status != "2":
                    self.wrong_frag += 1

            elif self.protocol == "icmp":
                if packet.icmp.checksum_status != "2":
                    self.wrong_frag += 1

        pass

    def get_connection_status(packets, ipv4=True):
        def process_packet_key(packet, source_ip):
            flags = (packet.tcp.flags_syn, packet.tcp.flags_ack, packet.tcp.flags_reset, packet.tcp.flags_fin)
            return ('1' if source_ip == packet.ip.src else '0', *flags) if ipv4 else ('1' if source_ip == packet.ipv6.src else '0', *flags)



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

        source_ip = packets[0].ip.src if ipv4 else packets[0].ipv6.src

        connection_status = "INIT"

        for packet in packets:
            key = process_packet_key(packet, source_ip)
            try:
                connection_status = conn[connection_status][key]
            except KeyError:
                status_mapping = {'INIT': 'OTH', 'SH': 'SH', 'SHR': 'SHR', 'RSTRH': 'RSTRH', 'OTH': 'OTH', 'REJ': 'REJ', 'RST0S0': 'RST0S0', 'RST0': 'RST0', 'RSTR': 'RSTR', 'SF': 'SF'}
                return status_mapping.get(connection_status, 'OTH')

        return connection_status

    def _process_status_flag_IP(self):
        if "ip" in self.packet_list[0]:
            self.src_ip = self.packet_list[0].ip.src
            self.dst_ip = self.packet_list[0].ip.dst
            self.status_flag = self.get_connection_status(self.packet_list)
        else:
            self.src_ip = self.packet_list[0].ipv6.src
            self.dst_ip = self.packet_list[0].ipv6.dst
            self.status_flag = self.get_connection_status(self.packet_list, False)
        pass

    def __str__(self):
        return (
            f"{self.timestamp},{self.src_ip},{self.src_port},"
            f"{self.dst_ip},{self.dst_port},{self.idx},"
            f"{self.duration},{self.protocol_type},{self.service},{self.status_flag},"
            f"{self.src_bytes},{self.dst_bytes},{self.land},{self.wrong_fragment},{self.urgent}"
        )


class NetworkPacketSniffer:
    def __init__(self, pcap_file, filename):
        self.cap_file = pcap_file
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
            ]
        ]

    def _get_connection_key(self, packet):
        if "tcp" in packet:
            return "tcp_conn" + packet.tcp.stream
        elif "udp" in packet:
            return "udp_conn" + packet.udp.stream
        elif "icmp" in packet:
            return f"icmp_conn_{packet.ip.src}_{packet.ip.dst}_{packet.icmp.type}"
        else:
            # for other protocol , we will sort out what to do with this case
            pass

    def create_connection_records(self):
        # cap = pyshark.FileCapture(self.cap_file)              # this method directly gets the packet already capture , using FIlecapture can also acheive real time but with few sec delay
        cap = pyshark.LiveCapture(interface=None)

        # figuring out how to stop this and continue the feature extraction process
        # Also focus on parallelize "the packet read" and "feature extract process" if time permits

        raw_connections = defaultdict(list)

        try:
            for packet in cap:
                key = self.get_connection_key(packet)
                raw_connections[key].append(packet)

        except StopIteration:
            pass

        return dict(raw_connections)

    def get_iana(self):
        filename = self.service_map_file
        with open(filename, "r", newline="") as csvfile:
            csvreader = csv.reader(csvfile)
            for row in csvreader:
                try:
                    service = row[0]
                    port = int(row[1])
                    protocol = row[2].lower()

                    if service and port and protocol:
                        port_protocol_tuple = (protocol, port)
                        self.service_mapping[port_protocol_tuple] = service
                except (IndexError, ValueError):
                    continue

    def initialize_connection(self, raw_connections):
        connections = []
        idx = 0

        for key, packet_list in raw_connections.items():
            connection = ConnectionRecord(packet_list, idx)
            connection.process(self.service_mapping)
            connections.append(connection)
            self.records.append(str(connection))
            idx += 1

        return connections

    def process_packets(self):
        service_mapping = self.get_iana()
        raw_connections = self.create_connection_records()
        connections = self.initialize_connection(raw_connections, service_mapping)

        # other feature like host features and server feature to be added soon

        return connections

    def save_records_to_csv(self, filename="record_self.csv"):
        with open(filename, "w+") as out:
            for record in self.records:
                out.write(record + "\n")


def main():
    service_file = "service_map.csv"
    if len(argv) == 1:
        cap_file = None
        sniffer = NetworkPacketSniffer(cap_file, service_file)
    elif len(argv) == 2:
        cap_file = argv[1]
        sniffer = NetworkPacketSniffer(cap_file, service_file)
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

