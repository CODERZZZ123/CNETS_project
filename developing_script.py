import pyshark
import time
from sys import argv


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

    def process(self, service_mapping):
        if "tcp" in self.packet_list[0]:
            self.protocol_type = "tcp"
            self.duration = float(self.packet_list[-1].tcp.time_relative)
            self._process_tcp()
        elif "udp" in self.packet_list[0]:
            self.protocol_type = "udp"
            self.duration = float(self.packet_list[-1].udp.time_relative)
            self._process_udp()
        elif "icmp" in self.packet_list[0]:
            self.protocol_type = "icmp"
            self._process_icmp()
        else:
            return

        self._process_common(service_mapping)

    def _process_common(self, service_mapping):
        self.src_port = int(self.packet_list[0][self.protocol_type].srcport)
        self.dst_port = int(self.packet_list[0][self.protocol_type].dstport)

        if self.src_port <= self.dst_port:
            key = (self.protocol_type, self.src_port)
        else:
            key = (self.protocol_type, self.dst_port)

        if key not in service_mapping:
            self.service = "Unassigned"
        else:
            self.service = service_mapping[key]

        self._process_bytes()
        self._process_status_flag()

    def _process_tcp(self ,service_mapping):
        self.protocol = "tcp"
        self.duration = float(self.packet_list[-1].tcp.time_relative)
        self.src_port = int(self.packet_list[0].tcp.srcport)
        self.dst_port = int(self.packet_list[0].tcp.dstport)
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

    def _process_udp(self,service_mapping):
        self.protocol = 'udp'
        self.duration = float(self.packet_list[-1].udp.time_relative)
        self.src_port = int(self.packet_list[0].udp.srcport)
        self.dst_port = int(self.packet_list[0].udp.dstport)
        if self.src_port <= self.dst_port:
            if ('udp', self.src_port) not in service_mapping.keys():
                self.service="Unassigned"
            else:
                self.service = service_mapping[('udp', self.src_port)]
        else:
            if ('udp', self.dst_port) not in service_mapping.keys():
                self.service="Unassigned"
            else:
                self.service = service_mapping[('udp', self.dst_port)]
        pass

    def _process_icmp(self):
        self.protocol = 'icmp'
        self.src_port = int(self.packet_list[0].icmp.srcport)
        self.dst_port = int(self.packet_list[0].icmp.dstport)
        self.duration = float(self.packet_list[0].icmp.time_relative)
    
        self.service = 'eco_i'         # ? why only eco_i , lets serch for other 
        pass

    def _process_bytes_land_wrong_urgent_timestamp_duration(self):
        if self.src_ip == self.dst_ip and self.src_port == self.dst_port:
            land = 1
        else:
            land = 0

        timestamp = self.packet_list[-1].sniff_timestamp
        # traverse packets (some basic features are aggregated from each packet in whole connection)
        for packet in self.packet_list:
            if 'ip' in self.packet_list[0]:
                if self.src_ip == packet.ip.src:
                    self.src_bytes += int(packet.length.size)
                else:
                    self.dst_bytes += int(packet.length.size)
            else:
                if self.src_ip == packet.ipv6.src:
                    self.src_bytes += int(packet.length.size)
                else:
                    self.dst_bytes += int(packet.length.size)

            # Urgent packets only happen with TCP
            if self.protocol == 'tcp':
                if packet.tcp.flags_urg == '1':
                    self.urgent += 1
                if packet.tcp.checksum_status != '2':
                    self.wrong_frag += 1

            elif self.protocol == 'udp':
                if packet.udp.checksum_status != '2':
                    self.wrong_frag += 1

            elif self.protocol == 'icmp':
                if packet.icmp.checksum_status != '2':
                    self.wrong_frag += 1
        self.timestamp = self.packet_list[-1].sniff_timestamp
        pass

    def _process_status_flag(self):
        
        pass

    def __str__(self):
        return (
            f"{self.timestamp},{self.packet_list[0].ip.src},{self.src_port},"
            f"{self.packet_list[0].ip.dst},{self.dst_port},{self.idx},"
            f"{self.duration},{self.protocol_type},{self.service},{self.status_flag},"
            f"{self.src_bytes},{self.dst_bytes},{self.land},{self.wrong_fragment},{self.urgent}"
        )


class NetworkPacketSniffer:
    def __init__(self, pcap_file):
        self.cap_file = pcap_file
        self.records = [
            [
                "timestamp",
                "src_ip",
                "src_port",
                "dst_ip",
                "dst_port",
                "index",
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

    def create_connection_records(self):
        cap = pyshark.FileCapture(self.cap_file)
        raw_connections = {}

        for packet in cap:
            try:
                key = self._get_connection_key(packet)
                if key not in raw_connections:
                    raw_connections[key] = [packet]
                else:
                    raw_connections[key].append(packet)
            except AttributeError:
                continue

        return raw_connections

    def _get_connection_key(self, packet):
        if "tcp" in packet:
            return "tcp_conn" + packet.tcp.stream
        elif "udp" in packet:
            return "udp_conn" + packet.udp.stream
        elif "icmp" in packet:
            return f"icmp_conn_{packet.ip.src}_{packet.ip.dst}_{packet.icmp.type}"
        else:
            raise ValueError("Unsupported protocol")

    def get_iana(self):
        filename = './service_map.csv'
        with open(filename, 'r') as fd:
            for line in fd:
                stuff = line.split(',')
                try:
                    service = stuff[0]
                    port_protocol_tuple = (stuff[2].lower(), int(stuff[1]))
                    if service == '' or stuff[1] == '' or stuff[2] == '':
                        continue
                    self.service_mapping[port_protocol_tuple] = service
                except IndexError:
                    continue
                except ValueError:
                    continue
            pass

    def initialize_connection(self, raw_connections, service_mapping):
        connections = []
        idx = 0

        for key, packet_list in raw_connections.items():
            connection = ConnectionRecord(packet_list, idx)
            connection.process(service_mapping)
            connections.append(connection)
            self.records.append(str(connection))
            idx += 1

        return connections

    def process_packets(self):
        service_mapping = self.get_iana()
        raw_connections = self.create_connection_records()
        connections = self.initialize_connection(raw_connections, service_mapping)

        # Process other features or derive additional features as needed

        return connections

    def save_records_to_csv(self, filename="kdd.csv"):
        with open(filename, "w+") as out:
            for record in self.records:
                out.write(record + "\n")


def main():
    if len(argv) == 1:
        cap_file = "./outside.tcpdump"
        sniffer = NetworkPacketSniffer(cap_file)
    elif len(argv) == 2:
        cap_file = argv[1]
        sniffer = NetworkPacketSniffer(cap_file)
    else:
        print("Usage: python3 kdd99_preprocessor.py <pcap-file>")
        return

    connections = sniffer.process_packets()
    sniffer.save_records_to_csv()
    print("Connection records generated, written to kdd.csv...")


if __name__ == "__main__":
    main()
