import argparse
import os
import re
import select
import socket
import struct
import sys
import time
import packet_crafter


class Traceroute:
    def __init__(self, destination, packet_length, max_hops, timeout):
        if max_hops <= 0 or packet_length <= 0 or timeout <= 0:
            raise ValueError
        self.destination = destination
        self.packet_length = packet_length
        self.hops = max_hops + 1
        self.timeout = timeout
        self.ttl = 1
        self.packet_crafter = packet_crafter.PacketCrafter()
        self.identifier = os.getpid() & 0xffff

    def start_trace(self) -> None:
        print("Trace to: {} ({})".format(self.destination, socket.gethostbyname(self.destination)))

        while self.ttl < self.hops:
            delay, reply, ip = self.trace()
            if ip is None:
                print("{}. {}".format(str(self.ttl), "*"))
                print()
                self.ttl += 1
                continue
            ip = socket.inet_ntoa(struct.pack("!I", ip))
            print("{}. {} {} ms".format(str(self.ttl), ip, str(delay)))
            answer = self.whois_request(ip)
            pr = ""
            if answer == "local":
                print("local")
            else:
                for i in answer:
                    if i is not None:
                        pr += str(i)
                        pr += ", "
                print(pr[0:len(pr) - 2])
            print()
            self.ttl += 1
            if reply == self.packet_crafter.ICMP_ECHO_REPLY:
                break

    def trace(self) -> tuple:
        try:
            icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
            icmp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl)
        except socket.error as e:
            if e.errno == 1:
                print("Operation not permitted")
            else:
                print(e)
            sys.exit()

        send_time = self.send_icmp(icmp_socket)

        if send_time == 0:
            return None, None, None
        delay = 0
        recieve_time, icmp_reply, ip = self.parse_icmp_reply(icmp_socket)

        if recieve_time:
            delay = round((recieve_time - send_time) * 1000)

        return delay, icmp_reply, ip

    def send_icmp(self, icmp_socket) -> float:
        packet = self.packet_crafter.craft_icmp_packet(self.identifier, self.packet_length)
        send_time = time.time()

        try:
            icmp_socket.sendto(packet, (self.destination, 1))
        except socket.error as e:
            print(e)
            return 0

        return send_time

    def parse_icmp_reply(self, icmp_socket) -> tuple:
        while True:
            ready_data, _, _ = select.select([icmp_socket], [], [], self.timeout)
            receive_time = time.time()
            if not ready_data:
                return None, None, None

            packet, _ = icmp_socket.recvfrom(2048)

            type_of_reply = struct.unpack("!BBHHH", packet[20:28])[0]
            ip = struct.unpack("!BBHHHBBHII", packet[:20])[8]

            return receive_time, type_of_reply, ip

    def whois_request(self, ip: str):
        if ip == "127.0.0.1":
            return "local"

        data = self.send_and_read_data(ip, "whois.arin.net")
        if "PRIVATE-ADDRESS" and "IANA-RESERVED" in data:
            return "local"
        if re.findall(r"NetName:.+RIPE", data):
            data = self.send_and_read_data(ip, "whois.ripe.net")
            return self.parse_whois_request(data)
        elif re.findall(r"NetName:.+LACNIC", data):
            data = self.send_and_read_data(ip, "whois.lacnic.net")
            return self.parse_whois_request(data)
        elif re.findall(r"NetName:.+APNIC", data):
            data = self.send_and_read_data(ip, "whois.apnic.net")
            return self.parse_whois_request(data)
        elif re.findall(r"NetName:.+AFRINIC", data):
            data = self.send_and_read_data(ip, "whois.afrinic.net")
            return self.parse_whois_request(data)
        else:
            return self.parse_whois_request(data)

    @staticmethod
    def send_and_read_data(ip, server):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((server, 43))
            s.sendall((ip + "\r\n").encode())
            buff = b""
            while True:
                data = s.recv(1024)
                if not data:
                    break
                buff += data
        return buff.decode("utf-8", errors="ignore")

    def parse_whois_request(self, data):
        data = data.lower()
        re_for_netname = re.findall(r"netname:.+\n", data)
        re_for_as = re.findall(r"origin:.+\n", data)
        re_for_country = re.findall(r"country:.+\n", data)

        if re_for_netname:
            name = re_for_netname[0][16:len(re_for_netname[0])].split("\n")[0]
        else:
            name = None

        if re_for_country:
            country = re_for_country[0][16:len(re_for_netname[0])].split("\n")[0]
            if country == "eu":
                country = None
        else:
            country = None

        if re_for_as:
            a_system = re_for_as[0][18:len(re_for_netname[0])].split("\n")[0]
            if a_system == "":
                a_system = None

        else:
            re_for_as = re.findall(r"originas:.+.+\n", data)
            if re_for_as:
                a_system = re_for_as[0][18:len(re_for_as[0])].split("\n")[0]
                if a_system == "":
                    a_system = None
            else:
                a_system = None
        return name, a_system, country


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("destination")
    parser.add_argument("-p", dest="packet_length", type=int, default=50, required=False)
    parser.add_argument("-hops", dest="hops", type=int, default=30, required=False)
    parser.add_argument("-t", dest="timeout", type=int, default=3, required=False)
    args = parser.parse_args()
    dest = args.destination
    length = args.packet_length
    hops = args.hops
    timeout = args.timeout

    try:
        ip = socket.gethostbyname(dest)
    except Exception:
        print("{} is invalid".format(dest))
        sys.exit()
    traceroute = Traceroute(dest, length, hops, timeout)
    traceroute.start_trace()
