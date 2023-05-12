import argparse
import os
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
                self.ttl += 1
                continue
            ip = socket.inet_ntoa(struct.pack("!I", ip))
            print("{}. {} {} ms".format(str(self.ttl), ip, str(delay)))
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
    except IndexError:
        raise IndexError("addr not given")
    except socket.gaierror:
        raise UnicodeError("addr not correct")
    except UnicodeError:
        print("addr not correct")
        sys.exit()
    traceroute = Traceroute(dest, length, hops, timeout)
    traceroute.start_trace()