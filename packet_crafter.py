import struct
import socket
import sys


class PacketCrafter:
    ICMP_ECHO = 8
    ICMP_ECHO_REPLY = 0

    def craft_icmp_packet(self, identifier: int, packet_length: int) -> bytes:

        header = struct.pack("!BBHHH", self.ICMP_ECHO, 0, 0, identifier, 1)
        payload = []
        for i in range(0, packet_length):
            payload.append(i & 0xff)

        data = bytes(payload)
        packet = header + data
        icmp_checksum = self.checksum(packet)
        header = struct.pack("!BBHHH", self.ICMP_ECHO, 0, icmp_checksum, identifier, 1)
        return header + data

    def checksum(self, packet: bytes) -> int:

        count_to = (len(packet) // 2) * 2
        count = 0
        my_sum = 0

        while count < count_to:
            if sys.byteorder == "little":
                low_byte = packet[count]
                high_byte = packet[count + 1]
            else:
                low_byte = packet[count + 1]
                high_byte = packet[count]

            my_sum += high_byte * 256 + low_byte
            count += 2

        if count != len(packet):
            my_sum += packet[-1]

        checksum = (my_sum >> 16) + (my_sum & 0xffff)
        checksum += checksum >> 16
        return socket.htons(~checksum & 0xffff)
