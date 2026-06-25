#!/usr/bin/python3

# ======================================================================================================================
# This is a template for the project in CNSM Part I
#
#
# @author:Ludwig Karpfinger
# mailto:ludwig.karpfinger@hm.edu
#
# Please note:
# You can use this template for your project.
# This template is only a small help.
# You can implement your own idea.
#
# Python coding style:
# Use python black for formatting by running following command:
# $ black file.py
# This black command will format your python code
#
# Apart from this, please write your code very clearly and readable.
# That means:
# 1. Document at least each method/function with a block of comments: """ Block comment """
# 2. Write the authors name and the group number at the top of the document
# 3. Use keywords according to: @url https://datatracker.ietf.org/doc/html/rfc1350/
# 4. Use functions instead of very long codeblocks
# 5. Use 'speaking' variable names
# 6. Make use of global variables
# 7. Use a lot of meaningful print statements
#
# Information for advanced python users:
# scapy and virtualenv are already installed on this VM
#
# ======================================================================================================================

import socket
from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.tftp import TFTP, TFTP_ACK, TFTP_DATA, TFTP_RRQ, TFTP_WRQ
from scapy.sendrecv import send, sr
from enum import Enum
import select

SERVER_IP = "192.168.30.90"
CLIENT_IP = "192.168.40.50"
PROXY_IP_CLIENTSIDE = "192.168.40.80"
PROXY_IP_SERVERSIDE = "192.168.30.80"
TFTP_PORT = 69
BUFFERSIZE = 1024

class OPCode(Enum):
    """An Enumeration representing all possible OP-codes

    Args:
        Enum (bytes): The message type
    """

    RRQ = 1
    WRQ = 2
    DATA = 3
    ACK = 4
    ERROR = 5


class Proxy:
    """A class representing all possible operations, that can be executed on the proxy.

    Returns:
        object: returns an object of the class Proxy
    """

    def __init__(self) -> None:
        """This is the constructor for the Proxy Class"""
        print("The proxy is ready")

    def __get_sender_from_ip(self, ip) -> str:
        """Identifies the Sender

        Args:
            ip (str): The IP-address

        Returns:
            str: either Client or Server
        """
        if ip[8:] == "40.50":  # if the IP ends with 40.50
            return "Client"  # then this is the client
        elif ip[8:] == "30.90":  # if the IP ends with 30.90
            return "Server"  # then it's the server

    def get_opcode(self, packet) -> bytes:
        """A method for extracting the opcode from the data received by the socket.

        Args:
            packet (Byteobject): the raw packet data received by a socket

        Returns:
            bytes: The op-code can be: 1,2,3,4,5
        """
        return packet[1]

    def get_blocknumber(self, packet) -> int:
        """Identifies the blocknumber

        Args:
            packet (byteobject): the raw packet data received by a socket

        Returns:
            int: the blocknumber
        """
        block = int.from_bytes(
            packet[2:4], "big"
        )  # converts the blocknumber from bytes into int (bytes on index 2 and 3)
        return block

    def __get_data_packet_length(self, packet) -> int:
        """calculates the length of a data packet

        Args:
            packet (byteobject): the raw packet data received by a socket

        Returns:
            int: the length of the packet
        """
        return len(packet) - 4  # data packet header is 4 bytes long

    def __get_filename(self, packet) -> str:
        """Extract the filename as a string

        Args:
            packet (byteobject): the raw packet data received by a socket

        Returns:
            str: filename, like 'test511.txt'
        """
        startIndex = 2
        endIndex = packet.find(b"\00", startIndex)
        return packet[startIndex:endIndex].decode("ascii")

    def __get_error_message(self, packet) -> str:
        """Extract the error message from an ERROR packet

        Args:
            packet (byteobject): the raw packet data received by a socket

        Returns:
            str: error message
        """
        return packet[4 : len(packet) - 1].decode("ascii")

    def __get_mode(self, packet) -> str:
        """Extract the mode as a string

        Args:
            packet (byteobject): the raw packet data received by a socket

        Returns:
            str: mode, like 'netascii'
        """
        startIndex = packet.find(b"\00", 2) + 1
        endIndex = packet.find(b"\00", startIndex)
        return packet[startIndex:endIndex].decode("ascii")

    def __format_packet(self, packet) -> str:
        """Formats the contents of a packet for later printing to the console.

        Args:
            packet (Byteobject): the raw packet data received by a socket

        Returns:
            str: the formatted presentation of the packet as a string
        """
        opcode = self.get_opcode(packet)

        if opcode == OPCode.DATA.value:
            return "DATA packet| Block number: {block} | Length: {length} Bytes | Payload ".format(
                block=self.get_blocknumber(packet),
                length=self.__get_data_packet_length(packet),
            )
        elif opcode == OPCode.ACK.value:
            return "ACK packet | Block number: {block}".format(
                block=self.get_blocknumber(packet),
            )
        elif (opcode == OPCode.RRQ.value) or (opcode == OPCode.WRQ.value):
            filename, mode = packet[2 : len(packet) - 1].split(b"\x00")
            return "{op} packet | {filename} | 0 | {mode} | 0".format(
                op=OPCode(opcode).name,
                filename=self.__get_filename(packet),
                mode=self.__get_mode(packet),
            )
        else:  # only option left is an error packet
            return "ERROR packet | {err_code} | {err_msg} | 0".format(
                err_code=packet[3],
                err_msg=self.__get_error_message(packet),
            )

    def receive(self, socket: socket) -> tuple:
        """Receives incomming messages on the specified
        ip = address[0]
        port = address[1]

        Args:
            socket (socket): the socket, which receives the data

        Returns:
            tuple: returns a tuple of packet and sender address
        """
        packet, address = socket.recvfrom(1024)  # address is a tuple of (ip, port)
        print(
            "Recieved {format_packet} from {ip}:{port} ({host})\n".format(
                format_packet=self.__format_packet(packet),
                ip=address[0],
                port=address[1],
                host=self.__get_sender_from_ip(address[0]),
            )
        )
        return (packet, address)

    def forward(self, socket: socket, address, packet) -> None:
        """forwards a message from the specified socket to the specified address

        Args:
            socket (socket): the socket on which the packet is sent
            address (tuple): the address to which the packet is sent to
            packet (byteobject): the packet containing the data
        """
        print(
            "Forward {format_packet} to: {ip}:{port} ({host})\n".format(
                format_packet=self.__format_packet(packet),
                ip=address[0],
                port=address[1],
                host=self.__get_sender_from_ip(address[0]),
            )
        )
        socket.sendto(packet, address)


def example_for_sending_tftp_via_scapy() -> None:
    """This is an example for a crafted TFTP RRQ packet via scapy.
    You can use that as an inspiration for your own idea.

    Btw: The pylinter in vscode does sometimes not recognize scapy code.
    Do not get confused by that.
    You can circumvent that by inserting the specific path to the libary, like following:
    'from scapy.layers.tftp import TFTP' instead of 'from scapy.all import *'
    """
    packet = IP() / UDP() / TFTP() / TFTP_RRQ()
    packet[IP].dst = "192.168.30.90"
    packet[IP].src = "192.168.30.80"
    packet[UDP].sport = 69
    packet[UDP].dport = 69
    packet[TFTP].op = 1
    packet[TFTP_RRQ].filename = b"test511.txt"
    packet[TFTP_RRQ].mode = b"netascii"
    send(packet, iface="enp0s3.30")

# original file should be <=512 bytes, but we shall see what happens otherwise
def increase_data_to_513bytes(
    proxy: Proxy,
    initial_proxy_socket: socket,
    proxy_to_server_socket: socket,
    proxy_to_client_socket: socket,
) -> None:

    reset = False
    connected = False
    last_ack = -1
    last_block = -1
    server_address = (SERVER_IP, TFTP_PORT)
    receive_ack_from_client_again = False

    while True:
        if reset  and not receive_ack_from_client_again:
            changed_size = -1 # -1 means not yet, 0 means change next data packet (RRQ), 1 for WRQ, 2 means done
            server_address = (SERVER_IP, TFTP_PORT)
            reset = False
            connected = False
            last_ack = -1
            last_block = -1
            acks = 0

        if connected:
            request, client_address = proxy.receive(proxy_to_client_socket)
        else:
            print("--------------------------------------------------------------")
            print("Waiting for the request from client. Only the first packet will be increased.")
            print("--------------------------------------------------------------\n")
            request, client_address = proxy.receive(initial_proxy_socket)
            connected = True

        req_opcode = proxy.get_opcode(request)

        if req_opcode == OPCode.ACK.value:
            if proxy.get_blocknumber(request) == last_ack and not receive_ack_from_client_again:
                reset = True
            else:
                acks += 1

            if acks == 2:
                receive_ack_from_client_again = False
                acks = 0
        elif req_opcode == OPCode.RRQ.value:
            changed_size = 0
        elif req_opcode == OPCode.WRQ.value:
            changed_size = 1
        elif req_opcode == OPCode.DATA.value:
            if len(request) - 4 < 512:
                last_block = proxy.get_blocknumber(request)

            if(changed_size == 1):
                bn = proxy.get_blocknumber(request)
                data = request[4:]

                padding_needed = 550 - len(data)
                data += b" " * (padding_needed)
                # now rebuild the packet and then send to server
                request = req_opcode.to_bytes(2, "big") + bn.to_bytes(2, "big") + data
                changed_size = 2

        proxy.forward(proxy_to_server_socket, server_address, request)

        if not reset and not receive_ack_from_client_again:
            response, server_address = proxy.receive(proxy_to_server_socket)
            
            if proxy.get_opcode(response) == OPCode.DATA.value:
                if len(response) - 4 < 512:
                    last_ack = proxy.get_blocknumber(response)

                if(changed_size == 0):
                    bn = proxy.get_blocknumber(response)
                    data = response[4:]
                    opcode = proxy.get_opcode(response)

                    padding_needed = 550 - len(data)
                    data += b" " * (padding_needed)
                    response = opcode.to_bytes(2, "big") + bn.to_bytes(2, "big") + data
                    changed_size = 2
                    receive_ack_from_client_again = True
            elif proxy.get_opcode(response) == OPCode.ACK.value:
                if proxy.get_blocknumber(response) == last_block:
                    reset = True
            elif proxy.get_opcode(response) == OPCode.ERROR.value:
                reset = True

            receive_ack_from_client_again = False
            proxy.forward(proxy_to_client_socket, client_address, response)

def increase_data_over512(
    proxy: Proxy,
    initial_proxy_socket: socket,
    proxy_to_server_socket: socket,
    proxy_to_client_socket: socket,
) -> None:
    connected = False
    last_ack = -1
    last_block = -1
    server_address = (SERVER_IP, TFTP_PORT)
    client_address = None
    changed_size = -1 # -1 means not yet, 0 means change next data packet (RRQ), 1 for WRQ, 2 means done

    print("--------------------------------------------------------------")
    print("Waiting for the request from client. Only the first data packet will be changed.")
    print("--------------------------------------------------------------\n")
    
    while True:

        sockets_to_watch = [proxy_to_server_socket]
        if not connected:
            sockets_to_watch.append(initial_proxy_socket)
        else:
            sockets_to_watch.append(proxy_to_client_socket)

        readable, _, _ = select.select(sockets_to_watch, [], [])

        for sock in readable:
            
            if sock == initial_proxy_socket or sock == proxy_to_client_socket:
                request, addr = proxy.receive(sock)
                if not connected:
                    client_address = addr
                    connected = True
                
                req_opcode = proxy.get_opcode(request)
                
                if req_opcode == OPCode.ACK.value:
                    if proxy.get_blocknumber(request) == last_ack:
                        pass
                        
                elif req_opcode == OPCode.DATA.value:
                    if len(request) - 4 < 512:
                        last_block = proxy.get_blocknumber(request)

                    if changed_size == 1:
                        bn = proxy.get_blocknumber(request)
                        data = request[4:]

                        padding_needed = 550 - len(data)
                        data += b" " * (padding_needed)
                        # now rebuild the packet and then send to server
                        request = req_opcode.to_bytes(2, "big") + bn.to_bytes(2, "big") + data
                        changed_size = 2
                elif req_opcode == OPCode.RRQ.value:
                    changed_size = 0
                elif req_opcode == OPCode.WRQ.value:
                    changed_size = 1

                # Forward client packet to server
                proxy.forward(proxy_to_server_socket, server_address, request)

            # --- HANDLE SERVER TRAFFIC (Crucial for unexpected retransmissions) ---
            elif sock == proxy_to_server_socket:
                response, addr = proxy.receive(proxy_to_server_socket)
                server_address = addr  # Track dynamic ephemeral ports assigned by server
                
                res_opcode = proxy.get_opcode(response)

                if res_opcode == OPCode.DATA.value:
                    if len(response) - 4 < 512:
                        last_ack = proxy.get_blocknumber(response)

                    if changed_size == 0:
                        bn = proxy.get_blocknumber(response)
                        data = response[4:]
                        opcode = proxy.get_opcode(response)

                        padding_needed = 550 - len(data)
                        data += b" " * padding_needed
                        response = opcode.to_bytes(2, "big") + bn.to_bytes(2, "big") + data
                        changed_size = 2

                elif res_opcode == OPCode.ACK.value:
                    if proxy.get_blocknumber(response) == last_block:
                        pass

                # Forward server packet to client if we know who the client is
                if client_address:
                    proxy.forward(proxy_to_client_socket, client_address, response)

def change_bn_of_ack(
    proxy: Proxy,
    initial_proxy_socket: socket,
    proxy_to_server_socket: socket,
    proxy_to_client_socket: socket,
    behaviour_on_wrq: int
) -> None:
    reset = True  # Start as True to trigger the initial setup block
    connected = False
    last_ack = -1
    last_block = -1
    server_address = (SERVER_IP, TFTP_PORT)
    client_address = None
    modify_bn = 0

    while True:
        if reset:
            server_address = (SERVER_IP, TFTP_PORT)
            client_address = None
            reset = False
            connected = False
            last_ack = -1
            last_block = -1
            modify_bn = 0  # 0 - not yet, 1 - modify next ack, 2 - done, 3 - wait one ack, then modify

            print("--------------------------------------------------------------")
            print("Waiting for the request from client.")
            if behaviour_on_wrq == 0:
                print("On both RRQ and WRQ, the BN will be increased.")
            else:
                print("On RRQ, the BN will be increased, but on WRQ, it will be decreased.")
            print("--------------------------------------------------------------\n")

        # 1. Determine which sockets we need to watch right now
        sockets_to_watch = [proxy_to_server_socket]
        if not connected:
            sockets_to_watch.append(initial_proxy_socket)
        else:
            sockets_to_watch.append(proxy_to_client_socket)

        # 2. Wait until at least one socket receives data
        readable, _, _ = select.select(sockets_to_watch, [], [])

        for sock in readable:
            
            # --- HANDLE CLIENT TRAFFIC ---
            if sock == initial_proxy_socket or sock == proxy_to_client_socket:
                request, addr = proxy.receive(sock)
                if not connected:
                    client_address = addr
                    connected = True
                
                req_opcode = proxy.get_opcode(request)
                
                if req_opcode == OPCode.ACK.value:
                    if proxy.get_blocknumber(request) == last_ack and modify_bn == 2:
                        reset = True

                    if modify_bn == 1:
                        bn = proxy.get_blocknumber(request) + 1
                        request = req_opcode.to_bytes(2, "big") + bn.to_bytes(2, "big")
                        modify_bn = 2
                        
                elif req_opcode == OPCode.DATA.value:
                    if len(request) - 4 < 512:
                        last_block = proxy.get_blocknumber(request)
                elif req_opcode == OPCode.RRQ.value:
                    modify_bn = 1
                elif req_opcode == OPCode.WRQ.value:
                    modify_bn = 3

                # Forward client packet to server
                proxy.forward(proxy_to_server_socket, server_address, request)

            # --- HANDLE SERVER TRAFFIC (Crucial for unexpected retransmissions) ---
            elif sock == proxy_to_server_socket:
                response, addr = proxy.receive(proxy_to_server_socket)
                server_address = addr  # Track dynamic ephemeral ports assigned by server
                
                res_opcode = proxy.get_opcode(response)

                if res_opcode == OPCode.DATA.value:
                    if len(response) - 4 < 512:
                        last_ack = proxy.get_blocknumber(response)
                elif res_opcode == OPCode.ACK.value:
                    if proxy.get_blocknumber(response) == last_block:
                        reset = True
                elif res_opcode == OPCode.ERROR.value:
                    reset = True

                # Forward server packet to client if we know who the client is
                if client_address:
                    proxy.forward(proxy_to_client_socket, client_address, response)
def drop_data_and_spoof_ack(
    proxy: Proxy,
    initial_proxy_socket: socket,
    proxy_to_server_socket: socket,
    proxy_to_client_socket: socket,
) -> None:
    """Implements the 6th Optional case:
    The Proxy doesnt redirect the DATA packet to the server, instead it sends
    an ACK to the sender"""

    connected = False;
    server_address = (SERVER_IP, TFTP_PORT)
    client_address = None
    packet_dropped = False

    print("------------------------------------------------------------------------------")
    print("Wainting for the RRQ request from the client")
    print("The first DATA packet will be dropped and the server will receive a fake ACK")
    print("------------------------------------------------------------------------------")

    while True:
        sockets_to_watch = [proxy_to_server_socket]
        if not connected:
            sockets_to_watch.append(initial_proxy_socket)
        else:
            sockets_to_watch.append(proxy_to_client_socket)
        
        readable, _, _ = select.select(sockets_to_watch, [],[])

        for sock in readable:
            # traffic from client
            if sock == initial_proxy_socket or sock == proxy_to_client_socket:
                request, addr = proxy.receive(sock)
                if not connected:
                    client_address = addr
                    connected = True

                # redirect the request from the client to the server
                proxy.forward(proxy_to_server_socket, server_address, request)

            # traffic from the server
            elif sock == proxy_to_server_socket:
                response, addr = proxy.receive(proxy_to_server_socket)
                server_address = addr

                res_opcode = proxy.get_opcode(response)

                #intercepting DATA packet

                if res_opcode == OPCode.DATA.value and not packet_dropped:
                    bn = proxy.get_blocknumber(response)
                    print(f"\n[!] PROXY: DATA packet with BN={bn} from server.")
                    print("[!] Packet DROPPED")

                    fake_ack = (OPCode.ACK.value).to_bytes(2, "big") + bn.to_bytes(2, "big")
                    print(f"[!] Sending fake ACK with BN={bn} to server.\n")
                    proxy.forward(proxy_to_server_socket, server_address, fake_ack)

                    packet_dropped = True
                else:
                    if client_address:
                        proxy.forward(proxy_to_client_socket, client_address, response)
def handle_normal_transmission(
    proxy: Proxy,
    initial_proxy_socket: socket,
    proxy_to_server_socket: socket,
    proxy_to_client_socket: socket,
) -> None:
    """The normal transmission without 'faulty situations' is handled here.

    Args:
        proxy (Proxy): proxy
        initial_proxy_socket (socket): socket for incomming requests of the client to the proxy
        proxy_to_server_socket (socket): socket for forwarding messages from the client to the server
        proxy_to_client_socket (socket): socket for forwarding messages from the server to the client
    """
    reset = False  # a boolean variable used for resetting the connection
    connected = False  # a boolean variable for checking the connection status
    last_ack = -1  # a variable for saving the last received ack
    last_block = -1  # a variable for saving the last block number of a data packet
    server_address = (SERVER_IP, TFTP_PORT)

    while True:
        if reset:
            server_address = (SERVER_IP, TFTP_PORT)
            reset = False
            connected = False
            last_ack = -1
            last_block = -1

        if connected:
            request, client_address = proxy.receive(proxy_to_client_socket)
        else:
            print("--------------------------------------------------------------")
            print("Waiting for the request from client.")
            print("--------------------------------------------------------------\n")
            request, client_address = proxy.receive(initial_proxy_socket)
            connected = True

        if proxy.get_opcode(request) == OPCode.ACK.value:
            if proxy.get_blocknumber(request) == last_ack:
                reset = True
        elif proxy.get_opcode(request) == OPCode.DATA.value:
            if len(request) - 4 < 512:
                last_block = proxy.get_blocknumber(request)

        proxy.forward(proxy_to_server_socket, server_address, request)

        if not reset:
            response, server_address = proxy.receive(proxy_to_server_socket)
            if proxy.get_opcode(response) == OPCode.DATA.value:
                if len(response) - 4 < 512:
                    last_ack = proxy.get_blocknumber(response)
            elif proxy.get_opcode(response) == OPCode.ACK.value:
                if proxy.get_blocknumber(response) == last_block:
                    reset = True
            elif proxy.get_opcode(response) == OPCode.ERROR.value:
                reset = True

            proxy.forward(proxy_to_client_socket, client_address, response)


def main() -> None:
    """The main is creating a proxy instance and is calling the function
    which is responsible for the faulty situation
    """
    proxy = Proxy()
    initial_proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    initial_proxy_socket.bind((PROXY_IP_CLIENTSIDE, TFTP_PORT))
    proxy_to_server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    proxy_to_server_socket.setsockopt(
        socket.SOL_SOCKET, 25, str("enp7s0" + "\0").encode("ascii")
    )
    proxy_to_client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    num = read_user_input()
    print("Start of transmission.")
    if num == 0:
        handle_normal_transmission(
            proxy, initial_proxy_socket, proxy_to_server_socket, proxy_to_client_socket
        )
    elif num == 1:
        increase_data_over512(
            proxy, initial_proxy_socket, proxy_to_server_socket, proxy_to_client_socket
        )
    elif num == 2:
        print("Decrease BN on WRQ? (1 for yes, 0 for no)")
        resp = 2
        while(resp != 0 and resp != 1):
            resp = int(input())
            if(resp != 0 and resp != 1):
                print("Invalid input! Try again.")

        change_bn_of_ack(
            proxy, initial_proxy_socket, proxy_to_server_socket, proxy_to_client_socket, resp
        )
    elif num == 3:
        print("not implemented yet..")
    elif num == 4:
        print("not implemented yet..")
    elif num == 5:
        print("not implemented yet..")
    elif num == 6:
        drop_data_and_spoof_ack(
            proxy, initial_proxy_socket, proxy_to_server_socket, proxy_to_client_socket
        )
        print("not implemented yet..")
    elif num == 7:
        print("not implemented yet..")

    print("End of transmission. \n")


def read_user_input() -> int:
    """Reads user input from the command line

    Returns:
        int: return the userinput if it was meaningful
    """
    is_valid_input = False
    while not is_valid_input:
        print("Which faulty-situation would you like to use for the next transmission?")
        print("0: Normal transmission")
        print("1: Increase data block size over 512bytes")
        print("2: Change BN of first ACK after DATA packet")
        print("3: faulty situation 3")
        print("4: faulty situation 4")
        print("5: faulty situation 5")
        print("6: faulty situation 6")
        print("7: faulty situation 7")
        print()  # prints empty line on console

        try:
            # Asking for user input
            user_input = int(input())
        except Exception:
            print("Please enter a number. Try again.")

        if user_input == 0:
            print("Normal transmission was selected")
            is_valid_input = True
        elif user_input == 1:
            print("Situation 1 selected (increase payload size)")
            is_valid_input = True
        elif user_input == 2:
            print("Siuation 2 selected (change BN of ACK)")
            is_valid_input = True
        elif user_input == 3:
            print("faulty situation 3 was selected")
            is_valid_input = True
        elif user_input == 4:
            print("faulty situation 4 was selected")
            is_valid_input = True
        elif user_input == 5:
            print("faulty situation 5 was selected")
            is_valid_input = True
        elif user_input == 6:
            print("faulty situation 6 was selected")
            is_valid_input = True
        elif user_input == 7:
            print("faulty situation 7 was selected")
            is_valid_input = True
        else:
            print("The number does not exist. Try again.")

    return user_input


if __name__ == "__main__":
    main()
