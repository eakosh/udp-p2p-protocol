import os
import socket
import threading
import struct
import random
import queue
import time
from time import sleep

# Define the format of the header
# 8b (Flags + 1 empty bits), 16b (Seq Number), 16b (Ack Number), 16b(Total Fragments), 8b(Window Size), 16b(Checksum)
HEADER_FORMAT = "!B H H H B H"
# Define flag values
SYN_FLAG = 0b10000000
ACK_FLAG = 0b01000000
NACK_FLAG = 0b00100000
KA_FLAG = 0b00010000
FLAG_RST = 0b00001000
FIN_FLAG = 0b00000100
DATA_FLAG = 0b00000010  # DATA 0 - text, 1 - file
UDP_MAX_SIZE = 65535
MAX_FRAGMENT_SIZE = 65455

seq_local = 0
ack_local = 0
handshake = False
fragment_size = MAX_FRAGMENT_SIZE
location_set = False
save_location = ""
ack_queue = queue.Queue()  # Queue to manage incoming acknowledgments
WINDOW_SIZE = 4
TIMEOUT = 5

HEARTBEAT_INTERVAL = 5
HEARTBEAT_THRESHOLD = 3
missed_heartbeats = 0
last_activity_time = time.time()
connection_active = False
program_running = True


# Calculate CRC-16 checksum
def calculate_crc16(data):
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if (crc & 1):
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


# Functions to change the fragment size or remaining fragment size
def set_fragment_sizes():
    global fragment_size
    change_fragment_size = input("Do you want to change the fragment size? (y/n): ").lower() == 'y'
    if not change_fragment_size:
        return
    fragment_size = int(input("Enter fragment size: "))
    if fragment_size > MAX_FRAGMENT_SIZE:
        print(f"Fragment size too large. Setting to maximum size: {MAX_FRAGMENT_SIZE}")
        set_fragment_sizes()
    if fragment_size < 1:
        print(f"Fragment size too small. Setting to minimum size: 1")
        set_fragment_sizes()
    print(f"File fragment size set to: {fragment_size}")


# Function to set the save location
def set_save_location():
    global save_location, location_set
    save_location = input("Enter save location: ")
    if save_location[0] == '"':
        save_location = save_location[1:-1]
    if save_location:
        print(f"Save location set to: {save_location}")
        location_set = True


# Functions to send SYN for 3-way handshake
def send_syn(udp_socket, target_ip, target_port):
    global seq_local, ack_local
    seq_local = random.randint(0, 1000)
    header = struct.pack(HEADER_FORMAT, SYN_FLAG, seq_local, ack_local, 1, 0, 0)
    udp_socket.sendto(header, (target_ip, target_port))
    print(f"Sent SYN {seq_local}")
    seq_local += 1


# Functions to send ACK for 3-way handshake
def send_ack(udp_socket, target_ip, target_port):
    global seq_local, ack_local
    header = struct.pack(HEADER_FORMAT, ACK_FLAG, seq_local, ack_local, 1, 0, 0)
    udp_socket.sendto(header, (target_ip, target_port))
    print(f"Sent ACK {ack_local}")
    seq_local += 1


# Function to send a heartbeat message
def send_heartbeat(udp_socket, target_ip, target_port):
    global seq_local, ack_local
    header = struct.pack(HEADER_FORMAT, KA_FLAG, seq_local, ack_local, 1, 0, 0)
    udp_socket.sendto(header, (target_ip, target_port))


# Function to monitor the connection status and handle missed heartbeats
def monitor_connection(udp_socket, target_ip, target_port):
    global last_activity_time, missed_heartbeats, connection_active, program_running
    while connection_active:
        sleep(HEARTBEAT_INTERVAL)  # Wait for the heartbeat interval
        if not program_running:
            return
        with threading.Lock():
            # Check the time since the last activity
            time_since_last_activity = time.time() - last_activity_time
            if time_since_last_activity >= HEARTBEAT_INTERVAL:
                send_heartbeat(udp_socket, target_ip, target_port)
                missed_heartbeats += 1

                # If missed heartbeats exceed the threshold, consider the connection lost
                if missed_heartbeats >= HEARTBEAT_THRESHOLD:
                    connection_active = False
                    print("All heartbeats are missed\nConnection lost. Attempting to reconnect...")
                    handle_connection_failure(udp_socket, target_ip, target_port)


# Function to handle connection failure
def handle_connection_failure(udp_socket, target_ip, target_port):
    global connection_active, program_running, missed_heartbeats
    for _ in range(HEARTBEAT_THRESHOLD):
        send_heartbeat(udp_socket, target_ip, target_port)
        time.sleep(HEARTBEAT_INTERVAL)
        if connection_active:
            print("Connection restored!")
            missed_heartbeats = 0
            return
    print("Connection permanently lost. Terminating transmission.")
    # Send a reset (RST) header to terminate the connection
    header = struct.pack(HEADER_FORMAT, FLAG_RST, seq_local, ack_local, 1, 0, 0)
    udp_socket.sendto(header, (target_ip, target_port))
    udp_socket.close()
    with threading.Lock():
        program_running = False  # Stop the program


# Class to represent individual packets for ARQ
class Packet:
    def __init__(self, seq_num, data):
        self.seq_num = seq_num  # Sequence number of the packet
        self.data = data  # Data payload
        self.acked = False  # The packet is acknowledged or not


# Function to listen for incoming messages
def listen_for_messages(udp_socket):
    global seq_local, ack_local, handshake, WINDOW_SIZE, missed_heartbeats, connection_active, program_running
    received_fragments = {}  # Dictionary to store received fragments
    file_name = ""  # To store the name of the file
    start_time = time.time()
    while program_running:
        try:
            # Receive data from socket
            data, addr = udp_socket.recvfrom(UDP_MAX_SIZE)
            if data:
                header = data[:10]
                content = data[10:]
                # Unpack the header based on the defined format
                flags, seq, ack, total_fragments, window_size, checksum = struct.unpack(HEADER_FORMAT, header)

                # Step 2 in handshake: respond with SYN-ACK
                if flags == SYN_FLAG:
                    print(f"\nStep 2:")
                    print(f"Received SYN {seq}")
                    seq_local = random.randint(0, 1000)
                    ack_local = seq + 1
                    header = struct.pack(HEADER_FORMAT, SYN_FLAG | ACK_FLAG, seq_local, ack_local, 1, 0, 0)
                    udp_socket.sendto(header, addr)
                    print(f"Sent my SEQ {seq_local}, my ACK {ack_local}\n")
                    seq_local += 1
                # Step 3 in handshake: respond with ACK
                elif flags == (SYN_FLAG | ACK_FLAG):
                    if ack == seq_local:
                        print(f"\nStep 3:")
                        print(f"Received SYN {seq} ACK {ack}")
                        ack_local = seq + 1
                        send_ack(udp_socket, addr[0], addr[1])
                        handshake = True
                        connection_active = True
                    else:
                        # If acknowledgment doesn't match, reinitiate SYN
                        print(f"Invalid SYN {seq} ACK {ack}")
                        send_syn(udp_socket, addr[0], addr[1])
                # Handle acknowledgment
                elif flags == ACK_FLAG:
                    if not handshake:
                        handshake = True
                    connection_active = True
                    ack_queue.put(Packet(ack, flags))  # Add to acknowledgment queue
                # Handle negative acknowledgment
                elif flags == NACK_FLAG:
                    ack_queue.put(Packet(ack, flags))  # Add to acknowledgment queue
                # Handle heartbeat
                elif flags == KA_FLAG:
                    header = struct.pack(HEADER_FORMAT, ACK_FLAG | KA_FLAG, seq_local, ack_local, 1, 0, 0)
                    udp_socket.sendto(header, addr)  # Send acknowledgment for heartbeat
                # Reset missed heartbeat count
                elif flags == (ACK_FLAG | KA_FLAG):
                    with threading.Lock():
                        missed_heartbeats = 0
                # Handle termination request
                elif flags == FIN_FLAG:
                    print(f"Connection closed by {addr}")
                    header = struct.pack(HEADER_FORMAT, (ACK_FLAG | FIN_FLAG), seq_local, ack_local, 1, 0, 0)
                    udp_socket.sendto(header, addr)  # Send acknowledgment for termination
                    # Stop the program
                    udp_socket.close()
                    with threading.Lock():
                        program_running = False
                # Handle acknowledgment for termination
                elif flags == (ACK_FLAG | FIN_FLAG):
                    print(f"Received ACK for FIN from {addr}. Closing connection...")
                    # Stop the program
                    udp_socket.close()
                    with threading.Lock():
                        program_running = False
                # Handle reset request
                elif flags == FLAG_RST:
                    print(f"Connection closed due to reset by {addr}")
                    # Stop the program
                    udp_socket.close()
                    with threading.Lock():
                        program_running = False
                # Handle incoming data packets
                elif flags == DATA_FLAG:
                    expected_checksum = calculate_crc16(header[:-2] + content)
                    # Handle checksum errors
                    if checksum != expected_checksum:
                        print(f"Checksum error on fragment {seq}. Expected {expected_checksum}, got {checksum}.")
                        ack_local = seq + 1
                        nack_header = struct.pack(HEADER_FORMAT, NACK_FLAG, seq_local, ack_local, total_fragments, 0, 0)
                        udp_socket.sendto(nack_header, addr)  # Send negative acknowledgment
                        print(f"Sent NACK for fragment {seq}")
                        continue
                    # Only add new fragments based on unique sequence numbers
                    if seq not in received_fragments:
                        if len(received_fragments) == 0:  # If it's the first fragment, parse file name
                            file_name_length = struct.unpack('!H', content[:2])[0]
                            file_name = content[2:2 + file_name_length].decode()
                            received_fragments[seq] = content[2 + file_name_length:]  # Store fragment data
                            start_time = time.time()  # Record start time
                            print()
                        else:
                            received_fragments[seq] = content  # Store fragment data
                        ack_local = seq + 1
                        ack_header = struct.pack(HEADER_FORMAT, ACK_FLAG, seq_local, ack_local, total_fragments, 0, 0)
                        udp_socket.sendto(ack_header, addr)  # Send acknowledgment for the fragment
                        print(f"Received fragment {seq} ({len(received_fragments)}/{total_fragments}) without mistakes")
                        print(f"Sent ACK for fragment {seq}")

                    if len(received_fragments) == total_fragments:
                        if save_location:
                            file_name = os.path.join(save_location, file_name)
                        # Write fragments in order
                        with open(file_name, 'wb') as f:
                            for i in sorted(received_fragments.keys()):
                                f.write(received_fragments[i])

                        print(f"File saved as {file_name}")
                        print(f"Total Size: {os.path.getsize(file_name)} bytes")
                        print(f"Time taken to receive the file: {time.time() - start_time:.2f} seconds")
                        # Clear fragments after saving
                        received_fragments.clear()
                        print("\nEnter   'm' to send message\n\t'f' to send file\n\t's' to set save location"
                              "\n\t'e' to end the connection: ")
                else:
                    expected_checksum = calculate_crc16(header[:-2] + content)
                    # Handle checksum errors
                    if checksum != expected_checksum:
                        print(f"Checksum error on fragment {seq}. Expected {expected_checksum}, got {checksum}.")
                        ack_local = seq + 1
                        nack_header = struct.pack(HEADER_FORMAT, NACK_FLAG, seq_local, ack_local, total_fragments, 0, 0)
                        udp_socket.sendto(nack_header, addr)
                        print(f"Sent NACK for fragment {seq}")  # Send negative acknowledgment
                        continue
                    # Only add new fragments based on unique sequence numbers
                    if seq not in received_fragments:
                        received_fragments[seq] = content  # Store the fragment data
                        ack_local = seq + 1
                        ack_header = struct.pack(HEADER_FORMAT, ACK_FLAG, seq_local, ack_local, total_fragments, 0, 0)
                        udp_socket.sendto(ack_header, addr)  # Send acknowledgment for the fragment
                        if len(received_fragments) == 1:
                            print()
                        print(f"Sent ACK for fragment {seq}")

                    # Check if all fragments have been received
                    if len(received_fragments) == total_fragments:
                        print(f"\nReceived message from {addr}:")
                        # Write each fragment in order
                        for i in sorted(received_fragments.keys()):
                            print(f"{received_fragments[i].decode()}", end="")
                        print("\n")
                        # Clear after all fragments are processed
                        received_fragments.clear()
                        print("\nEnter   'm' to send message\n\t'f' to send file\n\t's' to set save location"
                              "\n\t'e' to end the connection: ")
        except Exception:
            print(end="")


# Function to send a file
def send_file(udp_socket, target_ip, target_port, file_path):
    global seq_local, ack_local, fragment_size
    # Check if the file exists
    if not os.path.exists(file_path):
        print("File not found")
        return

    mistake = input("Do you want to introduce a mistake in the file? (y/n): ").lower() == 'y'
    mistake_index = 0
    # Record start time
    start_time = time.time()
    set_fragment_sizes()
    file_name = os.path.basename(file_path)
    file_size = os.path.getsize(file_path) + len(file_name) + 16
    # Calculate the number of fragments required
    total_fragments = (file_size + fragment_size - 1) // fragment_size
    if total_fragments >= 2 ** 16:
        print("Fragment size too small for the file")
        fragment_size = MAX_FRAGMENT_SIZE
        return

    # If a mistake is requested, choose the fragment to make the mistake
    if mistake:
        mistake_index = random.randint(0, total_fragments - 1)
        print(f"Mistake introduced at index {mistake_index}")

    print(f"Sending file '{file_name}' of size {file_size} bytes in {total_fragments} fragments.")
    print(
        f"Fragment for esch fragment: {fragment_size} bytes, for the last fragment: {file_size % fragment_size} bytes")

    # Initialize packets
    packets = []
    with open(file_path, 'rb') as file:
        for i in range(total_fragments):
            if i == 0:  # First fragment includes file name
                fragment = struct.pack('!H', len(file_name)) + file_name.encode()
                fragment += file.read(fragment_size - len(fragment))
            else:
                fragment = file.read(fragment_size)
            checksum = calculate_crc16(
                struct.pack(HEADER_FORMAT[:-2], DATA_FLAG, seq_local, ack_local, total_fragments, WINDOW_SIZE) + fragment
            )
            header = struct.pack(HEADER_FORMAT, DATA_FLAG, seq_local, ack_local, total_fragments, WINDOW_SIZE, checksum)
            packets.append(Packet(seq_local, header + fragment))
            seq_local = (seq_local + 1) % (2 ** 16)

    base = 0  # Oldest unacknowledged packet
    next_seq = 0  # Next packet to send

    while base < total_fragments:
        # Send packets within the window
        while next_seq < base + WINDOW_SIZE and next_seq < total_fragments:
            if not packets[next_seq].acked:
                sleep(0.05)
                # Introduce mistake if requested
                if mistake and next_seq == mistake_index:
                    flags, seq, ack, total_fragments, window_size, checksum = struct.unpack(HEADER_FORMAT,
                                                                                            packets[next_seq].data[:10])
                    checksum_mistake = checksum ^ 0xFFFF  # Change the checksum
                    mistake_header = struct.pack(HEADER_FORMAT, flags, seq, ack, total_fragments, window_size,
                                                 checksum_mistake)
                    mistake_data = mistake_header + packets[next_seq].data[10:]
                    udp_socket.sendto(mistake_data, (target_ip, target_port))
                else:
                    udp_socket.sendto(packets[next_seq].data, (target_ip, target_port))
                print(f"Sent fragment {packets[next_seq].seq_num} ({next_seq + 1}/{total_fragments})")
            next_seq += 1

        # Wait for ACK or timeout
        try:
            p_ack = ack_queue.get(timeout=TIMEOUT)
            ack, flags = p_ack.seq_num, p_ack.data
            ack_index = ack - packets[0].seq_num - 1
            # Handle ACK
            if flags == ACK_FLAG:
                if 0 <= ack_index < total_fragments and not packets[ack_index].acked:
                    packets[ack_index].acked = True
                    print(f"Received ACK for fragment {packets[ack_index].seq_num}")
                    # Slide the window
                    while base < total_fragments and packets[base].acked:
                        base += 1
            # Handle NACK
            elif flags == NACK_FLAG:
                print(f"Received NACK for fragment {packets[ack_index].seq_num}. Resending...")
                udp_socket.sendto(packets[ack_index].data, (target_ip, target_port))
        except queue.Empty:
            # Timeout: Resend all unacknowledged packets in the window
            print("Timeout! Resending unacknowledged packets...")
            for i in range(base, min(base + WINDOW_SIZE, total_fragments)):
                if not packets[i].acked:
                    sleep(0.05)
                    udp_socket.sendto(packets[i].data, (target_ip, target_port))
                    print(f"Resent fragment {packets[i].seq_num} ({i + 1}/{total_fragments})")

    print(f"File '{file_path}' successfully sent.")
    print(f"Time taken to send the file: {time.time() - start_time:.2f} seconds")
    fragment_size = MAX_FRAGMENT_SIZE


def send_text(udp_socket, target_ip, target_port):
    global seq_local, ack_local, fragment_size
    start_time = time.time()
    set_fragment_sizes()
    message = input("Enter message to send: ")
    message_bytes = message.encode()
    message_length = len(message_bytes)

    total_fragments = (message_length + fragment_size - 1) // fragment_size
    # Initialize packets with data
    packets = []
    for fragment_number in range(total_fragments):
        start_index = fragment_number * fragment_size
        end_index = min(start_index + fragment_size, message_length)
        fragment = message_bytes[start_index:end_index]
        checksum = calculate_crc16(struct.pack(HEADER_FORMAT[:-2], 0, seq_local, ack_local, total_fragments,
                                               WINDOW_SIZE) + fragment)

        header = struct.pack(HEADER_FORMAT, 0, seq_local, ack_local, total_fragments, WINDOW_SIZE, checksum)
        packets.append(Packet(seq_local, header + fragment))
        seq_local = (seq_local + 1) % (2 ** 16)

    base = 0  # Oldest unacknowledged packet
    next_seq = 0  # Next packet to send

    while base < total_fragments:
        # Send packets within the window
        while next_seq < base + WINDOW_SIZE and next_seq < total_fragments:
            if not packets[next_seq].acked:
                sleep(0.05)
                udp_socket.sendto(packets[next_seq].data, (target_ip, target_port))
                print(f"Sent fragment {packets[next_seq].seq_num} ({next_seq + 1}/{total_fragments})")
            next_seq += 1

        # Wait for ACK or timeout
        try:
            p_ack = ack_queue.get(timeout=TIMEOUT)
            ack, flags = p_ack.seq_num, p_ack.data
            # Handle ACK
            if flags == ACK_FLAG:
                ack_index = ack - packets[0].seq_num - 1
                if 0 <= ack_index < total_fragments and not packets[ack_index].acked:
                    packets[ack_index].acked = True
                    print(f"Received ACK for fragment {packets[ack_index].seq_num}")
                    # Slide the window
                    while base < total_fragments and packets[base].acked:
                        base += 1
            # Handle NACK
            elif flags == NACK_FLAG:
                print(f"Received NACK for fragment {packets[ack_index].seq_num}. Resending...")
                udp_socket.sendto(packets[ack_index].data, (target_ip, target_port))
        except queue.Empty:
            # Timeout: Resend all unacknowledged packets in the window
            print("Timeout! Resending unacknowledged packets...")
            for i in range(base, min(base + WINDOW_SIZE, total_fragments)):
                if not packets[i].acked:
                    sleep(0.05)
                    udp_socket.sendto(packets[i].data, (target_ip, target_port))
                    print(f"Resent fragment {packets[i].seq_num} ({i + 1}/{total_fragments})")

    print(f"Time taken to send the message: {time.time() - start_time:.2f} seconds")
    print(f"Sent message to {target_ip}:{target_port}")
    fragment_size = MAX_FRAGMENT_SIZE


def send(udp_socket, target_ip, target_port):
    global seq_local, ack_local, program_running
    while program_running:
        choice = input("\nEnter   'm' to send message\n\t'f' to send file\n\t's' to set save location"
                       "\n\t'e' to end the connection: ")
        if not program_running:
            print("Connection closed")
        elif choice.lower() == 'm':  # Option to send a message
            send_text(udp_socket, target_ip, target_port)
        elif choice.lower() == 'f':  # Option to send a file
            if not location_set:
                print("Please set the save location before sending a file")
                set_save_location()
            file_path = input("Enter file path: ")
            if file_path[0] == '"':
                file_path = file_path[1:-1]
            if file_path:
                send_file(udp_socket, target_ip, target_port, file_path)
        elif choice.lower() == 's':  # Option to set save location
            set_save_location()
        elif choice.lower() == 'e':  # Option to end the connection
            print("Closing connection...")
            header = struct.pack(HEADER_FORMAT, FIN_FLAG, seq_local, ack_local, 1, 0, 0)
            udp_socket.sendto(header, (target_ip, target_port))  # Send termination request
            seq_local += 1
            sleep(3)
        else:
            print("Invalid choice")


# Function to start the connection
def start_connection():
    global seq_local, ack_local, handshake
    # Input IP and port information
    local_ip = input("Enter local IP: ")
    local_port = int(input("Enter local port: "))
    target_ip = input("Enter target IP: ")
    target_port = int(input("Enter target port: "))

    # Create a UDP socket
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind((local_ip, local_port))
    threading.Thread(target=listen_for_messages, args=(udp_socket,), daemon=True).start()

    # Initiate the connection handshake by sending a SYN
    send_syn(udp_socket, target_ip, target_port)
    sleep(3)

    # Wait for the handshake to be completed
    while not handshake:
        sleep(3)
        print("Waiting for handshake to be completed...")

    # Start a thread to monitor the connection
    threading.Thread(target=monitor_connection, args=(udp_socket, target_ip, target_port), daemon=True).start()
    # Launch the main sending interface
    send(udp_socket, target_ip, target_port)


# Main
if __name__ == "__main__":
    start_connection()
