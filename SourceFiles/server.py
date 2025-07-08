import socket
import struct


def parse_packet(packed_data):
    unpacked_data = struct.unpack('!I4s4sH{}s'.format(len(packed_data) - 14), packed_data)
    # packet_id, src_ip_packed, dest_ip_packed, checksum, data_length, payload = unpacked_data
    packet_id, src_ip_packed, dest_ip_packed, data_length, payload = unpacked_data
   
    src_ip = socket.inet_ntoa(src_ip_packed)
    dest_ip = socket.inet_ntoa(dest_ip_packed)

    packet_dict = {
        'packet_id': packet_id,
        'src_ip': src_ip,
        'dest_ip': dest_ip,
        # 'checksum': format(checksum, "016b"),
        'data_length': data_length,
        'payload': payload.decode()
    }

    return packet_dict

host = "127.0.0.1"
#host = "127.20.10.6"
port = 12345
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind((host, port))

isConnectionClosed = False
### Handshaking Method
syn_packet, address = server.recvfrom(1024)
if syn_packet == b'INIT':
    server.sendto(b'RETURN', address)
    ack_packet = server.recvfrom(1024)[0]
    if ack_packet == b'ACK':
        with open('connectionDatabase.txt', 'w') as file:
            file.write('1')
        print("HANDSHAKE COMPLETE!")
else:
    print("CORRUPT HANDSHAKE! CLOSING CONNECTION")
    isConnectionClosed = True
    server.close()
###

### Password Authentication
if isConnectionClosed == False:
    with open('passwordDatabase.txt', 'r') as file:
        password = file.read()

    passWordGet = "NULL"
    numOfAttemptsIncorrect = 0

    while(passWordGet != password):
        passWordGet = (server.recvfrom(1024)[0]).decode('utf-8')
        if(passWordGet != password):
            if(numOfAttemptsIncorrect == 2):
                print("TOO MANY INCORRECT ATTEMPTS! TERMINATING CONNETION")
                isConnectionClosed = True
                server.sendto('NULL'.encode('utf-8'), address)
                server.close()
                break
            numOfAttemptsIncorrect += 1
            server.sendto('NULL'.encode('utf-8'), address)
    if isConnectionClosed == False:
        server.sendto("ACK".encode('utf-8'), address)
###

with open('dataDatabase.txt', 'w'):
    pass

if (isConnectionClosed == False):
    print("CONNECTED SUCCESFULLY")
    while True:
        message, address = server.recvfrom(1024)
        totalPacket = parse_packet(message)
        packetID = totalPacket['packet_id'] #4bytes
        sourceIP = totalPacket['src_ip'] #4bytes
        destIP = totalPacket['dest_ip'] #4bytes
        length = totalPacket['data_length'] #2bytes
        payload = totalPacket['payload'] #1010

        if(packetID < 0 or packetID > 4294967295):
            print("NOT FOLLOWING PROTOCOL")
            continue
        elif(len(sourceIP) < 4 or len(sourceIP) > 15):
            print("NOT FOLLOWING PROTOCOL")
            continue
        elif(len(destIP) < 4 or len(destIP) > 15):
            print("NOT FOLLOWING PROTOCOL")
            continue
        elif(length < 0 or length > 1010):
            print("NOT FOLLOWING PROTOCOL")
            continue
        elif(len(payload) < 0 or len(payload) > 1010):
            print("NOT FOLLOWING PROTOCOL")
            continue



        if payload == "CLOSE CONNECTION":
            print("CLIENT DISCONNECTED")
            break

        with open('dataDatabase.txt', 'a') as file:
            file.write("Packet ID: " + str(packetID) + "   Source IP: " + str(sourceIP) + "   Dest IP: " 
                       + str(destIP) + "   Packet Length: " + str(length) + "   Message: " + payload + 
                       "\n")

server.close()


