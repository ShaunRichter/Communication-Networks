import socket
import time
import struct

def create_packet(packet_id, src_ip, dest_ip, data_length, payload):
    src_ip_packed = socket.inet_aton(src_ip)
    dest_ip_packed = socket.inet_aton(dest_ip)
    packet = struct.pack('!I4s4sH{}s'.format(len(payload)),
                         packet_id, src_ip_packed, dest_ip_packed,
                         data_length, payload)
   
    return packet

host = "127.0.0.1"
#host = "172.17.37.183"
packetID = 1

port = 12345

client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

packetId = 0000
SERVER_ADDRESS = (host, port)

isConnectionClosed = False

client.sendto(b'INIT', SERVER_ADDRESS)
synAck = client.recvfrom(1024)[0]
if synAck == b'RETURN':
    client.sendto(b'ACK', SERVER_ADDRESS)
    time.sleep(0.1)
    with open('connectionDatabase.txt', 'r') as file:
        content = file.read()
        if(content == '1'):
            print("HANDSHAKE COMPLETE!")
        else:
            print("CORRUPT HANDSHAKE! CLOSING CONNECTION")
            isConnectionClosed = True
            client.close()
else:
    print("CORRUPT HANDSHAKE! CLOSING CONNECTION")
    isConnectionClosed = True
    client.close()

if isConnectionClosed == False:
    passwordAck = "NULL"
    numOfIterations = 0
    while(passwordAck != "ACK"):
        if(numOfIterations != 0):
            print("Incorrect Password! Please Try Again!")
        if(numOfIterations == 3):
            print("TOO MANY INCCORECT ATTEMPTS, TERMINATING CONNECTION")
            isConnectionClosed = True
            client.close()
            break
        passwordReq = input("Enter the password to the server: ")
        passWordMsg = passwordReq.encode("utf-8")
        client.sendto(passWordMsg, SERVER_ADDRESS)
        passwordAck = client.recvfrom(1024)[0].decode('utf-8')
        numOfIterations += 1
###

if isConnectionClosed == False:
    print("CORRECT PASSWORD! CONNETION TO SERVER ESTABLISHED")
    while True:
        data = input("Enter a message: ")

        sourceIP = socket.gethostbyname(socket.gethostname())
        destIP = host
        payload = bytes(data, "utf-8")
        length = len(payload)
        client.sendto(create_packet(packetID, sourceIP, destIP,length, payload), (host, port))
        packetID+=1
        if data == "CLOSE CONNECTION":
            print("DISCONNECTED FROM SERVER")
            break

client.close()






