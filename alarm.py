#!/usr/bin/python3

from scapy.all import *
from scapy.layers.http import *
import base64
import argparse

incident_counter = 0
credential_storage = {}

def alert(incident, src_ip, protocol_port, payload=""):
    global incident_counter
    incident_counter += 1
    alert = f"ALERT #{incident_counter}: {incident} is detected from {src_ip} ({protocol_port}) ({payload})!"
    print(alert)

def make_conn_key(client_ip, server_ip, client_port, server_port, protocol):
    return (client_ip, server_ip, int(client_port), int(server_port), protocol)

def store_pending_credential(client_ip, server_ip, client_port, server_port, protocol, username, password):
    key = make_conn_key(client_ip, server_ip, client_port, server_port, protocol)
    credential_storage[key] = {
        'username': username,
        'password': password,
        'timestamp': time.time(),
        'validated': False
    }

def packetcallback(packet):
    try:
        # Check if packet has TCP and IP layers
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return

        src_ip = packet[IP].src

        # NULL scan:
        if packet[TCP].flags == 0x000:
            protocol_port = "TCP"
            alert("NULL scan", src_ip, protocol_port)

        # FIN scan:
        if packet[TCP].flags == 0x001:
            protocol_port = "TCP"
            alert("FIN scan", src_ip, protocol_port)

        #XMAS scan: flags == 29
        if packet[TCP].flags == 0x029:
            protocol_port = "TCP"
            alert("XMAS scan", src_ip, protocol_port)

        #SMB scan: destination port == 139 or 445
        if packet[TCP].dport == 139 or packet[TCP].dport == 445:
            protocol_port = packet[TCP].dport
            alert("SMB scan", src_ip, protocol_port)

        #RDP scan: destination port == 3389
        if packet[TCP].dport == 3389:
            protocol_port = packet[TCP].dport
            alert("RDP scan", src_ip, protocol_port)

        #VNC scan: destination port == 5900
        if packet[TCP].dport == 5900:
            protocol_port = packet[TCP].dport
            alert("VNC scan", src_ip, protocol_port)

       # HTTP stuff (Nikto and HTTP Basic Authentication)
        if packet.haslayer(HTTPRequest) and packet[TCP].dport == 80:
            protocol_port = 'HTTP'

             # Nikto scan: User-Agent contains Nikto (only works for utf-8 encrypted payloads)
            useragent = packet[HTTPRequest].User_Agent
            if useragent:
                if "Nikto" in useragent.decode(errors="ignore"):
                    alert("Nikto scan", src_ip, protocol_port)

            # HTTP username:password
            auth = packet[HTTPRequest].Authorization
     
            if auth:
                auth_list = auth.decode(errors="ignore").split()
                encoded_cred = auth_list[1]
                cred = base64.b64decode(encoded_cred).decode(errors="ignore").split(':')
                username = cred[0]
                password = cred[1]
                payload = f"username:{username}, password:{password}"
                alert("Usernames and passwords sent in-the-clear", src_ip, protocol_port, payload)

                # Store creds for later verification
                client_ip = packet[IP].src
                server_ip = packet[IP].dst
                client_port = packet[TCP].sport
                server_port = packet[TCP].dport
                store_pending_credential(client_ip, server_ip, client_port, server_port, 'HTTP', username, password)


        # verify HTTP creds
        if packet.haslayer(HTTPResponse) and packet[TCP].sport == 80:
            code = packet[HTTPResponse].Status_Code.decode(errors="ignore")
        
            client_ip = packet[IP].dst
            server_ip = packet[IP].src
            client_port = packet[TCP].dport
            server_port = packet[TCP].sport

            key = make_conn_key(client_ip, server_ip, client_port, server_port, 'HTTP')
            cred = credential_storage.get(key)

            if cred and not cred['validated']:
                username = cred['username']
                password = cred['password']
                payload = f"username:{username}, password:{password}"

                if code == '200':
                    alert("Valid credentials used", client_ip, "HTTP", payload)
                    cred['validated'] = True



        # FTP username and password
        if packet[TCP].dport == 21 or packet[TCP].sport == 21:
            if packet.haslayer(Raw):
                raw_payload = packet[Raw].load.decode(errors="ignore")
                username = None
                password = None

                # check if credentials are valid
                m = re.search(r'(?m)^\s*(\d{3})', raw_payload)
                if m:
                    code = int(m.group(1))
                    if code == 230:
                        client_ip = packet[IP].src
                        server_ip = packet[IP].dst
                        client_port = packet[TCP].sport
                        server_port = packet[TCP].dport
                        key = make_conn_key(server_ip, client_ip, server_port, client_port, 'FTP')
                        cred = credential_storage.get(key)
                        if cred and not cred['validated']:
                            username = cred['username']
                            password = cred['password']
                            payload = f"username:{username}, password:{password}"
                            alert("Valid credentials used", client_ip, "IMAP", payload)

               

                # parse raw payload by line
                lines = raw_payload.splitlines()
                for line in lines:
                    if line.upper().startswith("USER"):
                        try:
                            username = line.split()[1]
                        except Exception:
                            username = ''
                        client_ip = packet[IP].src
                        server_ip = packet[IP].dst
                        client_port = packet[TCP].sport
                        server_port = packet[TCP].dport
                        credential_storage[make_conn_key(client_ip, server_ip, client_port, server_port, 'FTP')] = {
                            'username': username, 'password': None, 'timestamp': time.time(), 'validated': False
                        }
                    if line.upper().startswith("PASS"):
                        try:
                            password = line.split()[1]
                        except Exception:
                            password = ''
                        client_ip = packet[IP].src
                        server_ip = packet[IP].dst
                        client_port = packet[TCP].sport
                        server_port = packet[TCP].dport
                        key = make_conn_key(client_ip, server_ip, client_port, server_port, 'FTP')
                        credentials = credential_storage.get(key)
                        if credentials and credentials.get('username') is not None:
                            username = credentials['username']
                            payload = f"username:{username}, password:{password}"
                            protocol_port = "FTP"
                            alert("Usernames and passwords sent in-the-clear", src_ip, protocol_port, payload)
                            credential_storage[key]['password'] = password
                

        # IMAP username and password
        if packet[TCP].dport == 143:
            if packet.haslayer(Raw):
                raw_payload = packet[Raw].load.decode(errors="ignore")

                lines = raw_payload.splitlines()
                for line in lines:
                    line = line.split()
                    if len(line) == 4:
                        if line[1] == "LOGIN":
                            username = line[2]
                            password = line[3]
                            payload = f"username:{username}, password:{password}"
                            protocol_port = "IMAP"
                            alert("Usernames and passwords sent in-the-clear", src_ip, protocol_port, payload)

                            # Store creds for later verification
                            client_ip = packet[IP].src
                            server_ip = packet[IP].dst
                            client_port = packet[TCP].sport
                            server_port = packet[TCP].dport
                            store_pending_credential(client_ip, server_ip, client_port, server_port, 'IMAP', username, password)

                        # check if creds are valid
                        elif (part.upper() == "OK" for part in line):
                            client_ip = packet[IP].src
                            server_ip = packet[IP].dst
                            client_port = packet[TCP].sport
                            server_port = packet[TCP].dport
                            key = make_conn_key(client_ip, server_ip, client_port, server_port, 'IMAP')
                            cred = credential_storage.get(key)
                            if cred and not cred['validated']:
                                username = cred['username']
                                password = cred['password']
                                payload = f"username:{username}, password:{password}"
                                alert("Valid credentials used", client_ip, "IMAP", payload)
                                cred['validated'] = True


    except Exception as e:
        # Uncomment the below and comment out `pass` for debugging, find error(s)
        print(e)
        #pass



# DO NOT MODIFY THE CODE BELOW
parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except:
    print("Sorry, can\'t read network traffic. Are you root?")