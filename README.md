Analyzes live network traffic or reads from a set of PCAP files.
Requires scapy

Detects:
  -NULL scan
  -FIN scan
  -Xmas scan
  -HTTP Basic Authentication (cleartext) — reports username/password and validity
  -FTP credentials in cleartext — reports username/password and validity
  -IMAP credentials in cleartext — reports username/password and validity
  -Nikto web scanner activity
  -SMB scanning activity
  -RDP scanning activity
  -VNC scanning activity
When credentials are captured it will be indicated whether those credentials appear valid or invalid.

Read from set of PCAP files:
python3 alarm.py -r <PCAP file name>

Read from Network Traffic:
sudo python3 alarm.py -i <Network Interface>





