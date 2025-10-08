# Scanning-Network

Lab Tasks
Ethical hackers and pen testers use numerous tools and techniques to scan the target network. Recommended labs that will assist you in learning various network scanning techniques include:

1. Perform host discovery
 - Perform host discovery using Nmap

2. Perform port and service discovery
 - Explore various network scanning techniques using Nmap

3. Perform OS discovery
 - Perform OS discovery using Nmap Script Engine (NSE)

4. Scan beyond IDS and Firewall
 - Scan beyond IDS/firewall using various evasion techniques

5. Perform network scanning using various scanning tools
 - Scan a target network using Metasploit

# Lab 1: Perform Host Discovery
Host discovery is considered the primary task in the network scanning process. It is used to discover the active/live hosts in a network. It provides an accurate status of the systems in the network, which, in turn, reduces the time spent on scanning every port on every system in a sea of IP addresses in order to identify whether the target host is up.

The following are examples of host discovery techniques:
 - ARP ping scan
 - UDP ping scan
 - ICMP ping scan (ICMP ECHO ping, ICMP timestamp, ping ICMP, and address mask ping)
 - TCP ping scan (TCP SYN ping and TCP ACK ping)
 - IP protocol ping scan

Task 1: Perform Host Discovery using Nmap

1. Windows 11 machine is selected, click Parrot Security to switch to the Parrot Security machine
2. Open a Terminal window and execute sudo su to run the programs as a root user (When prompted, enter the password toor).
3. Run nmap -sn -PR [Target IP Address] command (here, the target IP address is 10.10.1.22).
4. The scan results appear, indicating that the target Host is up, as shown in the screenshot.
![image alt](https://github.com/asyrafzf95/Scanning-Network/blob/8d9a770eef862c9d20c4b02d6e6f8042f56fc89f/IMAGES/1.jpg)
5. Run nmap -sn -PU [Target IP Address] command, (here, the target IP address is 10.10.1.22). The scan results appear, indicating the target Host is up, as shown in the screenshot.
![image alt](https://github.com/asyrafzf95/Scanning-Network/blob/8d9a770eef862c9d20c4b02d6e6f8042f56fc89f/IMAGES/2.jpg)
6. Now, I will perform the ICMP ECHO ping scan. Run nmap -sn -PE [Target IP Address] command, (here, the target IP address is 10.10.1.22). The scan results appear, indicating that the target Host is up, as shown in the screenshot.
![image alt](https://github.com/asyrafzf95/Scanning-Network/blob/8d9a770eef862c9d20c4b02d6e6f8042f56fc89f/IMAGES/3.jpg)
7. Now, I will perform an ICMP ECHO ping sweep to discover live hosts from a range of target IP addresses. Run nmap -sn -PE [Target Range of IP Addresses] command (here, the target range of IP addresses is 10.10.1.10-23). The scan results appear, indicating the target Host is up, as shown in the screenshot.
![image alt](https://github.com/asyrafzf95/Scanning-Network/blob/8d9a770eef862c9d20c4b02d6e6f8042f56fc89f/IMAGES/4.jpg)
8. Run nmap -sn -PP [Target IP Address] command, (here, the target IP address is 10.10.1.22). The scan results appear, indicating the target Host is up, as shown in the screenshot.
![image alt](https://github.com/asyrafzf95/Scanning-Network/blob/8d9a770eef862c9d20c4b02d6e6f8042f56fc89f/IMAGES/5.jpg)

# Lab 2: Perform Port and Service Discovery
Port scanning techniques are categorized according to the type of protocol used for communication within the network.
- TCP Scanning
  - Open TCP scanning methods (TCP connect/full open scan)
  - Stealth TCP scanning methods (Half-open Scan, Inverse TCP Flag Scan, ACK flag probe scan, third party and spoofed TCP scanning methods)
- UDP Scanning
- SCTP Scanning
  - SCTP INIT Scanning
  - SCTP COOKIE/ECHO Scanning
- SSDP and List Scanning
- IPv6 Scanning

Task 1: Explore Various Network Scanning Techniques using Nmap

1. Click Windows 11 to switch to the Windows 11 machine. Click windows Search icon on the Desktop, search for zenmap in the search field and open the app.
2. The Zenmap appears; in the Command field, type nmap -sT -v [Target IP Address] (here, the target IP address is 10.10.1.22) and click Scan.
3. The scan results appear, displaying all the open TCP ports and services running on the target machine, as shown in the screenshot.
![image alt](https://github.com/asyrafzf95/Scanning-Network/blob/8d9a770eef862c9d20c4b02d6e6f8042f56fc89f/IMAGES/6.jpg)
4. Click the Ports/Hosts tab to gather more information on the scan results. Nmap displays the Port, Protocol, State, Service, and Version of the scan.
![image alt](https://github.com/asyrafzf95/Scanning-Network/blob/8d9a770eef862c9d20c4b02d6e6f8042f56fc89f/IMAGES/7.jpg)
5. Click the Topology tab to view the topology of the target network that contains the provided IP address and click the Fisheye option to view the topology clearly.
![image alt](https://github.com/asyrafzf95/Scanning-Network/blob/8d9a770eef862c9d20c4b02d6e6f8042f56fc89f/IMAGES/8.jpg)
6. In the same way, click the Host Details tab to view the details of the TCP connect scan.
![image alt](https://github.com/asyrafzf95/Scanning-Network/blob/8d9a770eef862c9d20c4b02d6e6f8042f56fc89f/IMAGES/9.jpg)
7. Click the Scans tab to view the command used to perform TCP connect/full open scan.
8. Click the Services tab located in the left pane of the window. This tab displays a list of services.
![image alt](https://github.com/asyrafzf95/Scanning-Network/blob/8d9a770eef862c9d20c4b02d6e6f8042f56fc89f/IMAGES/10.jpg)
9. In this sub-task, I be performing a stealth scan/TCP half-open scan, Xmas scan, TCP Maimon scan, and ACK flag probe scan on a firewall-enabled machine (i.e., Windows Server 2022) in order to observe the result. To do this, I need to enable Windows Firewall in the Windows Server 2022 machine. Click Windows Server 2022 to switch to the Windows Server 2022 machine.
10. Navigate to Control Panel --> System and Security --> Windows Defender Firewall --> Turn Windows Defender Firewall on or off, enable Windows Firewall and click OK, as shown in the screenshot.
![image alt](https://github.com/asyrafzf95/Scanning-Network/blob/8d9a770eef862c9d20c4b02d6e6f8042f56fc89f/IMAGES/11.jpg)
11. Now, click Windows 11 to switch to the Windows 11 machine. In the Command field of Zenmap, type nmap -sS -v [Target IP Address] (here, the target IP address is 10.10.1.22) and click Scan.
12. The scan results appear, displaying all open TCP ports and services running on the target machine, as shown in the screenshot.
![image alt](https://github.com/asyrafzf95/Scanning-Network/blob/8d9a770eef862c9d20c4b02d6e6f8042f56fc89f/IMAGES/12.jpg)
13. As shown in the last task, i can gather detailed information from the scan result in the Ports/Hosts, Topology, Host Details, and Scan tab.
14. Similarly, type nmap -sX -v [Target IP Address] (here, the target IP address is 10.10.1.22) and click Scan.
15. The scan results appear, displaying that the ports are either open or filtered on the target machine, which means a firewall has been configured on the target machine.
![image alt](https://github.com/asyrafzf95/Scanning-Network/blob/8d9a770eef862c9d20c4b02d6e6f8042f56fc89f/IMAGES/13.jpg)
16. In the Command field, type nmap -sM -v [Target IP Address] (here, the target IP address is 10.10.1.22) and click Scan. The scan results appear, displaying either the ports are open/filtered on the target machine, which means a firewall has been configured on the target machine.
![image alt](https://github.com/asyrafzf95/Scanning-Network/blob/8d9a770eef862c9d20c4b02d6e6f8042f56fc89f/IMAGES/14.jpg)
17. In the Command field, type nmap -sA -v [Target IP Address] (here, the target IP address is 10.10.1.22) and click Scan. The scan results appear, displaying that the ports are filtered on the target machine, as shown in the screenshot.
![image alt](https://github.com/asyrafzf95/Scanning-Network/blob/8d9a770eef862c9d20c4b02d6e6f8042f56fc89f/IMAGES/15.jpg)
18. Now, click Windows Server 2022 to switch to the Windows Server 2022 machine. Turn off the Windows Defender Firewall from Control Panel. Now, click Windows 11 to navigate back to the Windows 11 machine. In the Command field of Zenmap, type nmap -sU -v [Target IP Address] (here, the target IP address is 10.10.1.22) and click Scan. The scan results appear, displaying all open UDP ports and services running on the target machine, as shown in the screenshot.
![image alt](https://github.com/asyrafzf95/Scanning-Network/blob/d55f55f793f49b7e15b728fb293b24510b2be4d1/IMAGES/16.jpg)
19. In the Command field, type nmap -sV [Target IP Address] (here, the target IP address is 10.10.1.22) and click Scan. The scan results appear, displaying that open ports and the version of services running on the ports, as shown in the screenshot.
![image alt](https://github.com/asyrafzf95/Scanning-Network/blob/d55f55f793f49b7e15b728fb293b24510b2be4d1/IMAGES/17.jpg)
20. In the Command field, type nmap -A [Target Subnet] (here, target subnet is 10.10.1.* ) and click Scan. By providing the "*" (asterisk) wildcard, you can scan a whole subnet or IP range. Nmap scans the entire network and displays information for all the hosts that were scanned, along with the open ports and services, device type, details of OS, etc. as shown in the screenshot.
![image alt](https://github.com/asyrafzf95/Scanning-Network/blob/d55f55f793f49b7e15b728fb293b24510b2be4d1/IMAGES/18.jpg)
21. Choose an IP address 10.10.1.22 from the list of hosts in the left-pane and click the Host Details tab. This tab displays information such as Host Status, Addresses, Operating System, Ports used, OS Classes, etc. associated with the selected host.
![image alt](https://github.com/asyrafzf95/Scanning-Network/blob/d55f55f793f49b7e15b728fb293b24510b2be4d1/IMAGES/19.jpg)

# Lab 3: Perform OS Discovery
Banner grabbing, or OS fingerprinting, is a method used to determine the OS that is running on a remote target system.

There are two types of OS discovery or banner grabbing techniques:
- Active Banner Grabbing Specially crafted packets are sent to the remote OS, and the responses are noted, which are then compared with a database to determine the OS. Responses from different OSes vary, because of differences in the TCP/IP stack implementation.
- Passive Banner Grabbing This depends on the differential implementation of the stack and the various ways an OS responds to packets. Passive banner grabbing includes banner grabbing from error messages, sniffing the network traffic, and banner grabbing from page extensions.

Task 1: Perform OS Discovery using Nmap Script Engine (NSE)

1. Click Parrot Security to switch to the Parrot Security machine. Open a Terminal window and execute sudo su to run the programs as a root user.
2. In the terminal window, run nmap -A [Target IP Address] command (here, the target machine is Windows Server 2022 [10.10.1.22]). The scan results appear, displaying the open ports and running services along with their versions and target details such as OS, computer name, NetBIOS computer name, etc. under the Host script results section.
![image alt](https://github.com/asyrafzf95/Scanning-Network/blob/d55f55f793f49b7e15b728fb293b24510b2be4d1/IMAGES/20.jpg)
![image alt](https://github.com/asyrafzf95/Scanning-Network/blob/d55f55f793f49b7e15b728fb293b24510b2be4d1/IMAGES/21.jpg)
3. In the terminal window, run nmap -O [Target IP Address] command (here, the target machine is Windows Server 2022 [10.10.1.22]). The scan results appear, displaying information about open ports, respective services running on the open ports, and the name of the OS running on the target system.
![image alt](https://github.com/asyrafzf95/Scanning-Network/blob/d55f55f793f49b7e15b728fb293b24510b2be4d1/IMAGES/22.jpg)
![image alt](https://github.com/asyrafzf95/Scanning-Network/blob/d55f55f793f49b7e15b728fb293b24510b2be4d1/IMAGES/23.jpg)
4. In the terminal window, run nmap --script smb-os-discovery.nse [Target IP Address] command (here, the target machine is Windows Server 2022 [10.10.1.22]). The scan results appear, displaying the target OS, computer name, NetBIOS computer name, etc. details under the Host script results section.
![image alt](https://github.com/asyrafzf95/Scanning-Network/blob/d55f55f793f49b7e15b728fb293b24510b2be4d1/IMAGES/24.jpg)
![image alt](https://github.com/asyrafzf95/Scanning-Network/blob/d55f55f793f49b7e15b728fb293b24510b2be4d1/IMAGES/25.jpg)

# Lab 4: Scan beyond IDS and Firewall

An Intrusion Detection System (IDS) and firewall are the security mechanisms intended to prevent an unauthorized person from accessing a network. However, even IDSs and firewalls have some security limitations. Firewalls and IDSs intend to avoid malicious traffic (packets) from entering into a network, but certain techniques can be used to send intended packets to the target and evade IDSs/firewalls.

Techniques to evade IDS/firewall:
- Packet Fragmentation: Send fragmented probe packets to the intended target, which re-assembles it after receiving all the fragments
- Source Routing: Specifies the routing path for the malformed packet to reach the intended target
- Source Port Manipulation: Manipulate the actual source port with the common source port to evade IDS/firewall
IP Address Decoy: Generate or manually specify IP addresses of the decoys so that the IDS/firewall cannot determine the actual IP address
- IP Address Spoofing: Change source IP addresses so that the attack appears to be coming in as someone else
- Creating Custom Packets: Send custom packets to scan the intended target beyond the firewalls
- Randomizing Host Order: Scan the number of hosts in the target network in a random order to scan the intended target that is lying beyond the firewall
- Sending Bad Checksums: Send the packets with bad or bogus TCP/UDP checksums to the intended target
- Proxy Servers: Use a chain of proxy servers to hide the actual source of a scan and evade certain IDS/firewall restrictions
- Anonymizers: Use anonymizers that allow them to bypass Internet censors and evade certain IDS and firewall rules

Task 1: Scan beyond IDS/Firewall using various Evasion Techniques

1. Click Windows 11 to switch to the Windows 11 machine. Navigate to Control Panel --> System and Security --> Windows Defender Firewall --> Turn Windows Defender Firewall on or off, enable Windows Defender Firewall and click OK, as shown in the screenshot.
![image alt](https://github.com/asyrafzf95/Scanning-Network/blob/d55f55f793f49b7e15b728fb293b24510b2be4d1/IMAGES/26.jpg)
2. Minimize the Control Panel window, click windows Search icon on the Desktop. Search for wireshark in the search field and click Open to launch it.
3. The Wireshark Network Analyzer window appears, start capturing packets by double-clicking the available ethernet or interface (here, Ethernet).
4. Click Parrot Security to switch to the Parrot Security machine. Open a Terminal window and execute sudo su to run the programs as a root user.
5. Now, run cd command to jump to the root directory. In the terminal window, run nmap -f [Target IP Address] command, (here, the target machine is Windows 11 [10.10.1.11]).
6. Although Windows Defender Firewall is turned on in the target system (here, Windows 11), you can still obtain the results displaying all open TCP ports along with the name of services running on the ports, as shown in the screenshot.
![image alt](https://github.com/asyrafzf95/Scanning-Network/blob/d55f55f793f49b7e15b728fb293b24510b2be4d1/IMAGES/27.jpg)
6. Click Windows 11 to switch to the Windows 11 machine (target machine). You can observe the fragmented packets captured by the Wireshark, as shown in the screenshot.
![image alt](https://github.com/asyrafzf95/Scanning-Network/blob/d55f55f793f49b7e15b728fb293b24510b2be4d1/IMAGES/28.jpg)
7. Click Parrot Security to switch to the Parrot Security machine. In the Parrot Terminal window, run nmap -g 80 [Target IP Address] command, (here, target IP address is 10.10.1.11).
8. The results appear, displaying all open TCP ports along with the name of services running on the ports, as shown in the screenshot.
![image alt](https://github.com/asyrafzf95/Scanning-Network/blob/d55f55f793f49b7e15b728fb293b24510b2be4d1/IMAGES/29.jpg)
9. Click Windows 11 to switch to the Windows 11 machine (target machine). In the Wireshark window, scroll-down and you can observe the TCP packets indicating that the port number 80 is used to scan other ports of the target host, as shown in the screenshot.
![image alt](https://github.com/asyrafzf95/Scanning-Network/blob/d55f55f793f49b7e15b728fb293b24510b2be4d1/IMAGES/30.jpg)
10. Click Parrot Security to switch to the Parrot Security machine. Now, run nmap -mtu 8 [Target IP Address] command (here, target IP address is 10.10.1.11).
31
11. Click Windows 11 to switch to the Windows 11 machine (target machine). In the Wireshark window, scroll-down and you can observe the fragmented packets having maximum length as 8 bytes, as shown in the screenshot.
32
12. Click Parrot Security to switch to the Parrot Security machine. Now, run nmap -D RND:10 [Target IP Address] command (here, target IP address is 10.10.1.11).
33
13. Now, click Windows 11 to switch to the Windows 11 machine (target machine). In the Wireshark window, scroll-down and you can observe the packets displaying the multiple IP addresses in the source section, as shown in the screenshot.
34
14. Click Parrot Security to switch to the Parrot Security machine. In the terminal window, run nmap -sT -Pn --spoof-mac 0 [Target IP Address] command (here, target IP address is 10.10.1.11).
35
15. Click Windows 11 to switch to the Windows 11 machine (target machine). In the Wireshark window, scroll-down and you can observe the captured TCP, as shown in the screenshot.
36

# Lab 5: Perform Network Scanning using Various Scanning Tools

Task 1: Scan a Target Network using Metasploit

1. Click Parrot Security to switch to the Parrot Security machine. Open a Terminal window and execute sudo su to run the programs as a root user.
2. Execute command msfconsole to launch Metasploit.
37
3. An msf command line appears. Type nmap -Pn -sS -A -oX Test 10.10.1.0/24 and press Enter to scan the subnet, as shown in the screenshot. Nmap begins scanning the subnet and displays the results. It takes approximately 5 minutes for the scan to complete.
4. After the scan completes, Nmap displays the host information in the target network along with open ports, service and OS enumeration.
38
39
40
41
42
43
44
5. Type search portscan and press Enter. The Metasploit port scanning modules appear, as shown in the screenshot.
45
6. Here, i will use the auxiliary/scanner/portscan/syn module to perform an SYN scan on the target systems. To do so, type use auxiliary/scanner/portscan/syn and hit Enter.
7. We will use this module to perform an SYN scan against the target IP address range (10.10.1.5-23) to look for open port 80 through the eth0 interface.
To do so, issue the below commands:
- set INTERFACE eth0
- set PORTS 80
- set RHOSTS 10.10.1.5-23
- set THREADS 50
8. After specifying the above values, type run and press Enter, to initiate the scan against the target IP address range.
46
9. The result appears, displaying open port 80 in active hosts, as shown in the screenshot.
47
10. Now, i will perform a TCP scan for open ports on the target systems. To load the auxiliary/scanner/portscan/tcp module, type use auxiliary/scanner/portscan/tcp and press Enter. Run show options command to view module options.
48
11. Type set RHOSTS [Target IP Address] and press Enter.
12. Type run and press Enter to discover open TCP ports in the target system.
13. The results appear, displaying all open TCP ports in the target IP address (10.10.1.22).
49 
14. Now that i have determined the active hosts on the target network, i can further attempt to determine the OSes running on the target systems. As there are systems in our scan that have port 445 open, i will use the module scanner/smb/version to determine which version of Windows is running on a target and which Samba version is on a Linux host.
15. To do so, first type back, to revert to the msf command line. Then, type use auxiliary/scanner/smb/smb_version and hit enter.
16. I will use this module to run a SMB version scan against the target IP address range (10.10.1.5-23). To do so, issue the below commands:
- set RHOSTS 10.10.1.5-23
- set THREADS 11
17. Type run to discover SMB version in the target systems.
18. The result appears, displaying the OS details of the target hosts.
50
