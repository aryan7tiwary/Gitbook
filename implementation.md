# Implementation

### Secure Protocols

1. **SRTP:** Secure Real-Time Transfer Protocol (voice & video comm.)
   * Uses AES to encrypt voice and video flow.
   * Features Authentication, integrity and replay protection. (HMAC-SHA1 - hash based authentication)
   * Range starting from 5004 to 5300 (commonly even number) (UDP)
2. **NTPsec:** Secure Network Time Protocol (Time sync)
   * NTP was vulnerable to amplification attacks (DDoS)
   * 123 (UDP)
3. **S/MIME:** Secure/Multipurpose Internet Mail Extension (Email)
   * Public key encryption and digital signing of mail content.
   * Authentication, integrity, and non-repudiation.
   * Secure **POP** and Secure **IMAP**
     * Uses **STARTTLS** extension to encrypt **POP3** with **SSL** or **IMAP** with **SSL**.
   * SSL/TLS if mail is browser based. (SSL is must)
   * 3369, 3370, 3850 and 3851
4. **HTTPS:** HTTP over TLS / HTTP over SSL / HTTP Secure
   * SSL/TLS: Secure Sockets Layer/Transport Layer Security
   * Private key on the server.
   * Symmetric session key is transfered using Asymmetric encryption. (ECDHE)
   * Secure and speed.
   * 443
5. **IPSec:** Internet Protocol Security
   * Security for OSI Layer 3
   * Auth. and encryption for every packet. Integrity/anti-replay, confidentiality.
   * Core IPSec protocol: Authentication Header (AH) and Encapsulation Security Payload (ESP).
6. **File Transfer:**
   * **FTPS:** FTP over SSL (FTP-SSL). 990 or sometimes 21
   * **SFTP:** SSH FTP. dir listing, remote file removal, resuming intrurrupted transfers. 22
7. **LDAP:** Lightweight Directory Access Control
   * Protocol for reading and writing directories over IP on network.
   * Organized set of records, like phone directory.
   * LDAP is used to query and update an **X.500** directory.
   * **LDAPS:** non-standard implementation of LDAP over SSL.
   * **SASL:** A framework. Simple Authentication and Security Layer. Provides authentication using methods like kerberos or client certificate.
   * LDAP: 389 TCP/UDP.
8. **SSH:** Secure Shell (remote access)
   * Encrypted terminal communication.
   * Replaces Telnet and FTP.
9. **DNSSEC:** Domain Name System Security Extensions.
   * Data integrity, origin authentication.
   * Public key cryptography. Signed with trusted third party.
   * 53
10. **Routing and Switching:**
    * SSH
    * **SNMPv3:** Simple Network Management Protocol v3
    * versions < v3 is vulnerable.
    * Feature: CIA
    * HTTPS: browser based management.
    * 161 (UDP)
11. **Network Address Allocation:**
    * **DHCP:** Dynamic Host Configuration Protocol.
    * There is no secure version of DHCP.
    * DHCP can be made secure by :-
      * Rouge DHCP can be mitigated by setting rules that only authorized DHCP server can join network. Distribution should only be allowed from trusted DHCP sever.
      * Starvation Attack is use of spoofed MAC to exhaust DHCP pool. Mitigation by disabling an interface if seen using multiple MAC.
    * 67 (UDP)
12. **Subscription services:**
    * Autmated subscription for malicious IP database, firewall updates, IPS updates.
    * The data should be encrypted and integrity checked.
    * Check for certificates.

### Endpoint Protection

1. **AVs and Anti-Malware:**
   * Both are integrated in one software.
   * AV refers to types of malware: Trojan, worms, etc.
   * Anti-malware refers to broad malicious software category: ransomware, fileless malware, spyware, etc.
2. **Endpoint Detection and Response (EDR)**
   * Scalable to meet increasing number of threats.
   * Detect threat using - signatures, behvioral analysis, ML, process monitoring.
   * Lightweight agent on the endpoint.
   * Can repsond to threat by removing, quarantining, rolling back verions.
   * API driven, non technical.
   * Investigate the threat by root cause analysis.
3. **Data Loss Prevention (DLP)**
   * Stops leakage of data like, SSN, CC number; medical records.
   * Sits at endpoints. Cloud-based systems.
   * Can work with Email, cloud storage, collaborations tools.
4. **Next-generation-firewall (NGFW)**
   * The OSI Application Layer - All data in every packets regardless of IP or ports in use.
   * Also known as - Application layer gateway, Stateful multi-layer inspection, deep packet inspection.
   * 1\. Can allow individual features of applications. 2. Identify attacks and malware. 3. Can examine encrypted data by decrypting, examining and again encrypting.
   * Can prevent access to malicious URLs.
5. **Host-based Firewalls:**
   * Softwares, personal, runs on every endpoint.
   * Can allow inbound/outbound traffic.
   * Have access to view all data.
   * Identify and block malware before it can start.
   * Can be managed centrally.
6. **Finding intrusions:**
   1. Host-based Intrusion Detection System (HIDS)
      * Uses log files to identify intrusions.
      * Can reconfigure firewall to block.
   2. Host-based Intrusion Prevention System (HIPS)
      * Recognize and block known attacks.
      * Secure OS and application configs, validate incoming traffic.
      * Often integrated with endpoint protection software.
      * Detects a threat by - signatures, heuristics (AI), behavioral.
      * access to all non-encrypted data.

### Boot Integrity

1. **Hardware root of trust:**
   * Occurs in Trusted Platform Module (TPM), Hardware Security Module (HSM). It gives signal if system is safe or not by verifying hardwares - hard disk, RAM, etc.
   * Difficult to change or avoid as they are hardware, can be only physicaly changesd, but not by running scripts or malicious code.
2. **Trusted Platform Module (TPM):**
   * Hardware to help with cryptographic functions.
   * It generated random numbers and keys. Has persistant memory for storying keys. Password protected. Brute-force proof. Provides hardware security.
3. **Chain of Trust:**
   * Attcker want persistence with victim's machine. The boot process is infectious. Rootkits run on kernel have same permissions of an OS.
   * A chain of trust is important to verify if the system can be trusted before booting. Chain of Trust: 1. Secure Boot 2. Trusted Boot 3. Measured Boot.
4. **UEFI BIOS Secure Boot:**
   * Secure boot is a part of UEFI specification. Provides software security.
   * _1._ Stores manufacturer's public key to verify if released updates are authentic. _2._ Digital Signature is checked during BIOS update to mitigate fake/malicious update provided by attacker. _3._ Prevents unacuthorized writes to the flash. _4._ Secures bootloader by checking digital signatures and trusted certificates.
5. **Trusted Boot:**
   * Now since the bootloader has been verified by the BIOS, bootloaded will verify the authenticity of the OS kernel. Corrupted kernel will stop the boot process.
   * Then, kernel will verify boot drives and startup files.
   * Then, the OS will check every driver's authenticity by checking digital signatures.
6. **Measured Boot:**
   * This is where we manually check if any changes have been occured to OS. If there are multiple systems then it would be diffucult, scripts would do.
   * UEFI stores a hash of firmware, boot driver and everything else that is involved during Secure boot and Trusted boot. The hash is stored in TPM
   * Then, every hash gathered is sent to Attestation Server as a report digitally signed with keys of TPM. Attestation Server compares the hash in report with trusted hash. This is called Remote Attestation.
   * System administrator then can choose to stop boot if any warnings are raised by Attestation server.

### Database Security

* Protecting stored data and data in-transit. To complaiance issue with _PCI DSS_, _HIPPA_, _GDPR_, etc.

1. **Tokenization:**
   * To replace sentitive data with non-sensitive placeholder (tokens) which has nothing to do with original data.
   * Used in CC transactions as tokens are disposed after one time use, mitigating eavsdropping.
   * This is not encrypting, hashing or any mathematical relation.
2. **Hashing a password:**
   * Hashed password cannot be reversed. No different password can result same hash. This is a common way of storing password. Even if attacker has access to DB he can only see hash and not know the passwords.
3. **Adding some salt:**
   * Random data added to password before generating hash mitigates rainbow table attacks.
   * Can be manually brute-forced but salts slow down the process.

### Application Security

1. **Input Validation:**
   * Accepting correct input or correcting input --> normalization
   * Fuzzers can find improper input validation. (CLI or GUI softwares)
2. **Dynamic Analysis (fuzzing):**
   * Sending random data to input in an application to check for application crash, server error, exception, etc.
   * Starts with basic fuzzing payload to be quick and effective.
   * Fuzzing engines/frameworks: CERT Basic Fuzzing Framework (BFF).
3. **Secure Cookie:**
   * Information stored in browser for tracking activities, personalization, session management.
   * Cookie having secure attributes can force browser to send cookies via HTTPS only.
   * Sensitive data should not be stored in cookie.
4. **HTTP Secure Header:**
   * Scripts, images, stylesheets should only be allowed from the web server to prevent XSS.
   * Data should be prevented from loading into inline frame (iFrame) to mitigate XSS.
5. **Code Signing:**
   * Scripts and applications need to be authenticated. What if code/application has been tampered or not from legit developer.
   * Code/application is digitaly signed by developer by: --> Asymmetric encryption. --> Developer's public key signed by trusted CA. --> Signed with private key of developer. --> For internal use, personal CA can be used.
6. **Allow/Deny list:**
   * Allow list --> nothing runs unless approved. (very restrictive)
   * Deny list --> everything runs except things on 'deny list'.
   * Allow/Deny list can have application hash, certificate, local path, network zones or by the decision of OS.
7. **Static Code Analyzer:**
   * Static Application Security Testing (SAST) helps in identifying security flaw.
   * Many common vulns can be found like BOF, SQLi, etc.
   * Some vulns cannot be found with SAST like crypto vulns, auth sec. Therefore cannot fully rely on SAST.
   * Have to verify result due to false positive errors.

### Application Hardening

* Minimizing attack surface by removing possible entry points.
* Some hardining complaince --> HIPPA server, PCI DSS, etc.

1. **Open port services:**
   * Every port is an entry point, close ports that are not required.
   * NGFW can be used to limit application data flow from specific IP:PORT
   * Unused or unknown services can open ports that are often installed with OS or other softwares.
   * Monitoring open ports is important, can be done with nmap.
2. **Registry:**
   * Configuration database of windows. Everyting can be configured.
   * 3rd party software allows monitoring changes to regedit.
3. **Disk Encryption:**
   * Full Disk Encryption (FDE): Encrypt everyting on drive - BitLocker, etc.
   * Self-Encrypting Drive (SED): --> Hardware-based full disk encryption. --> No OS is required. --> Opal storage specification is a standard. Make sure SED follows the standard.
4. **OS Hardening:**
   * There are many OS => Android, Win, Linux, etc.
   * Updates are rolled out often. Security updates/security packs can be installed one at a time.
   * Setting up account password policies and network access.
   * Monitoring and securing with AV, Anti-Malware.
5. **Patch Management:**
   * Important for system stability, security fix.
   * Some organization roll out updates/patches monthly (incremental).
   * Auto-update is not always best option.
   * Involves emerency out-of-band updates like zero-days and security discovers.
6. **Sandboxing:**
   * Restricting applications from accessing other data.
   * Used in deployment and production techniques.
   * Used in => VMs, Mobile Devices, Browser iFrame, Windows User Account Control (UAC).

### Load Balancer

* Distribute the load between multiple servers. Covers falt tolerence.

1. **Features:** --> Configurable load. --> TCP offload --> SSL offload (encryption/decryption) --> Caching for fast response --> Prioritization --> Content switching for specific need balancing.
2. **Scheduling:**
   * Round Robin: Each server seleted in a turn.
   * Weighted Round Robin: Prioritize the server use.
   * Dynamic Round Robin: Monitor load and distribute to server with lowest load.
   * Active/Active: Every server is active.
3. **Affinity:**
   * Each client is struck with same server. Tracked by IP or session ID.
   * Active/Passive: when a server fails, another server in stand-by is switched on to balance load.

### Network Segmentation

* Segment physically, logically or virtually. To increase performance. To enforce sec by separating. Due to complaince like PCI DSS.

1. **Physical Segmentation:**
   * Devices are separated physically => air gap.
2. **Logical Segementation with VLANs:**
   * Separated logically instead of physically.
   * Logic --> devices cannot communicate without Layer 3 device: router.
3. **Screened subnet (DMZ):**
   * Previously known as Demilitarized Zone (DMZ).
   * Public access to public resources only.
4. **Extranet:** A private network for vendors, suppliers. On internet. Require auth.
5. **Intranet:** Private network - available only internally. Access by employees only with VPN or if internally.
6. **East-West Traffic:**
   * Traffic flow within same data center. Fast in response. Involves users connect internally.
7. **North-South Traffic:**
   * Traffic from outside devices. A different security posture than EW Traffic.
8. **Zero Trust:**
   * Many networks are open, once you are inside there are less security.
   * Zero trust is an approach to net sec to cover every device, process and person.
   * Everything must be verified, nothing can be trusted. MFA, encryption, system permissions, additional firewalls, monitoring, analysis, etc.

### Virtual Private Network (VPN)

* Encrypted data traversing a public network. (travelling across)

1. **Concentrator:** Encrypting/decrypting data. Often integrated with firewall. Can be hardware or a software. Sometimes built into OS.
2. **SSL VPN:** Uses common SSL/TLS protocol (443). No big VPN clients required. Works with browser.
3. **Remote Access VPN:** Software on client connects to a VPN concentrator.
4. **Site-to-Site VPN:** Traffic is encrypted by corporate network's VPN concentrator and decrypted by remote network's VPN concentrator (on the other side of tunnel). The process can be reversed.
5. **Full VPN Tunnel:** Traffic created by remote user is sent in a secure tunnel created by VPN concentrator (residing in user's OS) to corporate network where VPN concentrator decrypts it. This process is reversed when traffic is sent from corp net to remote user.
6. **Split VPN Tunnel:** Traffic to corporate network is encrypted, to all other sites, it is not encrypted. Rest of the working is same as Full VPN Tunnel.
7. **Layer 2 Tunneling Protocol (L2TP):**
   * Connecting sites over Layer 3 network as they were connected at Layer 2.
   * Commonly implemented with IPsec. L2TP for tunnel, IPsec for encryption.
8. **IPsec (Internet Protocol Security):**
   * Sec for OSI Layer 3.
   * Offers confidentiality and integrity/anti-replay. Encrypts and signs packets.
   * **Transport vs Tunnel mode:** => Transport: Only payload is encrypted, IP header are in plaintext. => Tunnel: IP header and payload both are encrypted. New IP header is signed and transfered to VPN concentrator which further moves the traffic.
   * Two Cores of IPsec: AH and ESP.
   * **Authentication Header (AH):** --> Adds hash to packet header which offers data integrity. (SHA-2) --> Does not encrypt the data. Prevents replay attacks.
   * **Encapsulation Security Payload (ESP):** --> Encrypts and authenticates data. Provides data integrity. --> Commonly SHA-2 for hash and AES for encryption. --> Combined with AH for integrity and auth.
9. **HTML5 VPNs:**
   * Includes cryptography API.
   * Does not need to install VPN client, in-built in HTML5 based browsers.

### Port Security

* Limiting or controlling traffic. Watching for unusual or unwanted traffic.

1. **Broadcast:**
   * Send info to everyone at once in broadcast domain.
   * Used by routing updates, ARP requests.
   * Sometimes malicious software or a bad NIC might be there in broadcasting.
   * Mitigation: IPv6 which has multicast rather than broadcast.
2. **Broadcast Storm Control:**
   * Using switch to control broadcast. Limit broadcast/sec.
   * Can be managed with specific values or %age.
3. **Loop Protection:**
   * There is not counting mechanism in MAC layer so a loop in network can cause a packet to traffic back and forth forever.
   * This can cause a network down.
   * IEEE standards 802.1D to prevent loops in bridged (switched) network.
   * Spanning Tree Protocol: network designed in a way which prevents loop and also offers redundancy.
4. **BPDU Guards (Bridge Protocol Data Unit):**
   * Spanning tree protocol takes time to determine which port to forward.
   * BPDU bypass listening and learning stage, so it is fast.
5. **DHCP Snooping:**
   * IP tracking on a layer 2 device (switch).
   * Switch is a firewall for DHCP. It filters invalid IP and DHCP servers. Also monitors invalid traffic patterns.
6. **MAC Filtering:**
   * Media Access Control, for hardware.
   * Limits access by filtering hardware address (MAC).
   * MAC address can be spoofed, therefore it is security through obscurity (obscurity: things that are unclear or difficult to understand).

### Secure Network

1. **Domain Name Resolution (DNS):**
   * DNSSEC is security extension of DNS.
   * Validate DNS response by origin auth and data integrity.
   * DNS records are signed with a trusted 3rd party and these records are then pulished to DNS.
2. **Using a DNS for security:**
   * Stop end users from visiting dangerous sites by DNS sinkhole.
   * As user hits malicous malware, admins can be alerted and stop further exploitation. Content filtering.
3. **Out-of-band management:**
   * Sometimes when network isn't available, a separate device with management interface, commonly serial connection or USB is used by devices like devices like firewall, etc.
   * This is then connected to router/ comm server.
4. **The need of QoS:**
   * Some protocol is more prior than other. Therefore, that individual protocol is given more importance even if server is overloaded.
   * For example: VoIP is more prior than HTTP request.
5. **IPv6 security is different (not better/bad):**
   * More IP address space. Difficult to scan IP/Port.
   * Does not require NAT.
   * Mitigates ARP spoofing.
   * New attack like Neighbor Cache Exhaustion.
   * IPsec is built-in.
6. **Taps and port mirror:**
   * Intercepts network traffic. Sends a copy to packet capture device.
   * Physical taps: Disconnect a link, put a tap in the middle. Can be active or passive tap.
   * Port mirror: Port redirection, SPAN (Switched Port ANalyzer)
     * Software-based tap.
7. **Monitoring services:**
   * Constant cybersecurity monitoring. Ongoing security checks.
   * A staff of cybersec experts at Security Operation Center(SoC)
   * Identify threats in a broad range. Faster response.
   * Useful to maintain complaince: PCI DSS, HIPPA, etc.
8. **File Integrity Monitoring (FIM):**
   * Some files should ==never== change like boot file.
   * It monitors important OS and application files.
   * Windows: `sfc` (System File Checker)
   * Linux: Tripwire
   * Many HIPS have this as feature.

### Firewalls

* The universal security control for home, office, OS. Can control content to flow or not. Protects against malware and virus.

1. **Network-based firewalls:**
   * Filter traffic by port number or application.
   * Encrypt traffic - VPN between sites.
   * Can work as layer 3 router. Feature includes translation (NAT) functionality. Authenticate dynamic routing comm.
2. **Stateless firewall:**
   * Does not keep track of traffic flow. Therefore, every packets are examined irrespective if history.
   * Attacker can send malicious data in response to a web request from user and a stateless firewall would allow it, since the rule is defined to pass response from web server.
3. **Stateful firewall:**
   * It remembers when a user query web request and add a rule in state/session table as a response from web sever will be expected.
   * In case, attacker send malicious data in response, the flow will be different for which there will be no session. So, it will be blocked.
4. **Next-generation firewall (NGFW):**
   * All data in every layer can be monitored.
   * Every packet is analyzed and categorized before a security decision is determined.
   * Have IPS integrated with it. Can perform content filtering.
5. **Web Application Firewall (WAF):**
   * Applies rules specific for HTTP/HTTPS requests.
   * Allow/deny on the basis of expected input.
   * Defends against SQLi. Major focus on PCI DSS.
6. **UTL/ All-in-one security applicance:**
   * Unified Threat Management.
   * Contains all of the features: Web sec gateway, URL filtering/Content inspection, Malware inspection, spam filter, router & switch, Firewall, IDS/IPS, bandwidth sharper, VPN endpoints.
7. **Firewall rules:**
   * Access Control List: Allows/disallows traffic based on tuples. Group in categories - Source IP, Destination IP, port, time of delay, app, etc. --> Follows logical path, usually top to bottom. --> Includes deny in the bottom so if none in list allowed the data it will be blocked.
8. **Firewall Characteristics:**
   * Open-source vs proprietary: Open-source provides traditional firewall func. Proprietary features application control and high-speed hardware.
   * Hardware vs Software: Purpose built hardware are fast and efficient, and have flexible connectivity option. Software based can be intalled almost everywhere.
   * Applicance vs host-based vs virtual: Applicance provides fastest throughput. Host-based are application awareand can view all unencrypted data. Virtual firewalls provide valuable East/West network security.

### Network Access Control

1. **Edge vs access control:**
   * Control at edge: Managed through firewall, rules are rarely changed.
   * Access control: Access based on rules that can be changed from inside/outside. Access can easily be revoked or changed.
2. **Posture Assessment:**
   * You can't trust everyone's devices. In BYOD (Bring Your Own Device) model, some device might have malware or software that you don't need in your network.
   * BYOD are checked before connecting to org's network, a health check.
3. **Health check/posture assessment:**
   * A persistent agent is installed in BYOD which is constantly updated and monitored in case the device gets compromised.
   * Dissolvable agents can be used where no installation is required. Only runs during posture assessment and can be terminated i
   * Agentless NAC is integrated with AD and checks are being made when logging in/off. Cannot be scheduled.

### Proxies

* Sits between user and external network. It receives the user requests and send the request on their behalf to webservers.
* Features URL filtering, content scanning
* Proxy server may be in network and application needs to be configured to pass request through it. Or proxy server may exist and users have no idea about it and no additional config. is required (transparent proxy).
* Can cache data for fast response.

1. **Application proxies:**
   * A network level proxy, simplest 'proxies' is NAT.
   * Most proxies in use are application proxies. A proxy may know only one application. Many proxies are multipurpose proxies.
2. **Forward Proxy:** An internal proxy commonly used to protect monitor user access to internet from inside of org network.
3. **Reverse Proxy:** Examines inbound traffic from internet to internal network/services.
4. **Open Proxy:**
   * A 3rd party proxy, uncontrolled.
   * Can be significant securiy concern. Response can be modified by open proxy before reaching to the user.

### Intrusion Prevention:

**NIDS and NIPS:** - Network Intrusion Detection/Prevention System. - Watch network traffic.

1. **Intrustions:** Exploits against OS, app, etc. BOF, SQLi, XSS, etc.
2. Detection: Alarm/alert. Prevention: Stop b4 it gets in net.
3. **Passive monitoring:**
   * A copy is sent to NIDS by port mirroring (SPAN).
   * Unable to block (prevent) traffic, but only alert.
4. **Out-of-band-response:**
   * When malicious traffic is identified, IPS sends TCP RST (reset) frames which prevents any more data from exchanging in flow. Initial malware gets into system tho.
   * Limited UDP response available.
5. **Inline monitoring:** IDS/IPS is physically in-line. All traffic is passed though it.
6. **In-band response:** Packets can be droppen at the IPS if sus, thus does not enter network.
7. **Identification Technologies:**
   * Signature Based: check for exact sign.
   * Anomaly-based: build a baseline of what is normal.
   * Behavior-based: observe and report.
   * Heuristic-based: using AI.

### Other Network Appliance

1. **Hardware Security Module:**
   * High-end cryptographic hardware. Can be plug-in or separate hardware module.
   * Backup key - secure storage.
   * Have CPU in them specific for crypto-work which takes off some load from other devices.
   * Used in large envoirnment with cluster and redundant power.
2. **Jump server:**
   * Used to access secure servers. This is highly secured device, it's compromise is a significant breach.
   * External client can use SSH, RDP, or just "jump" to jump server.
3. **Sensors and collectors:**
   * Built-in sensor, a separate device which aggregates info from network devices. Integrated with firewall, switches, routers, servers, etc.
   * _Sensors_ sense IPS, firewall logs, web server logs, DB transaction logs, email logs, etc. Sensores provides these info to collectors.
   * _Collectors_ uses console, collects data from sensors and represent them on the screen. SIEMs includes a correlation engine to compare diverse sensor data.

### Wireless Cryptography

1. **Securing wireless network:**
   * Authenticate user before granting access.
   * Ensure all comm is confidential by encrypting traffic flow.
   * Integrity should be maintained. A message integrity check (MIC).
2. **WPA2 and CCMP:**
   * CCMP: Counter Mode (CTR) with Cipher Block Chaining (CBC) Message Authentication Code (MAC) Protocol, or Counter/CBC-MAC Protocol.
   * CCMP provides data confidentiality with AES and Message Integrity Check (MIC) with CBC-MAC.
3. **WPA3 and GCMP:**
   * GCMP: Galois/Counter Mode Protocol. Stronger encryption than WPA2.
   * Data confidentiality with AES.
   * Message Integrity Check (MIC) with Galois Message Authentication Code (GMAC).
4. **The WPA2 PSK problem:**
   * PSK: Pre-shared key, a password used by eveyone to connect.
   * WPA2 has PSK brute-force problem. Some methods can derive PSK hash without handshake. Hash can be brute-forced to find PSK (pre-shared key).
   * With increase in GPU power with time, and cloud-based pass cracking, it has been easier to crack PSK hash.
   * Does not features PFS (perfect forward secrecy).
5. **Simultaneous Authentication of Equals (SAE):**
   * WPA3 changes the PSK authentication process. It includes mutual authentication. Creates session key without sending across the net.
   * No more handshakes, no hash, no brute-force. Features PFS.
   * SAE: Deffie-Hellman derived key exchange with an authentication component. Everyone uses different session key, even with same PSK.
   * An IEEE standard - dragonfly handshake.

### Wireless Authentication Methods

* Shared pass: Pre-shared Key (PSK) eveyone uses same PSK.
* Centralized Authentication: 802.1X

1. **Wireless Security Modes:**
   * Open System: No pass required.
   * WPA3-Personal/PSK: Everyone uses the same pass. Unique session is derived from PSK using SAE.
   * WPA3-Enterprise/WPA-802.1X: Authenticates used individually with an auth server.
2. **Captive Portal:** Redirects web request to captive portal page.
   * User/Pass and additional factors required for authentication factors.
   * Once authentication is succesful, the web session continues until captive portal remove access.
3. **Using Wi-Fi Protected Setup (WPS):**
   * A passphrase can be ocmplicated for novice. **Different ways to connect:** => PIN configured in access point. => Push a button on WPS. => NFC - bringing mobile device closer to AP.
4. **WPS is unsecure:**
   * PIN is 8 digit number. WPS validate each half, first 4 digit then last 3 digit. Which leads to 10000 + 1000 = 11000 possibilities.
   * Can consider brute-force lockout function - most of them does not know this!

### Wireless Authentication Protocols

1. **Extension Authentication Protocol (EAP):**
   * An authentication framework. Many different ways to authenticate using RFC standards. Manufacturers can build their own EAP method.
   * Prevents access to the network until authentication succeds.
2. **IEEE 802.1X:**
   * Port-based network acces control (NAC). Prevents used from access until auth succeds.
   * Used with databases like: RADIUS, LDAP, TACACS+.
3. **IEEE 802.1X and EAP:**
   * Three components: supplicant (client), Authenticator (router), and Authentication Server (AS).
   * If a new device need access, authenticator will pass the request to AS, the AS will ask for supplicant's credentials through autheticator. Authenticator will then pass credentials to AS, then AS will tell authenticator to allow/deny access. Supplicant ---> Authenticator ---> Authentication Server
4. **EAP-FAST:**
   * EAP Flexible Authentication via Secure Tunneling.
   * Supplicant and AS mutually authenticates and negotiates a TLS.
   * Need a RADUIS server.
5. **PEAP:**
   * Protected Extensible Authentication Protocol.
   * Built by Cisco, MS, and RSA security.
   * Encapsulates EAP in TLS. AS uses digital signatures.
   * User can also authenticate with GTC. Generic token card, hardware token generator.
   * User authenticates with Microsoft's MS-CHAPv2 databases.
6. **EAP-TLS:**
   * EAP Tranport Layer Security. Strong security.
   * Requires digital cetificate on all devices. TLS is built-in for user authentication process.
   * It has relatively complex implementation. It requires public key infrastructure (PKI). Devices must deploy and manage certificates, but all older devices cannot support use of digital certificates.
7. **EAP-TTLS:**
   * EAP Tunneled Transport Layer Security. Support other authentication protocols in a TLS tunnel.
   * Requires digital certificate on AS.
   * Can use any authentication method inside TLS tunnel.
8. **RADUIS Fedetation:**
   * Use RADUIS with Federation.
   * Member of one organization can authenticate to the network of other organization.
   * Use 802.1X as authentication method.
   * Driven by eduroam (education roaming). Educators can use thier normal authentication when in different campus.

### Installing Wireless Network

1. **Site Surveys:**
   * Mapping, identifying existing AP. Generating heat maps to identify wireless signal strengths
2. **Wireless Packet Analysis:**
   * Packet capture in wireless network is easy, just listen and not send data in return. Some network drivers does not listen some packets.
3. **Channel Selection and overlaps:**
   * Frequency conflicts, do not overlap channels for two AP. Need to be manually configured.
4. **AP Placement:**
   * Minimal overlap, max coverage with min AP.
   * Avoid interference such as Electronic devices, building material.
5. **Wireless Infrastructure Security:**
   * Wireless controllers to manage APs centrally.
   * Controll access to management console.
   * Using strong HTTP encryption and logout user for inactivity.
   * Using strong password and update to latest firmware.

### Mobile Networks

1. **Point-to-Point:**
   * One-to-One connection, conversation b/w two devices. Ex: Wi-Fi extender.
2. **Point-to-multipoint:**
   * Most popular comm method: 802.11,
   * Does not fully imply connectivity, two devices in network may not be allowed to comm.
3. **Cellular Network:**
   * Antenna coverages a cell with certain frequencies.
   * Sec concerns: traffic monitoring, location tracking, worldwide access to mobile devices.
4. **Wi-Fi:**
   * Local network access having local sec problems.
   * Encrypt data to prevent data capture.
   * On path attacks, DoS by frequency inteference.
5. **Bluetooth:**
   * High speed communication in short range.
   * Connects mobile devices: electronic gadgets, tethering.
6. **RFID (Radio Frequency Identification):**
   * Access badges, used in inventory, tracking anything.
   * Very small.
   * Radar tech, radio energy transmitted to tag. RF powers the tag.
   * Bi-directional comm.
   * Some tags can be active/powered.
7. **NFC (Near Field Communication):**
   * Two-way wireless comm, builds on RFID.
   * Payment systems.
   * Short range with encryption support, can be used as ID or access token.
   * Sec concers: Remote capture (data), frequency jamming, Relay/replay attack, loss of RFC device control.
8. **IR (Infrared):**
   * Included on many mobile device, tabs, smartwatches.
   * Control entertainment center (IR exclusive).
   * File transfers are possible
   * Sec concern: Highly sec concern, other devices can control your device.
9. **USB (Universal Serial Bus):**
   * Physical connectivity to mobile device.
   * USB to comp. Physical access is always a concern.
   * Locked device is relatively sec (screen lock)
10. **GPS (Global Positioning System):**
    * Created by US DoD. Over 30 satellites curently in orbut.
    * Determine location based on time differences - Longiture, Latitude, Altitude.
    * Mobile device location services and geotracking is based on GPS.
    * Uses: maps, directions.

### Mobile Device Management (MDM)

* Manages company owned and personal phones. It is central management of mobile devices.
* It can set policies on apps, data, camera, etc. Maintain entire partion storage of device.
* Manage access control: force users to add screen lock.

1. **Application Management:**
   * Applications are often installed/updated in mobile devices, therefore requires continuous monitoring.
   * Not all application is secure there administrator creates an allow list (whitelist) for secure applications only through MDM.
   * Newly added/updated applications are checked.
2. **Content Management:**
   * Mobile Content Management (MCM). Secure access to data and protects from outsiders.
   * Restrict or allow file transfers from certain vendors only - cloud or on-site.
   * DLP prevents c/p of sensitive data. Everything is managed by MDM.
3. **Remote Wipe:**
   * Remove all data from the device even if geolocation is unknown.
   * Managed by MDM, remote wipe needs to be configured and planed.
   * Backup of the mobile device is necessary.
4. **Geolocation:**
   * Precise tracking device - tracks within feet.
   * Can find phone. Devices have option to disable it.
   * May be managed by MDM.
5. **Geofencing:**
   * Restricts/allows features when device is in particular area.
   * Ex: camera can work only outside office, authenticate/login if in particular area.
6. **Screen Locks:**
   * All mobile devices can be locked to protect data with Personal Identification Number (PIN) or aplhanumeric.
   * Too many fail attemps can be planned to remote wipe device.
   * Lockout policies can be planned. Completely lock device, then can only be unloacked by administrator.
7. **Push Notification:**
   * Info appears on mobile screen even if user is using completely different device.
   * Push notification can be managed by MDM. It can even be pushed by MDM.
8. **Passwords and PINs:**
   * Password reset can be through help desk, or individually (by answering password reset questions).
   * Mobile device can use MFA.
   * Data can be recovered and completely removed (company's data) by MDM.
9. **Biometrics:**
   * May not be fully secure. Some enviornment favor biometric auth.
   * Availablity is managed by MDM.
   * Biometric can be per app. Some apps require additional biometric authentication.
10. **Context-aware authentication:**
    * Combining multiple contexts.
    * Where you normally login (IP, Geolocation), Other devices paired - Bluetooth (headphone, smartwatch, wifi)
11. **Containerization:**
    * Virtual container for company data. Contained area for company data.
    * Storage segmentation keeps data separate.
    * Offboarding is easy, only company info is removed.
12. **Full device encryption:**
    * Even if mobile is lost, data is safe.
    * Uses a lot of CPU cycle, complex integration b/w hardware and software.
    * Loss of password leads to inevitable loss of data.

### Mobile Device Security

1. **MicroSD HSM:**
   * Not a microSD storage card, stores encryption key, digital signatures, key generation, authentication.
   * Protect private keys and cryptocurrency storage.
2. **Unified Endpoint Management (UEM):**
   * Evolution of MDM, manages mobile and non-mobile devices.
   * Applications can be used across laptop and mobiles.
3. **Mobile Application Management (MAM):**
   * Provision, update and remove apps.
   * Keeps applications running at correct version. Maintain an allow list of applications.
   * Can remotely wipe application data and manage remote data.
4. **SEAndroid:**
   * Security Enhancements for Android. SELinux in Android OS.
   * Suports access control security policies.
   * Protects privileged Android system daemons, and malicious activity.
   * Change Discretionary Access Control (DAC) to Mandatory Access Control (MAC). Move user-assigned control to object labels and minimum user access.
   * Isolates and sandboxes android applications.
   * Centralized management policy.

### Mobile Device Enforcement

1. **Rooting/Jailbreaking:**
   * Mobile devices are purpose build, cannot access with OS.
   * Gaining access to OS in Android - Rooting, iOS - Jailbreaking.
   * Custom firmware is installed, replaces existing OS.
   * After gaining access to OS MDM becomes relatively useless.
2. **Carrier unlocking:**
   * Most phone are locked to a carrier. Carrier lock is illegal in some country. Legal in India by uncommon.
   * Can be unlocked if carrier allows.
   * Moving to another carrier can circumvent MDM, preventing SIM unlock may not be possible on personal phones.
3. **Firmware OTA:**
   * Updates are provided On-The-Air (OTA). No cable required.
   * MDM can manage what OTA is allowed.
4. **Camera use:**
   * Camera can be controlled by MDM.
   * Enable except for certain locations (geo-fencing)
5. **SMS/MMS:**
   * Control of data can be concern - outbound data leaks, financial disclosure, inbound notification, phishing attempts.
   * MDM can enable/disable SMS/MMS, or only during timeframes or locations.
6. **External Media:**
   * Limit data written to removable drives or prevent the use of them from MDM.
7. **USB OTG:**
   * USB On-The-Go (OTG) - connect device directly together.
   * Mobile device can act as storage or read form external device.
8. **Recording Microphone:**
   * Every state has different laws, every situation is different.
   * Can be disabled or geo-fence - Manage from MDM.
9. **Geotagging/GPS Tagging:**
   * Adds location to files - metadata.
   * This cause security concern.
10. **Wifi-Direct/ad hoc:**
    * Includes ad hoc (for purposes/when needed) mode which allows wireless connection without AP.
11. **Hotspot/tethering:**
    * Turning mobile into a WiFi hotspot. Personal wireless router.
    * May provide inadvertent access to internal network.
12. **Payment Method:**
    * Send small amount of data wirelessly over limited area (NFC).
    * Built-in phone, payment system, trasportation, in-person information exchange.

### Mobile Deployment Models

1. **BYOD:**
   * Bring Your Own Device/Technology.
   * Employee owns the device - needs to meet company's requirements.
   * Defficult to secure.
2. **COPE:**
   * Corporate Owned, Personally Enabled.
   * Company buys the device, used as both corporate and personal.
   * Similar to company owned laptop, data is protected using corporate policies.
3. **CYOD:**
   * Choose Your Own Device, similar to COPE but you can choose the device.
4. **Corporate Owned:**
   * The company owns the device for corporate only.
   * Cannot use for personal, very specific security policies.
5. **VDI/VMI:**
   * Virtual Desktop/Mobile Infrastructure.
   * The apps, data are separared from mobile device.
   * Data is stored securely, centralized.
   * Physical Device loss does not mean loss or access of data.

### Cloud Security Control

1. **HA Across zones:**
   * Availability Zones (AZ)
     * Isolated locations within a cloud region (geo location)
     * Each AZ have independent power supply, HVAC, etc.
     * Run as active/standby and active/active.
     * Load Balancer for seamless HA.
2. **Resource Policy:**
   * Identity and Access Management (IAM) - who gets what job/access.
   * Provide access to cloud resources - Group, IP address, date & time.
   * Centralize user account, syncronize across all platform.
3. **Secret Managemet**
   * Cloud computing incudes many secrets: API, passphrase, certificate..
   * Diffcult to manage, limit users and access of users to secret service.
   * Accounting: know who accessed secrets and when.
4. **Integration and Auditing:**
   * Integrate account across multiple platform and consolidate logs storage and reporting.
   * Use cloud based Security Information and Event Management.
   * Auditing: validate the security controls, verify cmplaince with financial and user data.

### Security Cloud Storage

1. **Public Cloud:**
   * Data stored in _amazon, google, etc._ are all on public cloud, hence setting weak permission is common.
2. **Permissions:**
   * Public access should not be allowed.
   * IAM, bucket policies is used.
   * Clould should not be used until really necessary.
3. **Encryption:**
   * Cloud data is more accessible than non-cloud data.
   * Encrypted data is sent & stored, decrypted when reaches client.
   * Key management is critical.
4. **Replication:**
   * Real-time data duplication in multiple location.
   * Disaster recovery plan, HA.
   * Data analysis.

### Securing Cloud Network

1. **Virtual Network:**
   * A cloud contains virtual devices - server, databases, storage devices, switches, routers.
   * Cloud network can change with rest of the infrastructure on-demand or rapid elasticity.
2. **Public and Private subnets:**
   * Private cloud: all internal IP addresses, connection over VPN.
   * Public cloud: External IP, connection from everywhere.
   * Hybrid cloud: Combine internal cloud source with external, may combine both public and private subnet.
3. **Segmentation:**
   * The cloud contains seperate VPC, containers, and microservices.
   * Seperation is security opportunity.
   * Virtualized security technologies: WAF, NGFW, IPS.
4. **API inspection and integration:**
   * Microservice architectureis underlying application engine.
   * API calls can include risk.
   * API monitoring is necessary.

### Securing Compute Clouds

1. **Compute Cloud Instances:**
   * IaaS componenet like Amazon's EC2 (Elastic Compute Cloud), Google Compute Engine (GCE) and MS Azure VM allows to manage VM/containers.
2. **Security groups:**
   * A firewall for compute instances.
   * Controls inobound/outbound traffic flow on Layer 4 and Layer 5.
3. **Dynamic resource allocation:**
   * Provision resource when needed.
   * Scale up/down and ongoing CPU monitoring.
4. **Instance awareness:**
   * Indetifying and managing very specific data flow.
   * Allow PII data upload to corporate cloud but not to personal cloud.
   * Alert sec team if such action is taken.
5. **Virtual Private Cloud endpoint:**
   * Microservice architecture is VPC gateway endpoint.
   * Keep private resource private by allowing certain subnets. No internet reaquired.
   * Add an endpoint to connect VPC resource.
6. **Container Security:**
   * Containers have similar sec concers as other application deployment method - bugs, misconfigurations, etc.
   * Container specific OS is prefered.

### Cloud Security Solution

1. **Cloud Access Service Provider (CASB):**
   * Implemented as client software, local security applicance, or cloud based security solutions.
   * Determines Authorization of use of apps, check for complainces - HIPPA, PCI DSS.
   * Prevent attacks by only allowing authorized users.
   * Data security by ensuring encryption of data and tranfer of PII with DLP.
2. **Application Security:**
   * Applications are easy to misconfigure and easier when in cloud.
   * Authorization and Access should be string enough.
   * API security should be strong.
3. **Next-gen Secure Web Gateway (SWG):**
   * Go beyond URLs and GET requests, it examines API requests and JSON strings.
   * Allow/disallow certain activities.
4. **Firewalls in cloud:**
   * Control traffic flow in cloud.
   * Inexpensive compaired to appliances
   * Allows segementation and protect in Layer 4 (transport) & Layer 7 (Application).
5. **Security Control:**
   * Cloud native security control.
   * Integrated and supported by cloud provider.
   * No additional cost.
   * But most of the organization uses multiple vendors for cloud service. There 3rd party cloud security solution is prefered.
     * Support across multiple cloud providers.
     * Extend policies outside the scope of cloud provider.
     * More extensive reporting.

### Identity Control

1. **Identity Provider (IdP):**
   * It is difficult to manage users in cloud than on-premise.
   * 3rd party IdP is used to manage, SSO apps is commonly used.
   * Uses standard authentication method: OAuth, SAML, OpenID Connect..
2. **Attributes:**
   * An identifier/property of an entity.
   * Includes name, email, Employee ID, job title, mail id..
   * One or more attributes combined can be used as attribute.
3. **Certificate:**
   * Digital cert is assigned to a person or device. It can be used to encrypt data or create digital signature.
   * Requires PKI, CA to digitally sign certificate.
   * Token and Cards can also be used.
4. **SSH Keys:**
   * Using keys instead of passwords for automation.
   * Key management is critical.
   * Open source and commercial SSH key managers are used.

### Account Types

1. **User Account:**
   * Account associated with specific person in a computer.
   * Storage and files can be private from other user.
   * No privilage access to OS.
2. **Shared and Generic Account:**
   * Used by more than one user.
   * Difficult to create audit trail, do not know who used specific function.
   * Password changes require notifying everyone.
   * Recommended not to use.
3. **Guest Account:**
   * Can login without password and have limited functions.
   * Brings security concern. Vulnerable kernel can be exploited.
   * Was removed after Windows 10 build 10159.
4. **Service Account:**
   * Used exclusively by services running on computer.
   * Not interactive/user access.
   * Access is defined for specific service - web server, DB server.
5. **Privileged Account:**
   * Elevated access to one or more systems - Administrator, root.
   * Complete access to system.
   * Should not be used for general works. Needs to be highly secured with MFA.

### Account Policies

1. **Perform Routine Audits:**
   * Certain actions can be automatically identified - log analysis.
   * Make it schedule.
2. **Auditing:**
   * Permission Auditing: Check if everyone have correct permissions.
   * Usage Auditing: Check if resources are used in secure way.
3. **Password complexity and length:**
   * Mitigating brute-force attack by increasing password entrophy.
   * Prevent password reuse.
4. **Account lockout and disablement:**
   * Too many incorrect password can lead to account lockout which can only be enabled by administrator.
   * Prevent brute-force.
   * Disablement: Account is not deleted, just disabled. All files of disabled account will be there.
5. **Location based policies:**
   * Network location based on IP subnet.
   * Geolocation by GPS, IP address.
   * Geofencing: allow/disallow function based on location.
   * Geotagging: Adding location metadata to document or file.
   * Location based access rule: allow/disallow access if from this geolocation.
   * Time-based access rule: allow/disallow access to this at this time.

### Authentication Management

1. **Password Keys:**
   * Hardware based solution. Something you have.
   * Does not replace other factor. You still need password.
2. **Password Vault:**
   * Password manager to store all passwords in one location.
   * Cloud based syncronization. Unique passwords can be created.
3. **Trusted Platform Module:**
   * Specific for cryptographic functions. Comes with keys burned in it.
   * Individually have processor, integrated with motherboard.
4. **Hardware Security Module:**
   * High-end cryptographic hardware.
   * Offload CPU overhead from other device. Used in large envoirnments.
5. **Knowledge-based Authentication:**
   * Something you know (personal)
   * Static KBA: Pre-configured shared secerets. Often used in account recovery.
   * Dynamic KBA: Questions based on a identity verification service. Asking your correct address, asking phone number, etc. Not pre-shared.

### PAP and CHAP

* Client wants to access file server in a network. Firewall will provide authentication to client by the help of AAA server. There are two methods of authentication: PAP and CHAP.

1. **Password Authentication Protocol (PAP):**
   * Basic authentication method. Used in legacy system.
   * PAP is in clear. Lack of encryption makes it unsecure.
   * Was used in analog dialups where encryption was not necessary.
2. **Challenge-Handshake Authentication Protocol (CHAP):**
   * Includes three-way handshake.
   * For authentication: AAA server send a challenge with use of password to client. Client is expected to use that challenge to make challenge-respone which should match AAA server's expected challenge-reponse to get authenticated.
   * You see, password is never sent in network.
3. **MS-CHAP:**
   * Microsoft implementation of CHAP.
   * Used commonly on PPTP. MS-CHAP v2 is more recent.
   * Security issue related to use of DES. Brute-force is easy.
   * Do not use MS-CHAP, consider using L2TP, IPSec, 802.1x or some other secure auth method.

### Identity and Access Service

1. **RADUIS:**
   * Remote Authentication Dial-in User Service.
   * Centralize auth for users. Often used with VPN concentrator.
2. **TACACS:**
   * Terminal Access Controller.
   * Was created for dial-up lines.
   * XTACACS: Externded TACACS, additional support of accounting and auditing.
   * TACACS+ : Latest version of TACACS, not backward compatible. More auth response and response code.
3. **Kerberos:**
   * Network Authentication Protocol. Once authenticated, can be trusted by systems. No need to re-auth.
   * Works Kerberos compatible OS.
   * SSO with Kerberos: Authenticate one time. Server gives ticket which can be used for authentication with different systems.
4. **IEEE 802.1X:**
   * Port-based Network Access Control (NAC)
   * Authentication to enter a network.
   * Used in conjunction with an access DB - RADUIS, LDAP, TACACS+.

### Federated Identities

1. **Federation:**
   * Provide network access to other - suppliers, customer, partners.
   * Authenticate and Authorize between two trusted organization.
   * Login with Facebook credentials to another organization.
2. **SAML:**
   * Security Assertion Markup Language.
   * Authenticate through 3rd party to gain access.
   * Not for mobile devices.
   * User requests to web. Web sends user signed/encrypted SAML request which redirects to Auth server. User authenticate to auth server and SAML token is generated by auth server. User present SAML token to web server and gain access.
3. **OAuth:**
   * Authorization Framework. Not authentication protocol.
   * Allows 3rd party to have some permission over another organization. _Eg: discord bot to tweet with discord commands._
   * OpenID Conect: handles single sign-on.

### Access Control

* **Authorization:** Users' right definied on different access control methods. Policy of ensuring only authorized rights are exercised.

1. **Mandetory Access Control (MAC):**
   * OS limits operation based on object, object labels: confidential, secret, top secret.
   * Administrator decides which user gets which object label.
   * Most secure and strictest.
2. **Discretionary Access Control (DAC):**
   * Used in most OS.
   * Owner of the file decides permissions/operations of other user on that file.
   * Access can be modified by owner.
   * Very flexible, hence very unsecure.
3. **Role-based Access Control (RBAC):**
   * Access control by roles in organization: manager, director, team lead..
   * Administrator provide access based on role of user.
4. **Attribute-based Access Control (ABAC):**
   * ABAC consider many parameters. Considered as 'next gen' authorizatoin model.
   * Combine and evaluate parameters like: Resource information, IP Address, time of day, relation to the data, etc.
5. **Rule-based Access Control:**
   * Conditions other than who you are.
   * Access is determined through system-enforced rules.
   * System checks ACL for that object. _Eg: Lab Network is only available between 9 and 5._
6. **File system security:**
   * Store file and access them.
   * Accessing information: ACL, Group/user rights permissions, can be centrally administered.
   * The file system handles encryption and decryption.
7. **Conditional Access:**
   * Devices are changing constantly, therefore becomming difficult to manage access control.
   * Conditions: Employee, type of application accessed.
     * Controls: Allow/Block, require MFA.
     * Admins can build complex access rules.
8. **Privileged Access Management (PAM):**
   * Managing superusers, root account, administrators.
   * Store Privilege accounts in digital vault. Can only be accessed from vault request. Privilege account is temporary.
   * Advantages: Centralized Password Managemet, enables automation, manage access to each user, extensive tracking and auditing.

### Public Key Infrastructure (PKI)

* PKI is a set of software, hardware, people, systems, etc. which create, distribute, manage, store, revoke digital certificates.

1. **The Key management lifecycle:**
   * Key is created with the certificate. key is distributed among the users. Key should be stored securely. Compromised keys are revocationed. Certificates have expiration date.
2. **Digital Certificates:**
   * Public key certificate.
   * Binds public key with a digital certificate, contains other details about the key holder.
   * Certificate can be created by Windows Domain Service or 3rd party.
3. **Commercial Certificate Authorities:**
   * Built-in browser. Web site certificate needs to be purchased.
   * A key pair is created, and public key is sent to CA for signing.
4. **Private Certificate Authorities:**
   * CA is personal, on-premise. Devices must trust your CA.
   * Needed for medium to large organizations.
   * Implemented as a part of overall computing strategy.
5. **PKI Trust Relationships:**
   * Single CA: everyone receives ceetificate from one authority.
   * Hierarchical: Single CA certs to intermediate CA. Distribute management load. Easier to deal with the revocation.
6. **Registration Authority (RA):**
   * You cannot reach out to root CA directly. RA acts as a proxy to root CA.
   * Responsible for rejection, revocation, re-key of certificates.
7. **Important Certificate Attributes:**
   * Common Name (CN), Fully Qualifies Domain Name (FQDN)
   * Additional hostname: github.io | aryan7tiwary.github.io.
   * Expiration: limits exposure to compromise.
8. **Key Revocation:**
   * Certificate Revication List (CRL), maintained by the Certificate Authority (CA).
   * Older certificates gets added to CRL.
9. **Getting revocation details to the browser:**
   * OCSP (Online Certificate Status Protocol). The browser checks if the cert is revocated.

### Certificates

1. **Web Server SSL certificates:**
   * Domain Validation Certificate (DV). Owner of the cert has some control over DNS domain.
   * Exteded Validation Certificate (EV). Additional checks of certificate owner's id. More expense. Green highligh shown in link.
   * Subject Alternative Name (SAN). Extention of X.509 cert. Lists additional cert info. Allows cert to support many domains. _Eg: cloudfare_.
   * Wildcard Domain: Certificate based on name of server. _Eg:_ `*.github.io`.
2. **Code Signing Certificate:**
   * Developer provide a level of trust. Apps are signed by dev.
   * The user's OS will examine the signature for trust.
3. **Root Certificate:**
   * Public key certificate which identifies the root CA. Everything starts from here.
   * Root CA issue cert to other CA - intermediate CA..
   * Needs to be highly secured. Compromise of root CA allows creation of any trusted cert.
4. **Self-signed certificate:**
   * Internal cert, no requirement to be signed by public CA.
   * Only my organization will use it.
   * CA certificate/trusted chain on all device should be installed.
5. **Machine and computer certificate:**
   * Often there are some remote device you cannot physically access.
   * A certificate needs to be installed on them.
   * Business which rely on cert - VPN, Access from remote.
   * Management sofware can validate the end devices.
6. **Email Certificate:**
   * Use cryptography in email platform.
   * Encrypting/decrypting email using private/public key.
   * Digital signatures for non-repudiation.
7. **User Certificate:**
   * Certificate associated to user.
   * Electronic ID, for additional authentication factor.

### Certificate Formats

* **X.509 digital certificate:** The structure of the certification is standardized. The format of actual certificate file can take many different forms. Many cert file formats are available and can be converted to one another.

1. **DER (Digital Encoding Rules):**
   * Format designed to transfer syntax for data structures.
   * Non-human readable (binary format)
   * Common format. Used across many platform. Often used with JAVA certificates.
2. **PEM (Primary Enhanced Mail):**
   * A very common format.
   * Base64 encoded DER cert. Generally the format provided by CAs.
   * ASCII format. Easy to email, readable.
3. **PKCS #12**
   * Public Key Cryptography Standars #12
   * Personal Information Exchange Syntax Standard
   * Developed by RSA.
   * Container format for many cert. Store many X.509 cert in a single `.p12` or `.pkx` file.
   * Often used to transfer a private and public key pair.
   * The container can be password protected.
   * Extened from Microsoft's `.pkx` format.
4. **CER (Certificate):**
   * Primarily a Windows X.509 file extension.
   * Can be encoded as binary DER format or as a ASCII PEM format.
   * Usually contains public key. Private keys would be transfer in `.pkx` file format.
5. **PKCS #7:**
   * Public Key Cryptography Standards #7
   * Stored in ASCII format - humar readable.
   * Contains cert or chain of cert.
   * Cert are included in .p7b file.
   * Wide platform support: MS Windows, Java Tomcat.

### Certificate Concept

1. **OCSP Stapling:**
   * CA is responsible for responding to OCSP requests which cannot be done in real time.
   * Instead, certificate holder verify their status (not revocated) by stapling OCSP status into SSL/TLS handshakes.
2. **Pinning:**
   * You could be communicating to non-legitimate/compromised web server.
   * Mitigation: "pinning" certificate/public key to browser/app is compiled or added when first request was made.
   * If expected certificate/public key does not match. Browser/app can shutdown or show error msg.
3. **PKI Trust Relationships:**
   * Single CA: Everyone receives cert from same CA.
   * Hierarchical: Single CA issue cert to intermediate CAs.
   * Mesh: Cross-certifying CAs - does not scale well.
   * Web-of-trust: Alternative to traditional PKI; if A trust B and B trust C, than A trust C.
   * Mutual Auhentication: Client trust server, server trust client.
4. **Key Escrow:**
   * Someone else holds decryption keys. (3rd party)
   * A legitimate business management.
5. **Certificate Chaining:**
   * Chain of trust.
   * Consists of SSL cert to root CA cert. (intermediate cert if any)
   * Needs to be configured properly.
