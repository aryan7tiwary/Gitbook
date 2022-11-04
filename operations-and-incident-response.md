# Operations and Incident Response



### Reconnaissance Tools

1. **traceroute/tracert (win):** Maps the network path which a packet took to reach destination. TTL (time to live) refers to hop a packet took to reach destination.
2. **pathping:** ping + traceroute. Runs traceroute then measure round trips (TTL) and packet loss at each hop.
3. **netstat:** Network staticks.
   * `netstat -a`: show all active connections.
   * `netstat -b`: show with binaries. (windows)
   * `netstat -n`: do not resolve names.
4. **route:** Prints routing table.
   * `route print`: windows
   * `netstat -r`: linux
5. **cuckoo:** sanbox for malware analysis. Tracks API calls, net traffic, screenshots, memory analysis.

### File Manipulation Tools

1. **chmod:** [Chmod Cheatsheet](obsidian://open?vault=Obsidian%20Vault\&file=Cybersec%2FCTFs%2FNotes%2Fchmod%20file%20permissions)
2. **logger:** Add custom entries to syslog.
   * `logger "this is a custom log"`

### Shell & Script Envoirnment

1. **Windows Powershell:** Comand line for sysadmin. Uses cmdlets (command-lets), stantalone executables.
2. **OpenSSL:** toolkit and crypto library for SSL/TLS.
   * Create cert - X.509
   * Message digests
   * Encryption/Decryption

### Packet Tools

1. **tcpdump:** Display packets on terminal. Can be writen to a file.
2. **tcpreplay:** A suite of packet relay utility. Replay & edit packet captures.
   * Check IPS signatures and firewall rules.
   * Test and tune IP flow/NetFlow devices.
   * Can be used for stress test by sending large amount of packets/s.

### Forensic Tools

1. **dd:** Data Definition. Bit-by-Bit copy of a drive.
2. **memdump:** Copy information in system memory to standard output stream. 3rd party software can read a memory dump.
3. **winhex:** universal hexadecimal editor for Windows OS.
   * edit disk, file, RAM. Clone disk. Secure wipe.
4. **FTK imager:** AccessData forensic drive imaging tool.
   * Include file utility and read-only image mounting.
   * Windows executable.
   * Widely supported with 3rd party forensic tools.
   * Can also import other image formats: _dd, Ghost, Expert Witness, etc._
5. **Autopsy:** Recover data and view in classified format - videos, images, etc

* **Data Sanitization:** Completely remove data. Cannot be recovered. Disk/multilpe or single file.

### IR Process

1. **NIST SP800-61:** NIST Special Publication 800-61, about computer security incidents. Handling guide.
   * IR Lifecycle: Preperation --> detection & analysis --> containment, eradiction & recovery --> Post-incedent activity.
   * Preperation: includes preparing communication method, handling hardware & software, analysis resources - baseline, etc. Mitigation software, policies.
   * Detection: How impactful attack is? Details of attack.
   * Incident precursors: Web server log, exploit anouncement, what are the threats.
   * Incident Indicators: Attack underway or successful exploit. BoF attempts. Deviation in network traffic flow.
2. **Isolation and Containment:** Sanboxes - isolated OS to detonate malware. Isolation can be problematic. Malware can monitor activity or does not detonate after detecting sandbox.
3. **Recovery after incident:** get things back to normal by eradicating and recovery.
4. **Reconstitution:** A phased approach to fix thing. Recovery can take months. Plan should be efficient.
5. **Lessons learned:** learn and improve Post-incident meeting. Do not wait too long to fix.

### IR Planning

1. **Tabletop exercise:** Verbally talking thorugh simulated disaster, not going physical.
2. **Walkthorugh:** Testing processes/tools before an event. Can indentify missing steps or actual faluts to fix.
3. **Simulations:** Testing with simulated event. Testing user. Phishing, breaching. Checking if phishing email got undetected though filter.
4. **Stakeholder management:** keeping good relation with customers of IT. Metting with them before/during/after events. Including them in exercises.
5. **Communication Plan:** Contacting CIO, IR team, infosec head. Even internal non-it - HR, public affairs, legal. External contact - System Owner, Law Inforcement, US-CERT.
6. **Disaster Recovery Plan:** IT should be ready for disaster - natural, tech failure. Plan should be comprehensive - recovery location, recovery method.
7. **Continuity of operation planning (COOP):** There should be alternatives. These must be documented and tested before event occurs.
8. **Retention Policy:** action of keeping something. How, where, how much should backup data. Regulatory complaince, Operations needed.

### Attack Framework

1. **MITRE ATT\&K:** Framework which contains extensive knowlegde. Includes Point of Intrustion, methods of intrustion, mitigation to intrusion.
2. **Diamond Model:** Apply scientific principle to intrusion analysis. Uses diamond shaped model to fill in detials.
3. **Cyber Kill Chain:** Seven phases of a cyber attack. A military concept.

* **Vulnerability Scan Output:** Depends on signatures of the service. Indicates lack of control system. False negative can be minimized by regularly updating signatures.
* **SEIM Dashboard:** Security alerts, log aggregation for long-term storage. Data correlation (link diverse data types). Forensic analysis.
  * Sensor and logs data - NetFlow, OS, Infrastructure device.
  * Viewing data - Trends, Alerts, Correlation.

### Log Files

1. **Network log files:**
   * From switches, routers, access points, VPN concentrators.
   * Routing updates, Authentication issue, network security issue
2. **System log files:** OS informations (extensive logs), security events.
3. **Application log files:** Specific to an application. Can be parsed on SEIM.
4. **Security log files:** Detailed security-related information. Blocked/Allowed traffic flow, exploit attemts, URL filtering, DNS sinkhole traffic. Includes Firewall, IPS, proxy. Correlated with other logs, summary of attack info.
5. **Web log file:** Web server acces, includes client IP, web page URL. Exploit attempts, access error.
6. **DNS Log files:** view lookup requests, identify query for bad requests.
7. **Authentication log file:** Know who logged in - account name, source IP, auth method. Correleated with other log.
8. **Dump files:** store all contents of memory into dignostic file. Created from task manager for an application.
9. **VoIP and Call Manager logs:** inbound/outbout traffic flow. Security infomation and traffic log.

### Log Management

1. **syslog:** Standard for message log. Central logging receiver interated into SIEM.
2. **Journalctl:** Linux. Syetem logs are stored in binary in linux which is represend in plain text by Journalctl. Have function to filter output.
3. **bandwidth monitor:** the fundamental network statistic. percentag of network use over time. Many different ways to gather this - SNMP, sFlow, NetFlow, IPFIX, protocol analyzer.
4. **Metadata:** Email - email headers. Mobile - type of phone, GPS. Web - OS, browser type, IP. Files - name, address, ph no. title.
5. **NetFlow:** Gather traffic statistics from all traffic flows. Probe watches network communication and summary are recorded in collectors. Seperate reporting app
6. **IPFIX:** IP flow information export. Evolved from NetFlow v9. Flexible data support, templated are used to describe data.
7. **sFlow:** Sampled Flow. Only a portion of actual network traffic. Usually embedded in infrastructure. Useful information regarding video streaming and high-traffic application.
8. **Protocol analyzer output:** Solve complex application issue. Gather packets on-air. Very detailed traffic information. Verify packet filtering and security control.

* **Endpoint Security Configuration:** Endpoints are end user devices. These are most sophisticated area.
  * Application allow/deny list: based on UID, Certificate, Path, Hash and Network zone.

### Security Confuguration

1. **Isolation:** Administratively isolate a compromised device from everything else. Prevent spread of malware and remote access from C2.
   * Network isolation: No communication to other device.
   * Process isolation: Limit app execution.
2. **Containment:** App container. Run each application in own sandbox. contain the spread of malware by disabling admin shares, remote management, change passwords.
3. **Segmentation:** Seperate network, prevent lateral movement.
4. **SOAR:** Integrate 3rd party tools. Make security team more effective.
   * Runbook: Linear checklist to perform task. Reset password, a website cert, backup app data (normal tasks).
   * Playbook: Conditional steps to follow. A broad process. Investigate data breach, recover from ransomware.

### Digital Forensics

1. **Digital Forensic:**
   * RFC 3227 - Guidelines for evidence Collection and Archiving.
   * Standard digital forensic process: Acquisition --> analysis --> reporting.
2. **Legal Hold:** Legal technique to preserve relevant data.
   * Seperate repository for electronically stored information (ESI).
3. **Video Capture:** Gather information external to the computer and network
   * Captures status of screen and other volatile info.
   * Video must also be archieved.
4. **Admissibility:** Not all data can be used in court. Different jurisdiction have different rules.
   * Legal authorization: Search and seizure of info.
   * Procedures and tools: correct tools are used in correct way.
   * Laboratories: Proper scientific procedure used to analyze the evidence.
   * Technical and academic qualifications
5. **Chain of Custody:** Control evidence and maintain integrity. Everyone who contacts evidence should be registered. Hashed should be used to avoid tampering.
6. **Recording time offsets:** Timezones determine how times are showed.
   * FAT: shows in local time.
   * NTFS: shows in GMT.
   * You can record time in windows from registry.
7. **Event logs:** Every important logs should be documented.
   * Linux: `/var/log`(c/p); Windows: Event Manager (can be exported)
8. **Interviews:** Interview and document person nearby forensic scene ASAP.
9. **Reports:** Document the findings. Summarize informations. Detailed explanation of data acquisition (step-by-step process). Conclusion (professional result).

### Forensics Data Acquisition

1. **Order of Volatility:** !\[\[Pasted image 20220918225028.png]]
2. **Disk:** Power down to prevent changes. Remove disk. Connect with imaging devide with write-protection. Bit-for-bit copy.
3. **RAM:** Difficult to capture. Memory dump grabs everything in memory. Important data - browsing history, clipboard information, encryption keys, command history - which might not be found anywhere else.
4. **swap/pagefile:** Extensive of RAM, where memory is stored from RAM to get storage for another application. Should also be archieved.
5. **OS:** OS files and data. Core OS (usually captured within drive). Other OS data includes: Logged in user, open ports, processes running, attached devices list.
6. **Device:** Mobile/tablet is more challenging. Transfer image over USB. Use previously made backup files by device. Data includes: phone logs, contact information, SMS, email, images & videos.
7. **Firmware:** Extract device firmware. Rootkits and exploited hardware devices affect firmware. Data includes: exploit data, firmware functionality, real-time data.
8. **snapshot:** Generally associated with virtual machines (VMs). Contains all file and info about VMs.
9. **Cache:** Store data for later use to speed things rather than querying same things multiple times (temporary). CPU cache is very short-term instruction storage. Data incudes: URL location, browser page components.
10. **Network:** Inbound/outbound sessions, packet data, 3rd party firewall, IPS packet captures.
11. **Artifacts:** Digital items left behind. Artifact locations: log information, flash memory, prefetch cache files, Recycle bin, browser bookmarks and logins.

### On-premise vs. Cloud Forensics

1. **Forensics in Cloud:** More complex as you do not have device physically.
   * Technical challenges: Devices are not totally in your control. Limited acces. Data associated with specific user.
   * Legal chellenges: Laws are different around the world.
2. **Right to audit clauses:** Have predefined rules with cloud privider.
   * How data sharing would work. How they are being access over internet. Are they secure?
   * Audit clause should be signed before a breach occur. Everyone agrees to ToC.
3. **Regulatory/Jurisdiction:** Forensic professionals should know their legal rights. Data in different jurisdiction may be bound to different regulations. Legal framework widely vary between different county.
4. **Data breach notification laws:** If consumer data is breached, the consumer should be notified. Data breach notification laws vary widely across different countries. Notification requirements: type of data breached, who gets notified, how quickly.

### Managing Evidence

1. **Integrity:** hashing, checksum, provenance (chain of custody - using blockchain tech, documentation)
2. **Preservation:** Handling evidence. Isolate and protect data. Analyse later without alterations.
3. **E-discovery:** Electronic discovery. Gather data required for legal process, does not involve analysis. Works with digital forensics. Determinning data was deleted and attempt to recover bc data on drive looked smaller.
4. **Data recovery:** Extract missin data without affecting the integrity of data.
5. **Non-repuduation:** Proof of data integrity and origin of data.
   * MAC (Message Authentication Code): two parties can verify non-repuduation.
   * Digital Signature: Everyone can verify non-repudiation.
6. **Strategic Intelligence/counterintelligence:**
   * Gathering information or key threat activity for domain. Includes: business sector, geographical region, countries. Can be gathered by internal threat report, 3rd party data sources, OSINT.
   * Counterintelligence: If we find someone doing intelligence operation on us, would counter it and run intelligence operations on them.
