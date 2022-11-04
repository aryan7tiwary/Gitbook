# Architecture and Design

1. Types of data: **data-at-rest**: data which are on removable HDD or SDD, pendrive, removable NAS or SAN. **data-at-transit**: data which are moving - wireless connection, VPN connection **data-in-use**: data which are being used - memory, swap memory, temp spaces.
2. **Trusted Platform Module (TPM)**: is a hardware chip embedded on motherboard used to store cryptographic keys for encryption safely.
   * **Hardware Security Module (HSM)**: same as TPM, unlike TPM it is removable. Both are used for encryption using **RSA** keys.
3. **API Gateway** can provide load balancing, virus scanning, orchestration, authentication, data conversion and more.
4. !\[\[Pasted image 20220522110640.png]]
5. **DNS Sinkhole**: DNS which hand out incorrect IP addresses.
   * Attacker can redirect users to a malicious site. (BAD)
   * Redirect known malicious domains to a benign IP address. (GOOD) Example: putting typosquats of genuine domains with same correct IP to mitigate typosquating.
6. Types of service by cloud:
   * **XaaS:** "Anything as a service", economical, helps IT to customize what they need in cloud.
   * **IaaS**: Also called "**Hardware** aaS". We are responsible for management and security. Data is out there but more under our control. We have responsibility of OS upto Application. _Eg: Web server_.
   * **PaaS**: Someone else handles the platform, we handle the development. We don’t have direct control of the data, people, or infrastructure. Allows us to build a application as per our need. Therefore, boosts development process. _Eg: Microsoft Azure_.
   * **SaaS:** On-demand software. Nothing needs to be done by you. _Eg: Google Mail, Office 365_.
   * !\[\[Pasted image 20220807210144.png]]
7. Types of Clouds:
   * **Private:** You manage and maintain all the resources.
   * **Public:** Cloud provider manages all the resources.
   * **Hybrid:** Mix of Private/Public. Eg: Some services in a company is running in public cloud and some internal services are running in private cloud.
   * **Community:** Serveral organization use a cloud and share same resources to make it cost efficient.
8. **Edge computing**: IoT devices close to the user. Can compute things on itself, so no need to go to cloud for computation. This means it has the right amount of data in it to process its task. **Fog computing:** A distrinuted cloud architecture which extends the cloud. Some data can be computed locally (edge computing), while some need to be sent over cloud. There is fog computing in between cloud and IoT to process and deliver some amount of data immediately to that device. Other device and then use the processed data if their need is same.
9. **Virtualized** vs **Containerized**
   * Virtualization: A hypervisor runs multiple guest OS for different specific application.
   * Containerization: A host OS contians docker which separates applications by initialising sandbox.
10. **Microservices and API:** Allows to tweak/update single feature from a large code of complex application. Failure of single service does not effect whole application. It can be scaled just by adding more microservice. API helps in operation of multiple microservice together.
11. **Serverless Architecture:** Serverless architecture is **an approach to software design that allows developers to build and run services without having to manage the underlying infrastructure**. Developers can write and deploy code, while a cloud provider provisions servers to run their applications, databases, and storage systems at any scale. They are often managed by 3rd party. **Scalability** is its advantage.
12. **Transit Gateway:** Router for virtual private clouds (pool of clouds in public cloud) !\[\[Pasted image 20220809161655.png]]
13. **Infrastructure of Code (IaC)**: **the managing and provisioning of infrastructure through code instead of through manual processes**. With IaC, configuration files are created that contain your infrastructure specifications, which makes it easier to edit and distribute configurations.
14. **SDN:** Software-defined networking technology is an approach to network management that enables dynamic, programmatically efficient network configuration in order to improve network performance and monitoring, making it more like cloud computing than traditional network management.
15. **SDV:** Software Defined Visibility, this allows us to deploy next-generation firewalls, intrusion prevention, web application firewalls, and other security devices while at the same time being able to understand exactly what type of data is flowing between all of these systems.
16. **VM Sprawl:** happens when an administrator can no longer effectively control and manage all the virtual machines on a network.
17. **VM Escape:** Break out of the VM and interact with the host operating system or hardware.
18. **Managed Service Provider (MSP)**: delivers services on-prem, customer site or in a 3rd party data centre. They handle network, application, infrastructure, security, etc. **Managed Security Service Provider (MSSP):** delivers service related to security devices. Offers 24X7 monitoring. Includes Firewall, IPS, VPNs, Vulnerability Scans, AV, etc.
19. **Confusion:** Encrypted data is totally different from plain text. **Diffusion:** Change in one character in input --> many change in output
20. Site Resiliency:
    * **Hot Site:** Exact replica. Ditto. Most expensive.
    * **Cold Site:** No hardware, no data. Basic power supply. Least expensive.
    * **Warm Site:** Have needed hardware. More expensive than Cold Site.
21. **Information Rights Management (IRM)**: Controls how data is used. Restriction to edit/modify, prevents copy/paste. Attackers have limited options.
22. **Provisioning:** Deploy an application. Web/Database server, network security, certificate update, OS, workstations, etc.
    * **Deprovisioning**: Dismantling or removing an application instance. To not leave information out there.
23. A **stored procedure** is a set of Structured Query Language (SQL) statements with an assigned name, which are stored in a relational database management system (RDBMS) as a group, so it can be reused and shared by multiple programs. Prevents SQL injection.
24. **Obfuscation/camouflage:** Make something normally understandable very difficult to understand. Eg: Take perfectly readable code and turn it into nonsense.
25. **Code Reuse:** Using old code to make application. If old code is vulnerable then it is bad because the application will be vulnerable.
    * **Dead Code:** is code in the source code of a program which is executed but whose result is never used in any other computation. This is bad, code should be most alive.
26. **Software Diversity:** If _XYZ_ software is vulnerable, every _XYZ_ can be exploited.
27. **CI:** Continuous Integration: Code is constantly written and added into repos. Security problem is a concern everytime.
    * **CD:** Continuous Delivery: Testing and release process is automated. User need to interact to deploy.
    * **CD:** Continuos Deployment: Even more automation, no human interaction. Automatically deploy to production. Eg - _Github pages_
28. **Authentication Methods:**
    * **Federation:** Credentials are stored in 3rd party storage system, and another organizatino authenticate in terms of that credentials. Inculdes two organizations.
    * **Attestation:** Authentication if your hardware is trusted and truly yours.
    * **TOTP:** OTPs are generated with a secret key and time of the day. Syncs via NTP.
    * **HOPT:** OTPs can be used only once for one session. Hash is different everytime.
    * **Retinal Scan:** unique capillary structure in the back of the eye.
    * **Iris Scan:** Texture and colour of the eye.
    * **Gait Analysis:** how a person does something uniquely.
    * **FAR:** False Acceptance Rate - Unauthorized person being accepted.
    * **FRR:** False Rejection Rate - Authorized person being rejected.
    * **CER:** Crossover Error Rate - Defines the accuracy of a biometric system. The rate at which FAR and FRR are equal.
29. **Disk Redundancy:** (we don't want a part failure lead to downtime)
    * **Redundant:** Duplicate part of something.
    * **Multipath I/O:** Multiple fibre channel interfaces with multiple switch, incase one fails.
    * **RAID** (Redundant Array of Independent Disks)
      * **RAID 0:** No redundancy, if disk has failed there is no backup. (Striping without parity)
      * **RAID 1:** Clone of disk. (Mirroring)
      * **RAID 5:** Pieces of data in individual disks. And parity information in another (last) disk. If disk fails it will rebuild the disk based on parity information. (Striping with parity)
      * **Combinations of RAID:** RAID 0+1, RAID 1+0, RAID 5+1, etc. Customizable as per need.
30. **Network Redundancy:**
    * **Load Balancing:** Decides which server to connect clients with. Some server are alive some are on stand-by while some may die in between.
    * **NIC teaming:**
      * LBFO - Load Balancing / Fail Over. Aggregates bandwidth by connecting with multiple ports with server.
      * Multiple Network Addapters - Looks like a single adapter but if one fails server can exchange packets with reduntant one.
      * NICs communicate with each other in a frequency of time, if one of the NICs doesn't respond it is said to be dead, now redundant takes its place.
31. **Power Redundancy:**
    * **UPS:** Uninterruptible Power Supply, short-term backup power. Some UPS has feature to auto shutdown computer. Has different battery capacity.
      * **Types of UPS:**
        * Offline/Standby - works when it detects no power.
        * Line-interactive - Detects low voltage in power to supply its DC current.
        * On-Line/Double-conversion - Power always flow through UPS, so it can back up faster than any other type.
    * **Generator:** Long-term backup power. Takes time to speed up and supply power.
    * **Dual-power supplies:** Two power supplies plugged in PC for redundancy. Power supplies can be aggregated. **Hot-swappable** replace a faulty power supply without powering down.
    * **PDUs:** Power Distribution Units - Multiple socket in a board. Can monitor power supply. Enable/Disable individual outlets.
32. **Replication:**
    * **SAN Replication:** Storage Area Network - Share data between devices, in case one fails. Very fast recovery time.
      * **SAN snapshot:** Can restore data between the snapshots. Snapshot can replicate data to another SAN for recovery.
    * **VM Replication:** Maintaining one VM, and replicating.
33. **Backup Types:**
    * **Full:** Everything back up. **One** tape is required.
    * **Incremental:** A full back up is taken first, then subsequent backups of data that changed wrt full back up and last incremental backup. **Multiple** disks are required.
    * **Differential:** A full backup is taken first, then subsequent backups of data changed from the last differential backup. Not more than **two** disk is required.
    * !\[\[Pasted image 20220819215539.png]]
    * **Magnetic tape** is portable but slower than **Disk**.
    * **Snapshots** have the fastest restore time.
34. **NAS vs SAN:**
    * NAS: Network Attached Storage ➡ Connected to a shared storage device across the network. _Ex: HDD connected to router._ **File level access** - To change a portion of a file, the entire file needs to be overwritten.
    * SAN: Storage Area Network ➡ Local storage device. **Block level access** - To change a portion of a large file, that portion will only be changed, no overwriting.
35. **HA (High Availability):** Redundancy does not always mean: always available. HA : means available. This can mean it is running along with the primary component. High cost. _Ex: Two power supply to a PC._
36. **Diversity:** A zero-day attack will affect only single device. With help of multiple security device (diversity) uptime can be maintained. _Ex: Diversity in technology, cryptography, vendor, controls (roles), etc_
37. **Embedded Systems**: hardware and software designed for specific purposes.
    * **SoC:** System on Chip - multiple components running on a chip. _Ex: Raspberry Pie_.
    * **FPGA:** Field-programmable gate array - an integrated circuit that can be configured after manufacturing. FPGA can be reprogrammed. Used in firewall logics, routers.
    * **SCADA/ISC:** Supervisory Control Data Acquisition System, Industrial Control System. A PC that manages equipments - power generation, refining, logistics.
    * **Smart devices/IoT:** extremely purpose oriented devices connected to internet. Sensors, smartwatches, facility automations, thermostats.
    * **HVAC:** Heating, Ventilation, and Air Conditioning. Managed by PC to make cooling/heating decisions.
    * **Printers, scanners, and fax machines:** All-in-one or multifunction devices (MFD). Every feature in single device.
    * **RTOS:** Real-Time Operating System - OS with high speed responses. Extremely sensitive to security issues.
    * **Surveillance Systems:** Video/audio surveillance. Some allows firmware updates.
38. **Embedded System Communications:**
    * **SIM:** Subscriber Identity Module - universal integrated circuit card.
    * **Narrowband:** can communicate in a narrow range of frequency. High power.
    * **Baseband:** single cable with digital signal. Utilization is either 0% or 100%.
    * **Zigbee:** For IoT networking. Standard - **IEEE 802.15.4 PAN** Alternative to Wi-Fi and Bluetooth.
39. **Constraints of embedded systems:**
    * Low cost; low power; upgradability limitations; limited cryptographic features.
40. **Responsibilities:**
    * DevOps: change/configuration.
    * IR team: change request
    * Vulnerability administrator: requesting changes to implementing changes. Can also be involved in testing changes/patches.
    * Network administrator: request as well as implement changes. Can be involved in testing changes.
    * Change Board: change approval.
41. **Physical Security Controls:**
    * **Access Control Vestibules:** Also known as _mantraps_. Space between two doors for authentication. Two doors cannot be opened together.
    * **Industrial Camouflage:** Blending an important building in local environment, like data centers.
    * **Door Access Control:** **Deadbolt** - physical bolt; **Electronic** - keyless, pin; **Token-based** - RFID, magnetic swipe card, key fob; **Biometric**; **Multi-factor**.
    * **USB data blocker:** Prevent _juice jacking_ - install malware on the device, or to surreptitiously copy potentially sensitive data using charger.
    * **Sensors:** Motion detection ; Noise detection ; Proximity reader - electronic door locks, combined with access cards; Moisture Detection - water leaks; Temperature detection .
    * **Faraday cage:** Blocks electromagnetic waves. Not all signals can be blocked.
    * **Screened subnet:** Demilitarized zone (DMZ). Public access to public resources. Separates private resources by subnetting.
    * **Protected Distribution System:** Secures cable networks. Prevent cable/fiber taps and physical DoS. By sealing cables with metal conduit.
42. **Secure Areas:**
    * **Air Gap:** physical separation between networks.
    * **Vaults and safes:** Vault is a secure reinforces room to store backup medias, protect something from theft. Safe are similar to vault but smaller.
    * **Hot and Cold aisles:** Cooling system for data centers. Cold air is pushed into CPUs from one side, hot air is sucked out from the other side where heat is generated. The hot air is then processed into cold air and recycled again and again.
43. **Secure Data Destruction:**
    * There is a security policy for destruction of media/device, some can be illegal. Destruction of email can be against government policy, as emails need to be there for later references.
    * **Pulping data:** large tank washing to remove ink nd recycle paper.
    * **Shredder/pulverizer:** heavy machinery, complete destruction.
    * **Electromagnetic (degaussing):** remove magnetic field to destroy data and make the drive unusable.
    * **Incineration:** Fire hot
    * **Certificate of Destruction:** If you are giving a 3rd party your device/media to be destructed, you'll need proof. This certificate show how exactly the which device exactly was destructed.
    * **Purge:** Removing some of the data from a database. **Wiping:** unrecoverable removal of data on storage devices. Media can be used again for another purposes.
    * **sdelete:** windows command for file level overwriting.
    * **DBAN:** Darik's Boot and Nuke (open-source project)

## Cryptography Concepts

1. **Cryptography provides:**
   * **Confidentiality:** A secret; only for selected group of people.
   * **Authentication and access control**
   * **Integrity:** Data has not been tampered.
2. **Cryptanalysis:** The art of cracking encryption.
3. Larger **keys** or using multiple **keys** makes encryption stronger.
4. **Key Stretching**/**Key Strengthening**: Hashing a password multiple times to make it stronger.
5. **Key Stretching Libraries:**
   * **bcrypt:** uses blowfish cipher, extension of UNIX crypt library.
   * **Password-Based Key Derivation Function 2:** (PBKDF2), part of RSA public key cryptography.
6. **Lightweight Cryptography:** for low watt and CPU devices - IoT
   * NIST is working on making powerful encryption which includes integrity feature in low cost for low watt and CPU devices.
7. **Homomorphic Encryption (HE):**
   * It is difficult to perform functions on encrypted data.
   * With HE performing functions while the data is encrypted is possible.
8. **Symmetric and Asymmetric Cryptography:**
   1. **Symmetric:**
      * Also known as - A single, shared key; Secret Key algorithm.
      * Encryption and decryption with same key.
      * Doesn't scale well. Faster and less computational.
   2. **Asymmetric:**
      * Also known as - Public Key Cryptography
      * Two or more keys are involved. Private & Public.
      * Private key is the only key which can decrypt encrypted data with the public key.
      * Key generation includes a lot of randomization, large prime numbers and math.
      * Public key is distributed in many ways. Private key should be kept private.
9. **Elliptic Curve Cryptography (ECC)**: Asymmetric Encryption, Uses graph instead of numbers. Uses smaller keys that non-ECC. Smaller storage bandwidth/transmission required, therefore perfect for mobile devices.
10. **Symmetric Key from Asymmetric Key:** When Private key of individuals are computed with other's public key, the result is a symmetric key for both sides.
11. **Digital Signature:** Hash can be used as digital signature as hash provides: Authentication, non-repudiation, and integrity.
12. **Salt:** Random data added to a password when hashing. Mitigation for Rainbow Table attacks. If attacker knows the salt, brute-force can be successful.
13. **Key Exchange:**
    * Out-of-band key exchange: Not sending key over network. Using telephone, courier, in-person, etc. modes to transfer.
    * In-band key exchange: Sending key over network. Using asymmetric encryption to deliver symmetric encryption.
14. **Real-time encryption/decryption:** Need for fast security
    1. sharing symmetric key using asymmetric encryption.
       * Client encrypts symmetric key using server's public key. Now, only server can decrypt it using server's private key. This is how a session key is created.
15. **Traditional web server encryption:** SSL/TLS uses encryption key to protect web server communication. If the server's private key is compromised, the attacker can rebuild/decrypt every communication. This leads to one point of failure. This is mitigated by PFS.
16. **Perfect Forward Secrecy (PFS):** Uses Elliptic curve or Diffie-Hellman ephemeral (ECDHE). Every session uses different private key for the exchange of symmetric (session key). More computing power is required.
17. **Steganography:**
    * Obfuscation: The process of making something unclear. Making source code difficult to read.
    * Steganography: Embedding message in unexpected files like - image, audio or video.
    * Common Steganography Technique: Embedded message in TCP packets. Using an image. Invisible watermarks.
18. **Quantum Computing:**
    * Uses quantum physics. This is not an upgrade, but a total new computing technology.
    * Rather than working on bits (0s and 1s) it works on qubits (in-between 0s and 1s).
    * It is very fast and can search quickly through large databases and index them at the same time.
19. **Post-quantum cryptography:**
    * None of the existing cryptography could be trusted.
    * No financial transactions would be safe.
    * No data would be private.
20. **Quantum communication:** Quantum Key Distribution: protects against eavesdropping. When a random stream of qubits (the key) is sent over the network, if the key is not identical, the key was viewed across the transmission.
21. **Stream and Block Ciphers**
    1. **Stream ciphers:** Encryption is done one bit/byte at a time. High speed and less computational. Used with symmetric encryption. Two stream could be identical, therefore their ciphertext would be identical, mitigation - using initialization vector (IV) to add randomization.
    2. **Block ciphers:** Encrypts fixed-length groups. Padding is done when plaintext falls short. Used with symmetric encryption. This avoids a pattern in encryption.
22. **Block cipher mode of operation:**
    * **Electronic Code Book (ECB)**: Each block is encrypted with same key. This leads to a pattern in ciphertext, which is an issue.
    * **Cipher Block Chaining (CBC):** Each plaintext is XORed with the previous ciphertext block. Which adds randomization, thus mitigates pattern forming issue.
    * **Counter (CTR):** Counter is encrypted and then XORed with plaintext to form cipher text.
    * **Galois/Counter Mode (GCM):** Encryption with authentication. Combines Counter mode with Galois authentication. Minimum latency, less computational, efficient. Commonly used in wireless, IPsec, SSH, TLS.
23. **Blockchain Technology:**
    * A distributed ledger. Keeps track of transaction.
    * Everyone on the blockchain network maintains the ledger.
    * Applications:
      * Payment, digital identification, supply chain monitoring, Digital voting.
24. **Cryptography Use Case:**
    * Low power device: Use ECC for asymmetric encryption. Smaller key size.
    * Low latency: Fast computation time - symmetric encryption, smaller key size.
    * High resiliency: Larger key size. Encryption algo quality. Hashing provides data integrity.
    * Integrity: Prevent modification of data. Validate contents of hashes when a file is downloaded. Password storage.
    * Obfuscation: Modern malware encrypts code to bypass IPS signature check.
    * Authentication: Password hashing, protects original password from being stored. Adds salt for randomization.
    * Non-Repudiation: Conform the authenticity of data. Asymmetric encryption provides digital signature which features integrity and non-repudiation.
25. **Cryptography Limitation:**
    * Speed: more involved encryption increases load.
    * Size: If a block cipher encrypts 16 bytes at a time, encrypting 8 bytes of plaintext would take up double space - padding.
    * Weak keys: Larger keys are more difficult to brute-force
    * Time: Encrypting larger files takes more time.
    * Longevity: A specific cipher can become less secure with time when more powerful CPUs gets developed. Key retirement is good practice
    * Predictivity and entropy: A passphrase needs to be appropriately random.
    * Key reuse: Reusing the keys reduces the key complexity.
    * IoT devices often have keys embedded in firmware.
    * Resource vs. Security constraints: IoT devices have limited CPU, memory and power. Difficult to maintain and upfate security components.
