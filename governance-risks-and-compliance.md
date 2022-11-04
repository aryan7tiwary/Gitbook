# Governance, Risks, and Compliance



1. **Control Categories:**
   * Managerial: Control that address sec design, implementation and sec policies.
   * Operational: Control implemented by people: guards, phishing awarness campaign.
   * Technical: Control implemented using systems: firewall, OS control, IPS.
2. **Control Types:**
   * Preventive: Prevents access to. Security guards, door lock, firewall.
   * Detective: Cannot prevent but detect. Motion detector, IDS.
   * Corrective: Designed to mitigate damage. Backup to mitigate ransomeware, IPS to block IPs.
   * Deterrent: Discourages attacker. Warning signs, login banner.
   * Compensating: Doesn't prevent an attack. Hot site, backup power system, re-image or restore from backup.
   * Physical: Fences, lock, mantraps.

### Security Regulation and Standards

**Complaince:** Meeting standards of laws, policies, and regulations. Industry specific. Pentalties for not coping.

1. **GDPR:**
   * General Data Protection Regulation.
   * Europian Union regulation for data protection and privacy for individuals in the EU. Name, address, photo, email, bank details, etc.
   * Controls export of personal data. User can decide where their data go.
   * Individial right to be forgotten from site.
2. **PCI DSS:**
   * Payment Card Industry Data Security Standards.
   * Standard for protecting credit cards.
   * Protects cardholder details. Build, maintains and reguarly monitors secure infrastructure.

### Security Frameworks

1. **Centre for Internet Security (CIS):**
   * Critical Security Controls (CSC)
   * Categorized for different organization sizes. Designed for IT professionals - includes implmentation.
2. **NIST RMF:**
   * Risk Management Framework (RMF)
   * Mandetory for US Federal agencies and oranizations which handle federal data.
3. **NIST CSF:**
   * Cybersecurity Framework (CSF)
   * Framework core: Indentify, Protect, Detect, Respond, Recover.
4. **ISO/IEC Frameworks:**
   1. International Organization for Standardization (ISO). International Electrotechnical Commision.
   2. ISO/IEC 27001: Standard for Information Security Management Systems (ISMS)
   3. ISO/IEC 27002: Code of practice for Information Security Controls.
   4. ISO/IEC 27701: Privacy Information Management System (PIMS).
   5. ISO 31000: International Standards for risk management practices.
5. **SSAE SOC Type I/II:**
   * The American Institute of Certified Public Accountants (AICPA) auditing standard Statement on Standards for Attestation Engagements number 18 (SSAE 18).
   * SOC 2 - Trust Service Criteria (security controls). Firewalls, intrusion detection, and MFA.
   * Type I audit: Tests controls in place at a particular point of time.
   * Type II audit: Tests controls over a period of 6 consecutive months.
6. **Cloud Security Alliance:**
   * Security in cloud computing.
   * Cloud Control Matrix (CCM)
   * Controls are mapped to standards, best practices and regulations.

### Secure Configuration

1. Default configs are not secure. Manufacturer's hardening guide is the key.
2. **Web server hardening:** Huge potential of data leaks, server access.
   * Info leakage: banner grabbing.
   * Permissions: should not be run from priviliged account and have minimum permissions.
   * Configure SSL: Managing and installing certs.
   * Log files: to monitor access and error logs.
3. **OS Hardening:** Varity of OS need updates, sec patches.
   * User account should be secured with password policies.
   * Implementation of network access and sec.
   * Monitoring and securing using AV, Anti-malware.
4. **Application Server:** Programming langs, runtime libraries, etc.
   * b/w webserver and DB. Also called middleware.
   * Unnecessary services should be dissabled.
   * Security Patching.
   * File permissions should be limited. Access from other devices should be limited.
5. **Network Infrastructure devices:** Switches, routers, firewalls, IPS, etc.
   * Purporse-built OS: embedded OS.
   * Don't use default config, use manufacturer's guide to harden sec.
   * Constantly check for updates from manufaacturer's.

### Personal Security

1. **Acceptable Use Policy (AUP):** Detailed documentations, Rule of Behaviours.
   * Covers topic regarding internet use, telephone, computer, mobiles.
   * Used by organization to limit legal liability.
2. **Business Policies:**
   * Job Rotation: Keep moving people b/w responsibilities.
   * Mandatory Vacation: Rotate others thorugh job, to identify fraud.
   * Seperation of Duties: Split knowledge. Ex: two people know parts of PIN. Also known as Dual Control.
   * Clean Desk Policy: When you leave nothing should be on the desk. Limits the exposure of sensitive informations.
3. **Least Privileges:** Rights and permisions should be set at bare minimum. Don't allow users to run with administrative privileges.
4. **Background Checks:** Pre-employment screening. Verify applicant's claims. Discover criminal activities.
   * Adverse Action: An action that denies employment based on background checks. Requires extensive documents. Can also include existing users.
5. **Personal Security Procedures:**
   * NDA: Confidential agreement/Legal contract. Prevents the use of confidential confidential information.
   * Social Media Analysis: Gather data from social media to build personal profile.
6. **On-boardring:**
   * New hires. IT agreements needs to be signed. Includes creating new accounts.
7. **Off-boarding:**
   * Pre-planned. Plans decides what happens to hardware and the data. Account informations are usually deactivated but not always deleted.
8. **User traning:**
   * Gamification. CTFs. Phishing simulation. Computer-based training (CBT) - automated pre-built training, includes videos, audios, O\&As for all users to have same experience.
9. **Role-based security awarness training:**
   * Training users before providing access.
   * Specialized training for each user according to their roles.
   * Also applied to third-parties.
   * Detailed documentation for records.

### Third-party Risk Management

1. **Vendors:** Every organization works with vendors. Payroll, customer, relationship management, travel, raw materials.
   * Important data is often shared. Risk assessment is imporant.
   * Contracts of clear undersanding should be used.
2. **Supply Chain:** The system involved with creating a product. Involves organizations, people, activities, and recources.
   * Supply Chain Assessment:
     * Get a product or service from supplier to customer.
     * Evaluate coordination between groups.
     * Indentify areas of improvement.
     * Assess the IT systems supporting the operation.
     * Document the business process change.
3. **Business partner:** Much closer to data than vendor. May require direct access, therefore larger security concern.
   * Involves communication over a trusted connection. More difficult to monitor traffic.
   * Partner risk management should be involved.
   * Additional security between partners.
4. **Common agreement:**
   * Service Level Agreement (SLA): Minimum terms of service provied. Commonly used between customer and service provider.
   * Memorandum of Understanding (MOU): Both sides agree on the contents of memorandum. Statements of confidentiality. Informal letter of intent; not signed contract.
   * Measurement System Analysis (MSA): Used with quality management systems. Access the measurement process. Calculate measurement uncertanity.
   * Business Partnership Agreement (BPA): When going into business together. Decides owner stakes, financial contracts, decision-making agreement, prepare for contengencies.
5. **Product Support Lifetime:**
   * End of Life (EOL): Manufacturer stops selling product. MAY continue supporting product. Important for security updates and patches.
   * End of Service Life (EOSL): Manufacturer stops selling products and support is no longer available for the product. No ongoing security patches and updates. May continue on premium prices.
6. **Non-disclosure Agreement (NDA):** Confidential agreement between parties. Information in the agreement should not be disclosed.
   * Unilateral or bilateral (or multilateral) One way NDA or mutual NDA.
   * Formal contract where signature is usually required.

### Managing Data

1. **Data Governance:** Rules, processes, and accountability assosiated with an organization's data.
   * Data Steward: Manages the governance processes. Responsible for data accuracy, privacy, and security. Associate sensitive label to data and ensures complaice with any applicable laws and standards.
2. **Data Classification:** Identify data types: Personal, Public, Restricted, etc.
   * Associate governance controls to be classification levels. Then according to data classification, data steward puts label on it.
3. **Data Retention:** Keeps files that change frequently for version control.
   * Recover from virus infection.
   * Often legal requirements for data retention. Some data are required to be stored for a longer time like emails.

### Credential Policies

1. **Credential Management:**
   * Passwords must not be embedded in the application. Everything should reside on server.
   * Communication across the network should be encrypted.
2. **Personnel Accounts:** An account on a computer associated with a specific person. The computer associate the user with a specific identification number.
   * Storage and files can be private to that user, even if another person is using that computer.
   * Privileged access to the OS should be restricted, especially with user account.
3. **Third Party Accounts:** Access to external third party systems can come from anywhere. 2FA is must. Audit the security posture of third party. All users should have their own account.
4. **Device Accounts:** Access to devices - mobile devices.
   * Issue device certificate to restrict unknown devices to authenticate.
   * Require lock screen as a standard.
   * Manage devices using MDM.
   * Add additional security - geographical based, associate a device with a user.
5. **Service Accounts:** Usedf exclusively by services running on a computer.
   * No interactive/user access. Web server, db server..
   * Access can be defined for a specific service account.
   * Commonly uses usernames and passwords.
6. **Administrator/root accounts:** Elevated access to one or more systems. (super user access).
   * This account should not be used for normal administrations.
   * Needs to be highly secured.
   * Scheduled password changes.

### Organizational Policies

1. **Change Management:** How to make changes? Upgrade softwware, change firewall configuration, modufy switch ports.
   * Should have clear policies.
2. **Change Control:** The formal process of mamageing managing change.
   * Helps avoid downtime, confusion, and mistakes.
   * Determine the scope, analyze risks, create plan, get approvals, present propocal to control board, have a backout plan incase change does not work, document the changes.
3. **Asset Management:** Indentify and track computing assets, usually an automated process.
   * Helps responder faster to security problems. Keep an eye on most valuable assets.
   * Track licenses, amount of licenses in need.
   * Verify all devices are up to date including digital signatures and malware signatures.

### Risk Management Types

1. **Risk Management:** Identify assets that could be affected by an attack. Includes hardware, customer data, Intellectual property (IP).
   * Determine the level of risk - high, medium, low.
   * Make future security plans.
2. **Risk Assessment:**
   * External threats: outside the organization.
   * Internal threats: employees, partners, ex-employee.
   * Legacy Systems: outdated, older technlogies, that may not be supported by the manufacturer.
3. **Multi-party Risk:** Breach involving multiple parties. Often trusted business relationship. Events involve many different parties.
4. **Risk Assessment:**
   * Intellectual Property (IP): Theft of ideas, inventions, creative expressions.
   * Software compliance/licensing: Operational risk with too few license or financial riskl with too many. Legal risk if proper license is not followed.
5. **Risk Management Strategies:**
   * Acceptance: A business decision to take all risk.
     * XYZ is being attacked by phishers, it decided to rely on its anti-phishing software rather than training users.
   * Risk-avoidance: Stop participating in high-risk activity.
     * Stop using outdated technologies.
   * Transference: Buy some cybersecutiry insurance.
     * Which will help in financial crisis.
   * Mitigation: Decrease the risk level.
     * Investing in cybersecurity software, hardwares

### Risk Analysis

1. **Evaluating Risk:**
   * Risk Register: Indentifying and documenting risk associated with every step during builing a project.
   * Risk matrix/heat map: Viewing the result of risk asessment based on colour based visual chart, where likelihod and consequence of the risk is merged to find overall risk.
2. **Audit Risk Model:**
   * Inherent Risk: Impact + Likelihood. Risk that exists when security controls are NOT places.
   * Resisual Risk: Inherent risk + controll effectiveness. Risk that exists when security controls are in place.
   * Risk appetite: The amount of risk an organization is willing to take.
3. **Risk Control Assessment:** Controlling risks after creating heat maps.
   * Find the gap. Often formal audit. Self-assessment in smaller org.
   * Build and maintain security systems based on the requirements.
   * Determine if existing controls are compliant or non-compiant.
4. **Risk Awareness:** New risks are always emerging. Difficult to manage defence.
   * Knowledge is the key. Every employee's daily job role.
   * Maintaining awareness by ongoing group discussion, presenting law enforcement, attenting security conferences and programs.
5. **Regulations that affect risk posture:** Requires a minimum level of infosec
   * HIPPA: Health Insurance Portability and Accountability Act.
     * Privacy to patient records.
     * New storage requirements, network sec, protect against threats.
   * GDPR: General Data Protection Regulation.
     * EU data protection and privacy.
     * Personal data must be protected and managed for privacy.
6. **Qualitative Risk Management:** Indentify significant risk factors by asking opinions about the significance.
7. **Quantative Risk Assessment:**
   * ARO: Annualized Rate of Occurance - How likely hurricane will hit?
   * SLE: Single Loss Expectancy
     * Monetary loss of a single event.
   * ALE: Annualized Loss Expectancy
     * `ARO * SLE`
   * Business impact can be more than monetory. Qualitative vs quantative.
8. **Disaster Type:**
   * Envoirnmental threats: Tornado, hurricane, earthquake..
   * Person-made threats: Human intent, negligence, error, riots.
   * Internal and External

### Business Impact Analysis

1. **Recovery:**
   * Recovery Time Objective (RTO): Time to get up and running quickly.
   * Recovery Point Objective (RPO): Amount of data that is okay to be unavailable.
   * Mean Time To Repair (MTTR): Time required to fix issue after an outage..
   * Mean Time Before Failures (MTBF): If there is a failure, how long before next failure?
2. **Functional Recovery Plan:** Recovery from outage.
   * Step-by-step guides, contact infos, technical process, recover and test.
3. **Removing single point of failures:**
   * Network configs, facilities, utilities, people, location. Money drives redundancy.
4. **Disaster Recovery Plan (DRP):** Detailed plan for resuming operations after a disaster.
   * Extensive planning prior to disaster about backups, off-site data replication, cloud alternatives, remote site.
5. **Site risk assessment:**
   * All location are a bit different. Recovery plans should consider unique envoirnments - applications, personnel, equipment, work envoirnment.

### Privacy and Data Breaches

1. **Information life cycle:**
   * Creation of data internally or receive data from 3rd party.
   * Distribution - records are sorted and stored.
   * Use - for business decisions, product creation and services.
   * Maintenance - of outgoing data retrival and data transfers.
   * Disposition - Archiving or disposal of data.
2. **Consequences:**
   * Reputation damage, identity theft, fines for lawsuit settlement, Intellectual Property (IP) theft.
3. **Notification:**
   * Internal escalation process - breach is often found by technicans.
   * External escalation process - know when to ask for external assistance, from security experts.
   * Public notification and disclosures - delays might lead to criminal investigation.
4. **Privacy impact assessment (PIA):**
   * New business relationship, product updates, website features, service offering almost everything can affect privacy.
   * Privacy risk needs to be identifies in each initiative.
   * Advantages: fix privacy issue, avoid breach, shows imporance of privacy to everyone.
5. **Notices:**
   * Terms of service - terms of use, terms and conditions (T\&C).
   * A legal agreement between service provider and user.
   * Privacy notice, privacy policy. These may be required by the law.

### Data Classifications

1. **Labeling Sensitive Data:** Not all data has the same level of sensitivity. Different level requires different security and handling. _Ex: license tag number v/s health records._
2. **Data Classification:**
   * Proprietary: Data that is property of an organization. May include trade secrets, often data is unique to an organization.
   * PII: Personal Identifiable Information.
     * Data used to identify an individual.
     * Includes name, dob, biometric infos.
   * PHI: Protected Health Information.
     * Health insurance associated with an individual. Health status, health care records, payment for health care.
   * Public / Unclassified: No restrictions on viewing this data.
   * Private / Classified / Restricted / Internal Use Only:
     * Restricted access, may require NDA.
   * Sensitive: IP, PII, PHI
   * Confidential: Very sensitive, may be approved to view.
   * Critical: Data that should be available all the time.
   * Financial Information: Internal Company financial information, customer financial details.
   * Government data: Open data, transfer b/w govnt entities. May be protected by law.
   * Customer Data: Data associated with customers. May include user-specific details. Legal handling required.

### Enhancing Privacy

1. **Tokenization:** Replace sensitive data with non-sensitive data. Common with CC processing. This isn't encryption and no math is involved.
2. **Data Minimization:** Minimal Data Collection. HIPPA has a "Minimum Necessary" rule. GDPR - "Personal data shell be adequate, relevant and not excessive in relation to the purposeor purpose for which they are processed."
   * Some data may not be required and intenal data should be limited.
3. **Anonymization:** Make it impossible to identify individual data from a dataset. Allows for data use with privacy concern. Anonymization cannot be reversed.
4. **Data Masking:** Data obfuscation. May only be hidden from view. Detail might still be intact in storage. Different techniques are - substituting, shuffling, encrpytion, masking out, etc.
5. **Pseudo-anonymization:** Pseudonymization. Replace personal information with pseudonyms. Often used to maintain stastical relationship.
   * May be reversible.
   * Random Replacement: A --> B --> C --> D
   * Consistent Replacement: A --> B, and always will be B.

### Data Roles and Responsibilities

1. **Data Responsibility:**
   * Data Owner: Accountable for specific data, often a senior office.
     * VP of Sales owns customer relationship data.
     * Treasurer owns financial information.
2. **Data Roles:**
   * Data Controller: Manages the purpose and means by which personal data is procesed,
   * Data Processor: Processes data on behalf of the data controller. Often a third-party or different group.
   * Payroll controller and processor:
     * Payroll department (data controller) defines payroll amounts and timeframes.
     * Payroll company (data processor) processes payroll and stores employee information.
3. **Additional data roles:**
   * Data custodian/steward: Responsible for data accuracy, privacy, and security.
