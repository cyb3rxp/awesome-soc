# Awesome SOC
A collection of sources of documentation, and field best practices, to build and run a SOC (including CSIRT).

Those are my view, based on my own experience as SOC/CSIRT analyst and team manager, as well as well-known papers. Focus is more on SOC than on CERT/CSIRT.

My motto is: without reaction (response), detection is useless.

NB: Generally speaking, SOC here refers to detection activity, and CERT/CSIRT to incident response activity. CERT is a well-known (formerly) US trademark, run by [CERT-CC](https://www.sei.cmu.edu/about/divisions/cert/index.cfm), but I prefer the term [CSIRT](https://www.enisa.europa.eu/topics/incident-response).

# Table of Content
* [Must read](https://github.com/cyb3rxp/awesome-soc/blob/main/README.md#must-read)
* [Fundamental concepts](https://github.com/cyb3rxp/awesome-soc/blob/main/soc_basics.md)
* [Mission-critical means (tools/sensors)](https://github.com/cyb3rxp/awesome-soc/blob/main/README.md#mission-critical-means-toolssensors)
* [SOAR](https://github.com/cyb3rxp/awesome-soc/blob/main/README.md#soar)
* [IT/security Watch](https://github.com/cyb3rxp/awesome-soc/blob/main/README.md#itsecurity-watch-recommended-sources)
* [Detection engineering](https://github.com/cyb3rxp/awesome-soc/blob/main/detection_engineering.md)
* [Threat intelligence](https://github.com/cyb3rxp/awesome-soc/blob/main/threat_intelligence.md)
* [Management](https://github.com/cyb3rxp/awesome-soc/blob/main/management.md)
* [HR and training](https://github.com/cyb3rxp/awesome-soc/blob/main/hr_training.md)
* [IT achitecture](https://github.com/cyb3rxp/awesome-soc/blob/main/README.md#it-achitecture)
* [To go further (next steps)](https://github.com/cyb3rxp/awesome-soc/blob/main/README.md#to-go-further)
* [Appendix](https://github.com/cyb3rxp/awesome-soc/blob/main/README.md#appendix)

# Must read

## For a SOC
* MITRE, [11 strategies for a world-class SOC](https://www.mitre.org/publications/technical-papers/11-strategies-world-class-cybersecurity-operations-center) (or use [local file](https://github.com/cyb3rxp/awesome-soc/blob/main/11-strategies-of-a-world-class-cybersecurity-operations-center.pdf)): part 0 (Fundamentals).
* CMM, [SOC-CMM](https://www.soc-cmm.com/)
* LetsDefend [SOC analyst interview questions](https://github.com/LetsDefend/SOC-Interview-Questions)
* FIRST, [Building a SOC](https://www.first.org/resources/guides/Factsheet_Building_a_SOC_start_small.pdf) 
* Gartner, [SOC model guide](https://www.gartner.com/doc/reprints?id=1-2C6FPM26&ct=230103&st=sb)
* NCSC, [Building a SOC](https://www.ncsc.gov.uk/collection/building-a-security-operations-centre)
* Splunk, [State of Security 2023](https://www.splunk.com/en_us/pdfs/gated/ebooks/state-of-security-2023.pdf) 
* Rabobank CDC, [DeTTECT](https://github.com/rabobank-cdc/DeTTECT)


## For a CERT/CSIRT
* FIRST, [CERT-in-a-box](https://www.first.org/resources/guides/cert-in-a-box.zip) 
* FIRST, [CSIRT Services Framework](https://www.first.org/standards/frameworks/csirts/csirt_services_framework_v2.1)
* ENISA, [Good practice for incident management](https://www.enisa.europa.eu/publications/good-practice-guide-for-incident-management)
* EE-ISAC [Incident Response whitepaper](https://www.ee-isac.eu/comp/uploads/2020/12/EE-ISAC-Incident-Response-White-Paper-1.pdf)
* NIST, [SP800-86, integration forensics techniques into IR](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-86.pdf)
* Microsoft/EY/Edelman, [Incident response reference guide](https://www.linkedin.com/posts/the-cyber-security-hub_incident-response-reference-guide-activity-7033563558642642944-0zav?utm_source=share&utm_medium=member_desktop)



## Globally (SOC and CERT/CSIRT)
* Shubham, [Security 360](https://twitter.com/Shubham_pen/status/1655192003448020993?s=20)
* NIST, [Cybersecurity framework](https://www.nist.gov/cyberframework)
* ENISA, [How to set-up a CSIRT and SOC](https://www.enisa.europa.eu/publications/how-to-set-up-csirt-and-soc/at_download/fullReport)
* NIST, [SP800-61 rev2, incident handling guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final) 
* MITRE, [ATT&CK: Getting started](https://attack.mitre.org/resources/getting-started/)
* Purp1eW0lf, [Blue Team Notes](https://github.com/Purp1eW0lf/Blue-Team-Notes)
* ThreatConnect, [SIRP / SOA / TIP benefits](https://threatconnect.com/blog/realizing-the-benefits-of-security-orchestration-automation-and-response-soar/)
* Gartner, [Market Guide for Security Orchestration, Automation and Response Solutions](https://www.gartner.com/doc/reprints?id=1-2ADE1K2G&ct=220621&st=sb) 
* PAN, [Security orchestration for dummies](https://www.paloaltonetworks.com/content/dam/pan/en_US/assets/pdf/cortex-xsoar/Security-Orchestration-For-Dummies-Demisto-Special-Edition.pdf)
* FIRST, [CVSS v3.1 specs](https://www.first.org/cvss/specification-document) 
* OASIS Open, [STIX](https://oasis-open.github.io/cti-documentation/stix/intro.html)
* FIRST, [TLP](https://www.first.org/tlp/) (intelligence sharing and confidentiality)
* CIS, [18 critical security controls](https://www.cisecurity.org/controls/cis-controls-list)
* Gartner, [Cybersecurity business value benchmark](https://emtemp.gcom.cloud/ngw/globalassets/en/doc/documents/775537-gartner-cybersecurity-business-value-benchmark-1st-generation.pdf)
* CyberArk: [NIS2, how to address the security control gaps](https://event.on24.com/eventRegistration/console/apollox/mainEvent?simulive=y&eventid=4110743&sessionid=1&username=&partnerref=&format=fhvideo1&mobile=&flashsupportedmobiledevice=&helpcenter=&key=588150776CAE70D7F02ECF2848FF11FA&newConsole=true&nxChe=true&newTabCon=true&consoleEarEventConsole=false&text_language_id=en&playerwidth=748&playerheight=526&eventuserid=600843623&contenttype=A&mediametricsessionid=517006274&mediametricid=5797475&usercd=600843623&mode=launch)


# Fundamental concepts

## Concepts, tools, missions, attack lifecycle, red/blue/purple teams
See: [SOC/CSIRT Basic and fundamental concepts](https://github.com/cyb3rxp/awesome-soc/blob/main/soc_basics.md).

## SOC and CSIRT core

### From logs to alerts: global generic workflow

Quoted from [this article](https://www.managedsentinel.com/siem-traditional-vs-cloud/):

![image](https://user-images.githubusercontent.com/16035152/206025151-759a0040-365e-4145-aa88-f7a7b737f8be.png)

Following the arrows, we go from log data sources to data management layer, to then data enrichment layer (where detection happens), to end-up in behavior analytics or at user interaction layer (alerts, threat hunting...). All of that being enabled and supported by automation.


### SOC/CSIRT architecture of detection
Based on [CYRAIL's paper drawing](https://slideplayer.com/slide/15779727/), that I've slightly modified, here is an example of architecture of detection (SIEM, SIRP, TIP interconnections) and workflow:
![image](https://user-images.githubusercontent.com/16035152/207597681-22c9da6d-d430-4660-b807-3e86138a0d9c.png)

* Sensors log sources are likely to be: audit logs, security sensors (antimalware, FW, NIDS, proxies, EDR, NDR, CASB, identity threat detection, honeypot...).



# Mission-critical means (tools/sensors)

## Critical tools for a SOC/CSIRT
* **[SIEM](https://www.gartner.com/en/information-technology/glossary/security-information-and-event-management-siem)**:
   * See [Gartner magic quadrant](https://www.gartner.com/doc/reprints?id=1-2BDC4CDW&ct=221010&st=sb) 
   * My recommendations: [Microsoft Azure Sentinel](https://azure.microsoft.com/en-us/products/microsoft-sentinel/#overview), [Sekoia.io XDR](https://www.sekoia.io/en/sekoia-io-xdr/), [Splunk](www.splunk.com).
* **[SIRP](https://d3security.com/blog/whats-the-difference-between-soar-and-sao/)**:
  * e.g.: [IBM Resilient](https://www.ibm.com/qradar/security-qradar-soar?utm_content=SRCWW&p1=Search&p4=43700068028974608&p5=e&gclid=Cj0KCQjw9ZGYBhCEARIsAEUXITW2yUqAfNqWNeYXyENeUAoqLxV543LT0n2oYhYxEQ47Yjm7NfYTFHAaAtwpEALw_wcB&gclsrc=aw.ds),  [TheHive](https://thehive-project.org/), [SwimLane](https://swimlane.com/), [PAN Cortex XSOAR](https://www.paloaltonetworks.com/cortex/cortex-xsoar)
  * My recommendations:  [TheHive](https://thehive-project.org/), [PAN Cortex XSOAR](https://www.paloaltonetworks.com/cortex/cortex-xsoar)
* **[SOA](https://d3security.com/blog/whats-the-difference-between-soar-and-sao/)**:
  * e.g.: [IBM Resilient]( https://www.ibm.com/qradar/security-qradar-soar?utm_content=SRCWW&p1=Search&p4=43700068028974608&p5=e&gclid=Cj0KCQjw9ZGYBhCEARIsAEUXITW2yUqAfNqWNeYXyENeUAoqLxV543LT0n2oYhYxEQ47Yjm7NfYTFHAaAtwpEALw_wcB&gclsrc=aw.ds), [SwimLane](https://swimlane.com/), [TheHive](https://thehive-project.org/), [PAN Cortex XSOAR](https://www.paloaltonetworks.com/cortex/cortex-xsoar), [Microsoft Logic Apps](https://learn.microsoft.com/en-us/azure/logic-apps/logic-apps-overview)
  * My recommendations: [SwimLane](https://swimlane.com/), [TheHive](https://thehive-project.org/), [PAN Cortex XSOAR](https://www.paloaltonetworks.com/cortex/cortex-xsoar) 
* **[TIP](https://www.ssi.gouv.fr/en/actualite/opencti-the-open-source-solution-for-processing-and-sharing-threat-intelligence-knowledge/)**:
   * See [Threat intel page](https://github.com/cyb3rxp/awesome-soc/blob/main/threat_intelligence.md) 
     

## Critical sensors for a SOC

* **Antimalware**:
  * See [Gartner magic quadrant](https://www.threatscape.com/microsoft-security-named-leader-in-4-gartner-magic-quadrants/) 
  * My recommendations: [Microsoft Defender](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/microsoft-defender-antivirus-windows?view=o365-worldwide), [ESET Nod32](https://www.eset.com/int/business/solutions/learn-more-about-endpoint-protection/), [BitDefender](https://www.bitdefender.fr/business/products/workstation-security.html).
* **[Endpoint Detection and Response](https://www.gartner.com/reviews/market/endpoint-detection-and-response-solutions)**:
  * See [Gartner magic quadrant](https://www.microsoft.com/security/blog/uploads/securityprod/2022/01/Gartner-EIA-1963x2048.png) and [MITRE ENGENUITY](https://www.cybervigilance.uk/post/2022-mitre-att-ck-engenuity-results)
  * My recommendations: [SentinelOne](https://www.sentinelone.com/blog/active-edr-feature-spotlight/), [Microsoft Defender for Endpoint](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/microsoft-defender-endpoint?view=o365-worldwide), [Harfanglab](https://www.harfanglab.io/en/block-cyberattacks), [ESET XDR](https://www.eset.com/int/business/enterprise-protection-bundle/), [WithSecure Elements EDR](https://www.withsecure.com/us-en/solutions/software-and-services/elements-endpoint-detection-and-response), [CrowdStrike Falcon EDR](https://www.crowdstrike.com/wp-content/uploads/2022/03/crowdstrike-falcon-insight-data-sheet.pdf), [Tanium](https://www.tanium.com/products/tanium-threat-response/), [Wazuh](https://wazuh.com/)
* **[Secure Email Gateway](https://www.gartner.com/reviews/market/email-security)** (SEG):
  * See [Gartner reviews and ratings](https://www.gartner.com/reviews/market/email-security)
  * My recommendations: [Microsoft Defender for Office365](https://www.microsoft.com/en-us/security/business/siem-and-xdr/microsoft-defender-office-365), [ProofPoint](https://www.proofpoint.com/fr/threat-reference/email-gateway), [Mimecast](https://www.mimecast.com/products/email-security/secure-email-gateway/)
* **[Secure Web Gateway](https://www.gartner.com/en/information-technology/glossary/secure-web-gateway)** (SWG) / Security Service Edge:
  * see [Gartner magic quadrant](https://www.zscaler.fr/cdn-cgi/image/format%3Dauto/sites/default/files/images/page/gartner-magic-quadrant-security-service-edge-sse-2022/zscaler-gartner-sse-2022-%401x.png) 
  * My recommendations: BlueCoat, CISCO, Zscaler, [Netskope](https://www.netskope.com/security-defined/what-is-casb).
* **[Identity Threat Detection and Response](https://www.semperis.com/blog/what-organizations-want-from-expert-itdr-solutions/)** **(ITDR)** for identity and AD/AAD security (audit logs, or specific security monitoring solutions):
  * My recommendations: [Semperis Directory Services Protector](https://www.semperis.com/active-directory-security/)
  * for a one-shot security assessment of AD, I recommend: [Semperis](https://www.purple-knight.com/fr/?utm_source=gads&utm_medium=paidsearch&utm_campaign=pk_emea&gclid=Cj0KCQjw9ZGYBhCEARIsAEUXITV3yX7Nn6_GR-YVwiOANFvS9wsEQdTyUGHvMMirMzNQEoQ1Q3EQYIMaAjTgEALw_wcB)  or [PingCastle](https://www.pingcastle.com/download/)
* **EASM**: External Asset Security Monitoring / External Attack Surface Management:
  * My recommendations: [Intrinsec (in French)](https://www.intrinsec.com/monitoring-cyber/), [Mandiant](https://www.mandiant.fr/advantage/attack-surface-management), [Microsoft EASM](https://learn.microsoft.com/en-us/azure/external-attack-surface-management/)
  * for a security check-up:
     * quick security assessment of your website: [ImmuniWeb](https://www.immuniweb.com/websec/)
     * AWS/Azure/GCP security assessment (community tool): [ScootSuite](https://github.com/nccgroup/ScoutSuite)
* **CASB**: [Cloud Access Security Broker](https://www.gartner.com/en/information-technology/glossary/cloud-access-security-brokers-casbs), if company's IT environment uses a lot of external services like SaaS/IaaS:
   * See [Gartner magic quadrant](https://www.netskope.com/wp-content/uploads/2021/01/Screen-Shot-2021-01-05-at-10.15.23-AM-1024x456.png)
   * My recommendations: [Microsoft MCAS](https://www.microsoft.com/en-us/security/business/siem-and-xdr/microsoft-defender-cloud-apps), [Zscaler](https://info.zscaler.com/resources-white-papers-data-protection-challenges?_bt=534426399999&_bk=%2Bzscaler%20%2Bcasb&_bm=b&_bn=g&_bg=121807608181&utm_source=google&utm_medium=cpc&utm_campaign=google-ads-na&gclid=CjwKCAjwu5yYBhAjEiwAKXk_eKLlKaMfJ-oGYItPTHguAmCA_b9WP0zNZgLPqGKjfC19IGmQFFG_9RoCgJAQAvD_BwE), [Netskope](https://www.netskope.com/security-defined/what-is-casb).
 * **Deceptive technology:**
    * My recommendation: implement [AD decoy acounts](https://medium.com/securonix-tech-blog/detecting-ldap-enumeration-and-bloodhound-s-sharphound-collector-using-active-directory-decoys-dfc840f2f644) and [AD DNS canary](https://www.protect.airbus.com/blog/active-directory-a-canary-under-your-hat/)
   

## Critical tools for CSIRT
* On-demand volatile data collection tool:
  * My recommendations: [VARC](https://github.com/cado-security/varc), [DFIR-ORC](https://github.com/dfir-orc), [FireEye Redline](https://fireeye.market/apps/211364), [ESET Sysinspector](https://www.eset.com/int/support/sysinspector/).
* Remote action capable tools (ie.: remote shell or equivalent):
  * My recommendations: [CIMSweep](https://github.com/mattifestation/CimSweep), [Velociraptor](https://docs.velociraptor.app/docs/deployment/), [CrowdStrike Falcon Toolkit](https://github.com/CrowdStrike/Falcon-Toolkit) but it relies on CrowdStrike EDR, [GRR](https://github.com/google/grr) but it needs an agent to be installed.
* On-demand sandbox:
  * My recommendations for online ones: [Joe's sandbox](https://www.joesandbox.com/#windows), [Hybrid Analysis](https://www.hybrid-analysis.com/), etc;
  * My recommendation for local one: Windows 10 native Sandbox, with [automation](https://megamorf.gitlab.io/2020/07/19/automating-the-windows-sandbox/).
* Forensics and reverse-engineering tools suite:
  * My recommendations: [SIFT Workstation](https://www.sans.org/tools/sift-workstation/), or [Tsurugi](https://tsurugi-linux.org/)
  * My recommendation for reverse engineering and malware analysis, under Windows: [FireEye Flare-VM](https://github.com/mandiant/flare-vm)
  * My recommendation for pure malware analysis, under Linux: [Remnux](https://remnux.org/)
* Incident tracker: 
  * My recommendation: [Timesketch](https://timesketch.org/)
* Scanners:
  * IOC scanners:
    * My recommendations: [Loki](https://github.com/Neo23x0/Loki), [DFIR-ORC](https://github.com/dfir-orc)
* Log scanners: [CrowdSec](https://doc.crowdsec.net/docs/user_guides/replay_mode), [DeepBlue](https://github.com/sans-blue-team/DeepBlueCLI)
  * Offline antimalware scanners: 
    * My recommendation: [Windows Defender Offline](https://support.microsoft.com/en-us/windows/help-protect-my-pc-with-microsoft-defender-offline-9306d528-64bf-4668-5b80-ff533f183d6c), [ESET SysRecue](https://www.eset.com/int/support/sysrescue/)
  * IOC repos for scanners:
    * Google [CTI's repo](https://github.com/chronicle/GCTI/tree/main/YARA): Yara rules for Cobalt Strike and others.
    * [Yara-rules GitHub repo](https://github.com/Yara-Rules/rules): multiple Yara rules types.
    * Spectre [Yara rules repo](https://github.com/phbiohazard/Yara)
    * Neo23x0 [Community Yara rules](https://github.com/Neo23x0/signature-base)
    * and those listed here, [Awesome threat intel](https://github.com/hslatman/awesome-threat-intelligence)
    
## Other critical tools for a SOC and a CERT/CSIRT
* Internal ticketing system (NB: **not** SIRP, not for incident response!):
  * My recommendation: [GitLab](https://about.gitlab.com/handbook/engineering/security/security-operations/sirt/sec-incident-response.html)
* Knowledge sharing and management tool:
  * My recommendations: [Microsoft SharePoint](https://www.microsoft.com/en-us/microsoft-365/sharepoint/collaboration), Wiki (choose the one you prefer, or [use GitLab as a Wiki](https://docs.gitlab.com/ee/user/project/wiki/)).
* Vizualization tool for OSINT search and IOC:
  * My recommendation: [OSINTracker](https://app.osintracker.com/)


# SOAR

## What is SOAR?

As per [Gartner definition](https://securityboulevard.com/2021/08/gartner-soar-magic-quadrant-when-where-and-how/):

![image](https://user-images.githubusercontent.com/16035152/186781422-ebb3996a-da66-4d27-a55f-6065fa84fca5.png)

Hence 3 critical tools (see above): SIRP, TIP, SOA, on top of SIEM.

And in my view, SOAR is more an approach, a vision, based on technology and processes, than a technology or tool per say. 


## Simple and commonly needed automation tools

* Online automated hash checker (script):
  * my recommendation: [Munin](https://github.com/Neo23x0/munin), or with PowerShell [Posh-VT](https://github.com/darkoperator/Posh-VirusTotal)

* Online URL automated analysis:
  * my recommendation: [CyberGordon](https://cybergordon.com/), [URLScan.io](https://urlscan.io/)

* Online automated sample analyzer:
  * my recommendation, via script and without sample submission: [Malwoverview](https://github.com/alexandreborges/malwoverview);
  * my recommendations for online dynamic analysis: [Hybrid-Analysis](https://www.hybrid-analysis.com/), [Joe's sandbox](https://www.joesandbox.com/#windows)

* (pure) Windows tasks automation:
  * My recommendations: [AutoIT](https://www.autoitscript.com/site/), [Chocolatey](https://chocolatey.org/)

* SaaS-based (and partly free, for basic stuff) SOA:
  * [Shuffle](https://shuffler.io/)

## Common automations

### My recommendations for detection (alerts handling):

Try to implement at least the following automations, leveraging the SOA/SIRP/TIP/SIEM capabilities:
* Make sure all the context from any alert is being automatically transfered to the SIRP ticket, with a link to the SIEM alert(s) in case of.
  * Leverage API (through SOA) if needed to retrieve the missing context info, when using built-in integrations.
* Automatically query the TIP for any artefacts or even IOC that is associated to a SIRP ticket.
* Automatically retrieve the history of antimalware detections for an user and/or endpoint, that is associated to a SIRP ticket.
* Automatically retrieve the history of SIEM detections for an user and/or endpoint, that is associated to a SIRP ticket.
* Automatically retrieve the history of SIRP tickets for an user and/or endpoint, that is associated to a new SIRP ticket.
* Automatically query AD or the assets management solution, for artefact enrichment (user, endpoint, IP, application, etc.).

### My recommendations for response (incident response, containment/eradication steps):
* Block an IP on all firewalls (including VPN), SWG and CASB.
* Block an URL on SWG. 
* Block an email address (sender) on SEG.
* Block an exe file (by hash) on endpoints (leveraging antimalware/EDR or AppLocker).
* Block an exe file (by hash) on gateways and CASB: SWG, SEG, CASB.
* Reset an AD account password.
* Disable an AD account (both user and computer, since computer account disabling will block authentication with any AD account on the endpoint, thus preventing from lateral movement or priv escalation).
* Report a (undetected) sample to security vendors, via email. Here are a few addresses, in case of: 
  * Files samples (to be attached in a password-protected Zip file, with 'infected' as password): samples@eset.com, newvirus@kaspersky.com, report@sentinelone.com, virus_submission@bitdefender.com, vsamples@f-secure.com, virus_malware@avira.com, submitvirus@fortinet.com, virus_research@avertlabs.com, virus_doctor@trendmicro.com
  * URL/IP samples: samples@eset.com, samples@kaspersky.com, report@sentinelone.com, virus_submission@bitdefender.com, vsamples@f-secure.com, phish@office365.microsoft.com, report@openphish.com, reportphishing@apple.com, abuse@clean-mx.de, datasubmission@mcafee.com
* Report a false positive to security vendors, via email;
  * You may want to have a look at [this page](https://github.com/yaronelh/False-Positive-Center) to know the required email address.
* Report a malicious URL (for instance, phishing) to a security vendor for takedown steps
  * My recommendation: [Netcraft](https://www.netcraft.com/cybercrime/) [via API](https://report.netcraft.com/api/v3), or [PhishReport](https://phish.report/docs).
* Block an IP address on web servers, linux firewalls, etc. based on community-driven CTI:
  * My recommendation: [CrowdSec bouncer](https://www.crowdsec.net/blog/crowdsec-not-your-typical-fail2ban-clone)
  



# IT/security Watch (recommended sources)

* SIEM rules publications:
  * [Sigma HQ (detection rules)](https://github.com/SigmaHQ/sigma/tree/master/rules) 
  * [Splunk Security content (free detection rules for Splunk)](https://research.splunk.com/) 
  * [SOC Prime](https://tdm.socprime.com/)
  * [Michel De Crevoisier's Git](https://github.com/mdecrevoisier/SIGMA-detection-rules)
* Known exploited vulnerabilities: 
  * [CISA catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  * [CVETrends](https://cvetrends.com/)
* LinkedIn / Twitter:
  * e.g.: [LinkedIn Information Security Community group](https://www.linkedin.com/groups/38412/) 
* RSS reader/portal:
  * e.g.: [Netvibes](https://www.netvibes.com/phvialle?page=phvialle#Security)  
* Government CERT, industry sector related CERT...
  * e.g.: [CERT-FR](https://www.cert.ssi.gouv.fr/avis/), [CERT-US](https://www.cisa.gov/uscert/ncas/alerts)
* Other interesting websites:
  * e.g.: [ISC](https://isc.sans.edu/), [ENISA](https://www.enisa.europa.eu/publications), [ThreatPost](https://threatpost.com/) ...


# Detection engineering

Cf. [detection engineering page](https://github.com/cyb3rxp/awesome-soc/blob/main/detection_engineering.md).

# Threat intelligence

Cf. [threat intelligence page](https://github.com/cyb3rxp/awesome-soc/blob/main/threat_intelligence.md).

# Management

Cf. [management page](https://github.com/cyb3rxp/awesome-soc/blob/main/management.md).


# HR and training

Cf. [HR and training page](https://github.com/cyb3rxp/awesome-soc/blob/main/hr_training.md).


# IT achitecture

## Have a single and centralized platform ('single console')

As per [NCSC website](https://www.ncsc.gov.uk/collection/building-a-security-operations-centre/detection/detection-practices#section_2):
> Indications of an attack will rarely be isolated events on a single system component or system. So, where possible, having a single platform where analysts have the ability to see and query log data from all of your onboarded systems is invaluable.
> Having access to the log data from multiple (or all) components, will enable analysts to look for evidence of attack across an estate and create detection use-cases that utilise a multitude of sources.
> By creating temporal (actions over a period of time) and spatial (actions across the estate) use-cases, an organisation is better prepared to address cyber security attacks that occur system wide.



## Disconnect (as much as possible) SOC from monitored environment

The goal is to prevent an attacker from achieving lateral movement from a compromised monitored zone, to the SOC/CSIRT work zone.

### Enclave: 
* Implement SOC enclave (with network isolation), as per MITRE paper drawing:
![image](https://user-images.githubusercontent.com/16035152/186420265-4c0275b2-d70e-4fec-936c-712c1c4802a8.png)

* only log collectors and WEF should be authorized to send data to the SOC/CSIRT enclave. Whenever possible, the SOC tools pull the data from the monitored environment, and not the contrary;

* on top of a SOC enclave, implement at least a [level 2 of network segmentation](https://github.com/sergiomarotco/Network-segmentation-cheat-sheet#level-2-of-network-segmentation-adoption-of-basic-security-practices);

SOC’s assets should be part of a separate [restricted AD forest](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/forest-design-models ), to allow AD isolation with the rest of the monitored AD domains. 


### Endpoints hardening:

* SOC/CSIRT's endpoints should be hardened with relevant guidelines;
   * My recommendations: [CIS benchmarks](https://www.cisecurity.org/cis-benchmarks/), [Microsoft Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319)


# To go further

## Must read
* MITRE, [11 strategies for a world-class SOC (remaining of PDF)](https://www.mitre.org/publications/technical-papers/11-strategies-world-class-cybersecurity-operations-center) 
* CISA, [Cyber Defense Incident Responder role](https://www.cisa.gov/cyber-defense-incident-responder)
* FireEye, [Purple Team Assessment](https://www.fireeye.fr/content/dam/fireeye-www/regional/fr_FR/services/pdfs/ds-purple-team-assessment.pdf)
*	Kaspersky, [AV / EP / EPP / EDR / XDR](https://usa.kaspersky.com/blog/introducing-kedr-optimum/27062/?reseller=usa_regular-sm_acq_ona_smm__onl_b2c_lii_post_sm-team______&utm_source=linkedin&utm_medium=social&utm_campaign=us_regular-sm_en0177&utm_content=sm-post&utm_term=us_linkedin_organic_pmgk1776sk4g1qp)
* Wavestone, [Security bastion (PAM) and Active Directory tiering mode: how to reconcile the two paradigms?](https://www.riskinsight-wavestone.com/en/2022/10/security-bastion-pam-and-active-directory-tiering-mode-how-to-reconcile-the-two-paradigms/)
* MalAPI, [list of Windows API and their potential use in offensive security](https://malapi.io/)
*	FireEye, [OpenIOC format](https://github.com/fireeye/OpenIOC_1.1/blob/master/IOC_Terms_Defs.md)
* Herman Slatman, [Awesome Threat Intel](https://github.com/hslatman/awesome-threat-intelligence)
*	Microsoft, [SOC/IR hierarchy of needs](https://github.com/swannman/ircapabilities) 
* Betaalvereniging, [TaHiTI (threat hunting methodology)](https://www.betaalvereniging.nl/wp-content/uploads/TaHiTI-Threat-Hunting-Methodology-whitepaper.pdf) 
* ANSSI (FR), [EBIOS RM methodology](https://www.ssi.gouv.fr/guide/ebios-risk-manager-the-method/)
* GMU, [Improving Social Maturity of Cybersecurity Incident Response Teams](https://edu.anarcho-copy.org/Against%20Security%20-%20Self%20Security/GMU_Cybersecurity_Incident_Response_Team_social_maturity_handbook.pdf)
* J0hnbX, [RedTeam resources](https://github.com/J0hnbX/RedTeam-Resources)
* Fabacab, [Awesome CyberSecurity BlueTeam](https://github.com/fabacab/awesome-cybersecurity-blueteam)
* Microsoft, [Windows 10 and Windows Server 2016 security auditing and monitoring reference](https://www.microsoft.com/en-us/download/details.aspx?id=52630).
* iDNA, [how to mange FP in a SOC?](https://www.idna.fr/2018/11/06/comment-gerer-les-faux-positifs-dans-un-soc/), in FR
* Soufiane Tahiri, [Playbook for ransomware incident response](https://github.com/soufianetahiri/ransomware_Incident_Response_FR), in FR
* PwnDefend, [AD post-compromise checklist](https://www.pwndefend.com/2021/09/15/post-compromise-active-directory-checklist/)
* Gartner, [Market guide for NDR](https://www.gartner.com/doc/reprints?id=1-2C26GPJO&ct=221220&st=sb&utm_campaign=23Q1%20-%20%5BP%5D%20-%20WW%20-%20DR%20-%20Gartner%20Market%20Guide%202022%20for%20NDR&utm_medium=email&_hsmi=238503267&_hsenc=p2ANqtz-8wHF9sVJ7vVNCjT-uxGc2EkfHf_7Rjj3PYQd1AhWkwv-bluEqKKFV_xfeZqdU2sHYMtuximF-J33CBTSwyutZIjcOd5SKywiV6HGRCfolqm1Pg9pU&utm_content=238503267&utm_source=hs_automation)
* Rawsec, [Resources inventory](https://inventory.raw.pm/resources.html)
* Quest, [Best practices for AD disaster recovery](https://www.quest.com/webcast-ondemandt/best-practices-for-active-directory-disaster-recovery/?param=L4qcdiH1R46lWbN5Jxs%2fNN0Qky57LDYQTnsyaoWVqKYZTocd3n1RpFTyQegqps0MbW7yx4UWSKyVRVyz%2bwo0XRB2%2fXpFzrMZeOA%2fne%2f4Fm3oH5YJAnFCP%2fnRqs9Rq%2fRD0VTXvdBaojCx5J46htyILvanM5FhOVa7MCGDGYBcq6925YtpmANy9OA1%2fjdtlDrp)
* Microsoft, [Isolate Tier 0 assets with group policy](https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/initially-isolate-tier-0-assets-with-group-policy-to-start/ba-p/1184934)
* Securenvoy, [How to be compliant with NIS2?](https://securenvoy.com/blog/how-to-be-compliant-with-new-nis-directive/)



## Nice to read
* NIST, [SP800-53 rev5 (Security and Privacy Controls for Information Systems and Organizations)](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
* Amazon,	[AWS Security Fundamentals](https://aws.amazon.com/fr/training/digital/aws-security-fundamentals/)   
* Microsoft, [PAW Microsoft](https://docs.microsoft.com/en-us/security/compass/privileged-access-devices) 
* CIS, [Business Impact Assessment](https://bia.cisecurity.org/) 
* Abdessabour Boukari, [RACI template (in French)](https://github.com/cyberabdou/SOC/blob/77f01ba82c22cb11028cde4a862ae0bea4258378/SOC%20RACI.xlsx) 
* Trellix, [XDR Gartner market guide](https://www.trellix.com/fr-fr/solutions/gartner-report-market-guide-xdr.html)
* Elastic, [BEATS agents](https://www.elastic.co/beats/)
* [V1D1AN's Drawing: architecture of detection](https://github.com/V1D1AN/S1EM/wiki/Architecture-guide#the-architecture-of-detection),
* [RFC2350](https://www.cert.ssi.gouv.fr/uploads/CERT-FR_RFC2350_EN.pdf) (CERT description)
* [Awesome Security Resources](https://github.com/Johnson90512/Awesome-Security-Resources)
* [Incident Response & Computer Forensics, 3rd ed](https://www.google.fr/books/edition/Incident_Response_Computer_Forensics_Thi/LuWINQEACAAJ?hl=fr)
* [GDPR cybersecurity implications (in French)](https://atelier-rgpd.cnil.fr/) 
* [SANS SOC survey 2022](https://www.splunk.com/en_us/pdfs/resources/whitepaper/sans-soc-survey-2022.pdf)
* Soufiane Tahiri, [Digital Forensocs Incident Response Git](https://github.com/soufianetahiri/Digital-Forensics-Incident-Response)
* [Austin Songer](https://github.com/austinsonger/Incident-Playbook)
* CISA, [Cybersecurity incident and vulnerability response playbooks](https://www.cisa.gov/sites/default/files/publications/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf)
* Reprise99, [Microsoft Sentinel queries](https://github.com/reprise99/Sentinel-Queries)
* MyFaberSecurity, [MS Sentinel architecture and recommendations for MSSP](https://myfabersecurity.com/2023/03/31/sentinel-poc-architecture-and-recommendations-for-mssps-part-1/)
* Gartner, [PAM Magic Quadrant reprint](https://www.gartner.com/doc/reprints?id=1-2AMZ88JO&ct=220721&st=sb)
* Rawsec, [Tools inventory](https://inventory.raw.pm/tools.html)
* Microsoft, [command line reference](https://cmd.ms/)
* [SOCTOM](https://soc-cmm.com/downloads/SOCTOM%20whitepaper.pdf)


## SOC sensors, nice to have
* (full-featured) Honeypot:
  * My recommendation: [Canary.tools](https://canary.tools/)
  * Or, have a look at (Awesome honeypots Git](https://github.com/paralax/awesome-honeypots)
* NIDS:
  * My recommendation: [Crowdsec](https://www.crowdsec.net/product/crowdsec-security-engine)
* Phishing and brand infringement protection (domain names):
  * My recommendation: [PhishLabs](https://www.phishlabs.com/), [Netcraft](https://www.netcraft.com/cybercrime/fraud-detection/)
* NDR:
  * My recommendation: [Gatewatcher](https://www.gatewatcher.com/en/our-solutions/trackwatch/)
* MDM:
  * My recommendation: [Microsoft Intune](https://docs.microsoft.com/en-us/mem/intune/fundamentals/what-is-intune)
* DLP:
  * See [Gartner reviews and ratings](https://www.gartner.com/reviews/market/data-loss-prevention)
* OT (industrial) NIDS:
  * My recommendation: [Nozomi Guardian](https://www.nozominetworks.com/products/guardian/)
* Network TAP:
  * My recommendation: [Gigamon](https://www.gigamon.com/products/access-traffic/network-taps.html)
* Mobile network security (2G/3G):
  * My recommendation: Dust Mobile.


## Harden SOC/CSIRT environment
* Implement hardening measures on SOC workstations, servers, and IT services that are used (if possible).
   * e.g.: [CIS](https://www.cisecurity.org/), [Microsoft Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319)
* Put the SOC assets in a separate AD forest, as [forest is the AD security boundary](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-firewall/gathering-information-about-your-active-directory-deployment), for isolation purposes, in case of a global enterprise's IT compromise
* Create/provide a disaster recovery plan for the SOC assets and resources.
* Implement admin bastions and silo to administrate the SOC env (equipments, servers, endpoints):
  * My advice: consider the SOC environment as to be administrated by **Tier 1**, if possible with a dedicated admin bastion. Here is a generic drawing from Wavestone's article (see Must read references): ![image](https://user-images.githubusercontent.com/16035152/202517740-812091b6-ff31-49cd-941e-3f6e4b4d140c.png)
  * Recommended technology choices: [Wallix PAM](https://www.wallix.com/privileged-access-management/)
  * Implement a [level 3 of network segmentation](https://github.com/sergiomarotco/Network-segmentation-cheat-sheet#level-3-of-network-segmentation-high-adoption-of-security-practices)


# Appendix

## License
[CC-BY-SA](https://en.wikipedia.org/wiki/Creative_Commons_license)

## Special thanks
Yann F., Wojtek S., Nicolas R., Clément G., Alexandre C., Jean B., Frédérique B., Pierre d'H., Julien C., Hamdi C., Fabien L., Michel de C., Gilles B., Olivier R., Jean-François L., Fabrice M., Pascal R., Florian S., Maxime P., Pascal L., Jérémy d'A., Olivier C. x2, David G., Guillaume D., Patrick C., Lesley K., Gérald G., Jean-Baptiste V., Antoine C. ...
