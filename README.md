# Awesome SOC
A collection of sources of documentation, and field best practices, to build and run a SOC (including CSIRT).

Those are my view, based on my own experience as SOC/CSIRT analyst and team manager, as well as well-known papers. Focus is more on SOC than on CERT/CSIRT.

My motto is: without reaction (response), detection is useless.

NB: Generally speaking, SOC here refers to detection activity, and CERT/CSIRT to incident response activity. CERT is a well-known (formerly) US trademark, run by [CERT-CC](https://www.sei.cmu.edu/about/divisions/cert/index.cfm), but I prefer the term [CSIRT](https://www.enisa.europa.eu/topics/incident-response).

# Table of Content
* [Must read](https://github.com/cyb3rxp/awesome-soc/blob/main/README.md#must-read)
* [Fundamental concepts](https://github.com/cyb3rxp/awesome-soc/blob/main/soc_basics.md)
* [Mission-critical means (tools/sensors)](https://github.com/cyb3rxp/awesome-soc/blob/main/README.md#mission-critical-means-toolssensors)
* [IT/security Watch](https://github.com/cyb3rxp/awesome-soc/blob/main/README.md#itsecurity-watch-recommended-sources)
* [SOAR](https://github.com/cyb3rxp/awesome-soc/blob/main/README.md#soar)
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
* FIRST, [ISO 27035 Practical value for CSIRT and SOCs ](https://www.first.org/resources/papers/conf2023/FIRSTCON23-TLPCLEAR-Benetis-ISO-27035-practical-value-for-CSIRTs-and-SOCs.pdf)
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
* LinkedIn Pulse, [Security incident management according to ISO 27005](https://www.linkedin.com/pulse/security-incident-management-according-iso-27035-dipen-das-)
* [ForensicsArtefacts](https://github.com/ForensicArtifacts/artifacts)
* Kaspersky, [Incident Response Playbook: Dark Web Breaches](https://media.licdn.com/dms/document/media/D4D1FAQGNnA_2uNbdpg/feedshare-document-pdf-analyzed/0/1701500614215?e=1702512000&v=beta&t=K7hE9V4OuF9-D1tUyH2ClR04kbG2d5ZM72avDMZ3Asg)


## Globally (SOC and CERT/CSIRT)
* Vilius Benetis, [CSIRT, SOC, ISAC and PSIRT definitions](https://www.linkedin.com/pulse/csirt-soc-isac-psirt-definitions-vilius-benetis)
* Thomas Roccia, [Visual Threat Intelligence](https://www.amazon.fr/Visual-Threat-Intelligence-Illustrated-Researchers/dp/B0C7JCF8XD)
* SentinelOne, [What is SecOps](https://www.sentinelone.com/cybersecurity-101/secops/?utm_content=white-paper&utm_medium=paid-display&utm_source=gdn-paid&utm_campaign=emea-t1-en-g-dsa&utm_term={demo-request}&utm_campaignid=19179764064&gclid=EAIaIQobChMItYzg5amQ_gIV6pBoCR1u0ACxEAAYAiAAEgJ1ofD_BwE)
* Shubham, [Security 360](https://twitter.com/Shubham_pen/status/1655192003448020993?s=20)
* NIST, [Cybersecurity framework](https://www.nist.gov/cyberframework)
* ENISA, [How to set-up a CSIRT and SOC](https://www.enisa.europa.eu/publications/how-to-set-up-csirt-and-soc/at_download/fullReport)
* NIST, [SP800-61 rev2, incident handling guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final) 
* MITRE, [ATT&CK: Getting started](https://attack.mitre.org/resources/getting-started/)
* Purp1eW0lf, [Blue Team Notes](https://github.com/Purp1eW0lf/Blue-Team-Notes)
* ThreatConnect, [SIRP / SOA / TIP benefits](https://threatconnect.com/blog/realizing-the-benefits-of-security-orchestration-automation-and-response-soar/)
* Swimlane, [Cyber Threat readiness report 2023](https://swimlane.com/wp-content/uploads/Cyber-Threat-Readiness-Report-2023.pdf);
* Gartner, [Market Guide for Security Orchestration, Automation and Response Solutions](https://www.gartner.com/doc/reprints?id=1-2ADE1K2G&ct=220621&st=sb) 
* PAN, [Security orchestration for dummies](https://www.paloaltonetworks.com/content/dam/pan/en_US/assets/pdf/cortex-xsoar/Security-Orchestration-For-Dummies-Demisto-Special-Edition.pdf)
* FIRST, [CVSS v4 specs](https://www.first.org/cvss/v4-0/) 
* OASIS Open, [STIX](https://oasis-open.github.io/cti-documentation/stix/intro.html)
* FIRST, [TLP](https://www.first.org/tlp/) (intelligence sharing and confidentiality), and [PAP](https://cert.ssi.gouv.fr/csirt/sharing-policy/)
* CIS, [18 critical security controls](https://www.cisecurity.org/controls/cis-controls-list)
* Gartner, [Cybersecurity business value benchmark](https://emtemp.gcom.cloud/ngw/globalassets/en/doc/documents/775537-gartner-cybersecurity-business-value-benchmark-1st-generation.pdf)
* CyberArk: [NIS2, how to address the security control gaps](https://event.on24.com/eventRegistration/console/apollox/mainEvent?simulive=y&eventid=4110743&sessionid=1&username=&partnerref=&format=fhvideo1&mobile=&flashsupportedmobiledevice=&helpcenter=&key=588150776CAE70D7F02ECF2848FF11FA&newConsole=true&nxChe=true&newTabCon=true&consoleEarEventConsole=false&text_language_id=en&playerwidth=748&playerheight=526&eventuserid=600843623&contenttype=A&mediametricsessionid=517006274&mediametricid=5797475&usercd=600843623&mode=launch)


# Fundamental concepts

## Concepts, tools, missions, attack lifecycle, red/blue/purple teams
See: [SOC/CSIRT Basic and fundamental concepts](https://github.com/cyb3rxp/awesome-soc/blob/main/soc_basics.md).

## SOC core

### From logs to alerts: global generic workflow

Quoted from [this article](https://www.managedsentinel.com/siem-traditional-vs-cloud/):

![image](https://user-images.githubusercontent.com/16035152/206025151-759a0040-365e-4145-aa88-f7a7b737f8be.png)

Following the arrows, we go from log data sources to data management layer, to then data enrichment layer (where detection happens), to end-up in behavior analytics or at user interaction layer (alerts, threat hunting...). All of that being enabled and supported by automation.


### SOC architecture of detection
Based on [CYRAIL's paper drawing](https://slideplayer.com/slide/15779727/), that I've slightly modified, here is an example of architecture of detection (SIEM, SIRP, TIP interconnections) and workflow:
![image](https://user-images.githubusercontent.com/16035152/207597681-22c9da6d-d430-4660-b807-3e86138a0d9c.png)

* Sensors log sources are likely to be: audit logs, security sensors (antimalware, FW, NIDS, proxies, EDR, NDR, CASB, identity threat detection, honeypot...).



# Mission-critical means (tools/sensors)

## Critical tools for a SOC/CSIRT
* **[SIEM](https://www.gartner.com/en/information-technology/glossary/security-information-and-event-management-siem)**:
   * See [Gartner magic quadrant](https://www.gartner.com/doc/reprints?id=1-2BDC4CDW&ct=221010&st=sb)
   * My recommendations: [Microsoft Azure Sentinel](https://azure.microsoft.com/en-us/products/microsoft-sentinel/#overview), [Sekoia.io XDR](https://www.sekoia.io/en/sekoia-io-xdr/), [Splunk](www.splunk.com), [Graylog](https://graylog.org/).
* **[SIRP](https://d3security.com/blog/whats-the-difference-between-soar-and-sao/)**:
  * e.g.: [IBM Resilient](https://www.ibm.com/qradar/security-qradar-soar?utm_content=SRCWW&p1=Search&p4=43700068028974608&p5=e&gclid=Cj0KCQjw9ZGYBhCEARIsAEUXITW2yUqAfNqWNeYXyENeUAoqLxV543LT0n2oYhYxEQ47Yjm7NfYTFHAaAtwpEALw_wcB&gclsrc=aw.ds),  [TheHive](https://thehive-project.org/), [SwimLane](https://swimlane.com/), [PAN Cortex XSOAR](https://www.paloaltonetworks.com/cortex/cortex-xsoar)
  * My recommendations:  [TheHive](https://thehive-project.org/), [PAN Cortex XSOAR](https://www.paloaltonetworks.com/cortex/cortex-xsoar)
* **[SOA](https://d3security.com/blog/whats-the-difference-between-soar-and-sao/)**:
  * I recommend to read the Forrester's [overview of SOAR providers](https://www.paloaltonetworks.com/engage/cortex-xsoar/forrester-com-2?utm_source=marketo&utm_medium=email&utm_campaign=Global-NU-EN-21-04-14-XX-P3-Cortex-XSOAR.EN-NU05-Cortex_XSOAR-MOFU&utm_network=pf&mkt_tok=NTMxLU9DUy0wMTgAAAGRtyevdpJBsF0cPQpwRMziLi8AsU4MneA1CMmGAGggPsBuYenJW9khG5e7Wqa78zC0GcLaP0a2R-e6bJpJ0BQAwEKLDrSpqe6npkmcM3DpNXSeqbeAJ9E&_pfses=Rx9LBfVH47t8TMQ542Kr7pCt)
  * e.g.: [IBM Resilient](https://www.ibm.com/qradar/security-qradar-soar?utm_content=SRCWW&p1=Search&p4=43700068028974608&p5=e&gclid=Cj0KCQjw9ZGYBhCEARIsAEUXITW2yUqAfNqWNeYXyENeUAoqLxV543LT0n2oYhYxEQ47Yjm7NfYTFHAaAtwpEALw_wcB&gclsrc=aw.ds), [SwimLane](https://swimlane.com/), [TheHive](https://thehive-project.org/), [PAN Cortex XSOAR](https://www.paloaltonetworks.com/cortex/cortex-xsoar), [Microsoft Logic Apps](https://learn.microsoft.com/en-us/azure/logic-apps/logic-apps-overview)
  * My recommendations: [SwimLane](https://swimlane.com/), [TheHive](https://thehive-project.org/), [PAN Cortex XSOAR](https://www.paloaltonetworks.com/cortex/cortex-xsoar) 
* **[TIP](https://www.ssi.gouv.fr/en/actualite/opencti-the-open-source-solution-for-processing-and-sharing-threat-intelligence-knowledge/)**:
   * See [Threat intel page](https://github.com/cyb3rxp/awesome-soc/blob/main/threat_intelligence.md) 
     

## Critical sensors for a SOC

* **Antimalware/antivirus** (you may want to have a look at [my antivirus and EDR differences table](https://github.com/cyb3rxp/awesome-soc/blob/main/soc_basics.md#difference-between-antivirus-and-edr)):
  * See [Gartner magic quadrant](https://www.microsoft.com/en-us/security/blog/2024/01/12/microsoft-is-named-a-leader-in-the-2023-gartner-magic-quadrant-for-endpoint-protection-platforms/) or [Forrester Wave](https://explore.bitdefender.com/epp-nurture-2023_2/report-forrester-wave-endpoint-security-q4-2023?cid=emm%7Cb%7Chubspot%7Cnrt-epp-2023&utm_campaign=nurture-epp-2023&utm_medium=email&_hsmi=280555694&utm_content=280555694&utm_source=hs_automation)
  * My recommendations: [Microsoft Defender](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/microsoft-defender-antivirus-windows?view=o365-worldwide), [ESET Nod32](https://www.eset.com/int/business/solutions/learn-more-about-endpoint-protection/), [BitDefender](https://www.bitdefender.fr/business/products/workstation-security.html).
* **[Endpoint Detection and Response](https://www.gartner.com/reviews/market/endpoint-detection-and-response-solutions)**:
  * See [Gartner magic quadrant](https://www.microsoft.com/security/blog/uploads/securityprod/2022/01/Gartner-EIA-1963x2048.png), [MITRE ENGENUITY](https://attackevals.mitre-engenuity.org/), and [Forrester Wave](https://www.crowdstrike.com/resources/reports/crowdstrike-recognized-as-dominant-endpoint-solution-with-superior-vision/)
  * My recommendations: [SentinelOne](https://www.sentinelone.com/blog/active-edr-feature-spotlight/), [Microsoft Defender for Endpoint](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/microsoft-defender-endpoint?view=o365-worldwide), [Harfanglab](https://www.harfanglab.io/en/block-cyberattacks), [ESET XDR](https://www.eset.com/int/business/enterprise-protection-bundle/), [WithSecure Elements EDR](https://www.withsecure.com/us-en/solutions/software-and-services/elements-endpoint-detection-and-response), [CrowdStrike Falcon EDR](https://www.crowdstrike.com/wp-content/uploads/2022/03/crowdstrike-falcon-insight-data-sheet.pdf), [Tanium](https://www.tanium.com/products/tanium-threat-response/), [Wazuh](https://wazuh.com/)
* **[Secure Email Gateway](https://www.gartner.com/reviews/market/email-security)** (SEG):
  * See [Gartner reviews and ratings](https://www.gartner.com/reviews/market/email-security)
  * My recommendations: [Microsoft Defender for Office365](https://www.microsoft.com/en-us/security/business/siem-and-xdr/microsoft-defender-office-365), [ProofPoint](https://www.proofpoint.com/fr/threat-reference/email-gateway), [Mimecast](https://www.mimecast.com/products/email-security/secure-email-gateway/)
* **[Secure Web Gateway](https://www.gartner.com/en/information-technology/glossary/secure-web-gateway)** (SWG) / Security Service Edge:
  * see [Gartner magic quadrant](https://www.zscaler.fr/cdn-cgi/image/format%3Dauto/sites/default/files/images/page/gartner-magic-quadrant-security-service-edge-sse-2022/zscaler-gartner-sse-2022-%401x.png) 
  * My recommendations: [BlueCoat Edge SWG](https://www.broadcom.com/products/cybersecurity/network/web-protection/proxy-sg-and-advanced-secure-gateway), [CISCO SASE](https://www.cisco.com/site/us/en/solutions/secure-access-service-edge-sase/index.html), [Zscaler Cloud proxy](https://www.zscaler.com/resources/security-terms-glossary/what-is-cloud-proxy), [Netskope](https://www.netskope.com/security-defined/what-is-casb).
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
* Compromise assessment tools:
  * My recommendations:
    * Paid ones: [Thor Cloud lite](https://www.nextron-systems.com/2023/10/30/introducing-thor-cloud-lite-seamless-on-demand-security-scanning-made-easy/).
    * free ones:
       * for Linux: WithSecure [Cat-Scale](https://labs.withsecure.com/tools/cat-scale-linux-incident-response-collection), [UAC](https://github.com/tclahr/uac).
       * for Windows:
          * simple but efficient ESET [Sysinspector](https://www.eset.com/int/support/sysinspector/);
          * [Velociraptor](https://docs.velociraptor.app/docs/);
          * [DFIR-ORC](https://github.com/dfir-orc);
          * [Sysmon](https://learn.microsoft.com/fr-fr/sysinternals/downloads/sysmon) (install it, let it run for a few hours/days, then investigate its log), with [Olaf Hartong's config](https://github.com/olafhartong/sysmon-modular/blob/master/sysmonconfig.xml);
       * For AD: 
         * [Semperis Purple Knight](https://www.purple-knight.com/active-directory-security-tool/);
       * For MS Entra ID & M365:
         * [Semperis Purple Knight](https://www.purple-knight.com/active-directory-security-tool/);
         * simple but efficient [ADRecon](https://github.com/tomwechsler/Active_Directory_Advanced_Threat_Hunting/blob/main/Different_hunting_methods/In-depth_investigation_active_directory.md);
         * [365Inspect](https://github.com/soteria-security/365Inspect);
         * [Azure AD Incident Response Powershell](https://github.com/reprise99/kql-for-dfir/tree/main/Azure%20Active%20Directory)
       * For Azure / GCP / AWS:
         * [ScootSuite](https://github.com/nccgroup/ScoutSuite)
* On-demand volatile data collection tool:
  * My recommendations: [FastIR](https://github.com/OWNsecurity/fastir_artifacts), [VARC](https://github.com/cado-security/varc), [FireEye Redline](https://fireeye.market/apps/211364), [DFIR-ORC](https://github.com/dfir-orc);
* Remote action capable tools (ie.: remote shell or equivalent):
  * My recommendations: [CIMSweep](https://github.com/mattifestation/CimSweep), [Velociraptor](https://docs.velociraptor.app/docs/deployment/), [CrowdStrike Falcon Toolkit](https://github.com/CrowdStrike/Falcon-Toolkit) but it relies on CrowdStrike EDR, [GRR](https://github.com/google/grr) but it needs an agent to be installed.
* On-demand sandbox:
  * My recommendations for online ones: [Joe's sandbox](https://www.joesandbox.com/#windows), [Hybrid Analysis](https://www.hybrid-analysis.com/), etc;
  * My recommendation for local one: Windows 10 native Sandbox, with [automation](https://megamorf.gitlab.io/2020/07/19/automating-the-windows-sandbox/).
* Forensics and reverse-engineering tools suite:
  * My recommendations: [SIFT Workstation](https://www.sans.org/tools/sift-workstation/), or [Tsurugi](https://tsurugi-linux.org/);
  * My recommendation for reverse engineering and malware analysis, under Windows: [FireEye Flare-VM](https://github.com/mandiant/flare-vm);
  * My recommendation for pure malware analysis, under Linux: [Remnux](https://remnux.org/).
* Incident tracker: 
  * My recommendations: [Timesketch](https://timesketch.org/), [DFIR IRIS](https://dfir-iris.org/)
* Scanners:
  * IOC scanners:
    * My recommendations: [Loki](https://github.com/Neo23x0/Loki), [DFIR-ORC](https://github.com/dfir-orc)
    * For smartphones: [Tiny Check](https://github.com/KasperskyLab/TinyCheck)
  * IOC repos for scanners:
    * Google [CTI's repo](https://github.com/chronicle/GCTI/tree/main/YARA): Yara rules for Cobalt Strike and others.
    * [Yara-rules GitHub repo](https://github.com/Yara-Rules/rules): multiple Yara rules types.
    * Spectre [Yara rules repo](https://github.com/phbiohazard/Yara)
    * Neo23x0 [Community Yara rules](https://github.com/Neo23x0/signature-base)
    * and those listed here, [Awesome threat intel](https://github.com/hslatman/awesome-threat-intelligence)
  * Offline antimalware scanners:
    * My recommendation: [Windows Defender Offline](https://support.microsoft.com/en-us/windows/help-protect-my-pc-with-microsoft-defender-offline-9306d528-64bf-4668-5b80-ff533f183d6c), [ESET SysRecue](https://www.eset.com/int/support/sysrescue/)
* Logs analyzers with detection capabilities:
    * My recommendations: [CrowdSec](https://doc.crowdsec.net/docs/user_guides/replay_mode), [Sekoia XDR](https://www.sekoia.io/en/product/xdr/), [DeepBlue](https://github.com/sans-blue-team/DeepBlueCLI)
      
## Other critical tools for a SOC and a CERT/CSIRT
* Data analysis tools:
  * My recommendations: [CyberChef](https://github.com/NextronSystems/CyberChef), [Notepad++](https://notepad-plus-plus.org/downloads/)
* Admin tools: 
  * My recommendations: [Azure AD Internals suite](https://aadinternals.com/), [SysInternals Suite](https://learn.microsoft.com/fr-fr/sysinternals/downloads/sysinternals-suite)
* Internal ticketing system (NB: **not** SIRP, not for incident response!):
  * My recommendation: [GitLab](https://about.gitlab.com/handbook/engineering/security/security-operations/sirt/sec-incident-response.html)
* Knowledge sharing and management tool:
  * My recommendations: [Microsoft SharePoint](https://www.microsoft.com/en-us/microsoft-365/sharepoint/collaboration), Wiki (choose the one you prefer, or [use GitLab as a Wiki](https://docs.gitlab.com/ee/user/project/wiki/)).
* Vizualization tool for OSINT search and IOC:
  * My recommendation: [OSINTracker](https://app.osintracker.com/)


# IT/security Watch (recommended sources)

* SIEM rules publications:
  * [Sigma HQ (detection rules)](https://github.com/SigmaHQ/sigma/tree/master/rules) 
  * [Splunk Security content (free detection rules for Splunk)](https://research.splunk.com/) 
  * [SOC Prime](https://tdm.socprime.com/)
  * [Michel De Crevoisier's Git](https://github.com/mdecrevoisier/SIGMA-detection-rules)
* Known exploited vulnerabilities +0days: 
  * [CISA catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  * [CVETrends](https://cvetrends.com/)
  * [Top 0days "in the wild"](https://docs.google.com/spreadsheets/d/1lkNJ0uQwbeC1ZTRrxdtuPLCIl7mlUreoKfSIgajnSyY/edit#gid=1746868651)
* LinkedIn / Twitter:
  * e.g.: [LinkedIn Information Security Community group](https://www.linkedin.com/groups/38412/) 
* RSS reader/portal:
  * e.g.: [Netvibes](https://www.netvibes.com/phvialle?page=phvialle#Security)  
* Government CERT, industry sector related CERT...
  * e.g.: [CERT-FR](https://www.cert.ssi.gouv.fr/avis/), [CERT-US](https://www.cisa.gov/uscert/ncas/alerts)
* Newsletters:
  * e.g.: [TheRecord.media](https://therecord.media/subscribe), [Intrinsec Threat Landscape](https://intrinsec.us13.list-manage.com/subscribe?u=403249ad144b732517b9fca94&id=041976f275)
* Other interesting websites:
  * e.g.: [ISC](https://isc.sans.edu/), [ENISA](https://www.enisa.europa.eu/publications), [ThreatPost](https://threatpost.com/) ...


# SOAR

Cf. [SOAR page](https://github.com/cyb3rxp/awesome-soc/blob/main/soar.md)


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
* CyberVigilance, [Mitre Engenuity Evaluations 2022 review](https://www.cybervigilance.uk/post/2022-mitre-att-ck-engenuity-results)



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
* Austin Songer, [Incident playbook](https://github.com/austinsonger/Incident-Playbook)
* CISA, [Cybersecurity incident and vulnerability response playbooks](https://www.cisa.gov/sites/default/files/publications/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf)
* Reprise99, [Microsoft Sentinel queries](https://github.com/reprise99/Sentinel-Queries)
* MyFaberSecurity, [MS Sentinel architecture and recommendations for MSSP](https://myfabersecurity.com/2023/03/31/sentinel-poc-architecture-and-recommendations-for-mssps-part-1/)
* Gartner, [PAM Magic Quadrant reprint](https://www.gartner.com/doc/reprints?id=1-2AMZ88JO&ct=220721&st=sb)
* Rawsec, [Tools inventory](https://inventory.raw.pm/tools.html)
* Microsoft, [command line reference](https://cmd.ms/)
* Microsoft, [Sentinel data collection scenarios](https://learn.microsoft.com/en-us/azure/sentinel/connect-cef-ama#how-collection-works-with-the-common-event-format-cef-via-ama-connector)
* SOC CMM, [SOCTOM](https://soc-cmm.com/downloads/SOCTOM%20whitepaper.pdf)
* [PTES](http://www.pentest-standard.org/index.php/Main_Page)
* OWASP, [WSTG](https://owasp.org/www-project-web-security-testing-guide/)
* BitDefender, [Analyzing MITRE ATT&CK evaluations 2023](https://explore.bitdefender.com/epp-nurture-2023_2/blog-mitre-attck-evaluations-2023?cid=emm%7Cb%7Chubspot%7Cnrt-epp-2023&utm_campaign=nurture-epp-2023&utm_medium=email&_hsmi=280552612&utm_content=280552612&utm_source=hs_automation)


## SOC sensors, nice to have
* Dark Web monitoring (data leaks, etc.)
  * My recommendation: [AIL Framework](https://github.com/CIRCL/AIL-framework)
  * for paid SaaS solutions, I recommend to have a look at this [top 10](https://expertinsights.com/insights/the-top-dark-web-monitoring-solutions/)
* (full-featured) Honeypot:
  * My recommendation: [Canary.tools](https://canary.tools/)
  * Or, have a look at [Awesome honeypots Git](https://github.com/paralax/awesome-honeypots)
* Phishing and brand infringement protection (domain names):
  * My recommendation: [PhishLabs](https://www.phishlabs.com/), [Netcraft](https://www.netcraft.com/cybercrime/fraud-detection/)
* NIDS:
  * My recommendation: [Crowdsec](https://www.crowdsec.net/product/crowdsec-security-engine)
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
