# Awesome SOC
A collection of sources of documentations, and field best practices to build/run a SOC.

Those are my view, based on my own experience as SOC/CERT analyst and team manager, as well as well-known papers. 

NB: Generally speaking, SOC here refers to detection activity, and CERT/CSIRT to incident response.

# Must read:
## For a SOC:
* NIST, Cybersecurity framework: https://www.nist.gov/cyberframework 
* FIRST, Building a SOC: https://www.first.org/resources/guides/Factsheet_Building_a_SOC_start_small.pdf 
* NIST, SP800-61 rev2, incident handling guide: https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final 
* MITRE, 11 strategies for a world-class SOC (part 0, Fundamentals): https://www.mitre.org/publications/technical-papers/11-strategies-world-class-cybersecurity-operations-center 

## For a CERT: 
* FIRST, CERT-in-a-box: https://www.first.org/resources/guides/cert-in-a-box.zip 
* ENISA, Good practice for incident response: https://www.enisa.europa.eu/publications/good-practice-guide-for-incident-management
* NIST, SP800-86, integration forensics techniques into IR: https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-86.pdf 

## Globally (SOC and CERT):
* ThreatConnect, SIRP / SOA / TIP benefits: https://threatconnect.com/blog/realizing-the-benefits-of-security-orchestration-automation-and-response-soar/ 
* Orange Cyberdefense, Feedback regarding experience with SOAR in 2020 (in French): https://www.orangecyberdefense.com/fr/insights/blog/threat-management/soar-quelles-conclusions-en-2020 
* Lutessa, Red/blue/purple teams’ roles: https://www.lutessa.com/wp-content/uploads/2020/09/red-team-purple-team-blue-team.png  (https://www.lutessa.com/?p=5524)


# Critical means (tools/sensors):

## Critical tools for a SOC/CERT:
* SIEM (see: https://www.gartner.com/en/information-technology/glossary/security-information-and-event-management-siem)
   * see Gartner magic quadrant: https://www.bankinfosecurity.com/whitepapers/2021-gartner-magic-quadrant-for-security-information-event-w-8758 
   * e.g.: Splunk, Elastic...
* SIRP (see: https://d3security.com/blog/whats-the-difference-between-soar-and-sao/)
  * e.g.: TheHive, PAN XSOAR, IBM Resilient, SwimLane...
* SOA (see: https://d3security.com/blog/whats-the-difference-between-soar-and-sao/)
  * e.g.: TheHive, PAN XSOAR, IBM Resilient, SwimLane...
* TIP (see: https://d3security.com/blog/whats-the-difference-between-soar-and-sao/)
  * e.g.: MISP, OpenCTI, ThreatQuotient...

## Critical sensors for a SOC:

* **Antimalware**
  * See Gartner magic quadrant: https://www.threatscape.com/microsoft-security-named-leader-in-4-gartner-magic-quadrants/ 
* **Endpoint Detection and Response** (see: https://www.gartner.com/reviews/market/endpoint-detection-and-response-solutions)
  * see Gartner magic quadrant: https://www.microsoft.com/security/blog/uploads/securityprod/2022/01/Gartner-EIA-1963x2048.png 
* **Security Email Gateway** (see: https://www.gartner.com/reviews/market/email-security)
* **Security Weg Gateway** / Security Service Edge (see: https://www.gartner.com/en/information-technology/glossary/secure-web-gateway)
  * see Gartner magic quadrant: https://www.zscaler.fr/cdn-cgi/image/format%3Dauto/sites/default/files/images/page/gartner-magic-quadrant-security-service-edge-sse-2022/zscaler-gartner-sse-2022-%401x.png 
* **AD security** (audit logs, or security monitoring)
  * e.g.: Semperis
* Cloud Access Security Broker, if company's IT environment uses a lot of external services like SaaS/IaaS (see: https://www.gartner.com/en/information-technology/glossary/cloud-access-security-brokers-casbs)
   * see Gartner magic quadrant: https://www.netskope.com/wp-content/uploads/2021/01/Screen-Shot-2021-01-05-at-10.15.23-AM-1024x456.png

## Critical tools for CERT:
* On-demand sandbox
* Forensics and reverse-engineering tools suite
  * e.g.: SIFT Workstation: https://www.sans.org/tools/sift-workstation/, Tsurugi: https://tsurugi-linux.org/
* Incident tracker, FireEye Flare-VM: https://github.com/mandiant/flare-vm 
  * e.g.: Timesketch: https://timesketch.org/ 


# IT/sec Watch (sources)

* Sigma HQ (detection rules): https://github.com/SigmaHQ/sigma/tree/master/rules 
* Splunk Security content (free detection rules for Splunk): https://research.splunk.com/ 
* Awesome Threat Intelligence: https://github.com/hslatman/awesome-threat-intelligence 
* LinkedIn / Twitter
* Government CERT, industry sector CERT


# Management

## TTP (attack methods) knowledge base reference:
* MITRE ATT&CK: https://attack.mitre.org/matrices/enterprise/

## Detection capabilities representation standard, for a given security solution (like AWS, Azure, NDR, etc.):
*	Security Stack Mappings: https://github.com/center-for-threat-informed-defense/security-stack-mappings 

## SOC detection capabilities **simplified** representation:
 * heatmap, see: https://www.signalblur.io/getting-started-with-mitres-att-ck-navigator/)

## SOC Self-assessment:
*	SOC Cyber maturity model: https://www.soc-cmm.com/introduction/ 
*	SOC-CMM self-assessment tool: https://www.soc-cmm.com/downloads/latest/ 

## CERT/CSIRT self-assessment:
* ENISA, OpenCSIRT cybersecurity maturity framework: https://www.enisa.europa.eu/topics/csirts-in-europe/csirt-capabilities/csirt-maturity/  
  * OpenCSIRT, SIM3 self-assessment: https://sim3-check.opencsirt.org/#/v1/ 
* CMM, SOC-CMM 4CERT: https://www.soc-cmm.com/4CERT/ 
  * SOC-CMM 4CERT self-assessment tool: https://www.soc-cmm.com/downloads/latest/soc-cmm%20for%20CERT%201.0%20-%20advanced.xlsx 
  



# To go further:

## Must read:
* MITRE, 11 strategies for a world-class SOC (remaining of PDF): https://www.mitre.org/publications/technical-papers/11-strategies-world-class-cybersecurity-operations-center 
*	Microsoft, SOC/IR hierarchy of needs: https://github.com/swannman/ircapabilities 
* CISA, Cyber Defense Incident Responder role: https://www.cisa.gov/cyber-defense-incident-responder 
* Betaalvereniging, TahiTI (threat huting methdology): https://www.betaalvereniging.nl/wp-content/uploads/TaHiTI-Threat-Hunting-Methodology-whitepaper.pdf 
* GMU, Improving Social Maturity of Cybersecurity Incident Response Teams: https://edu.anarcho-copy.org/Against%20Security%20-%20Self%20Security/GMU_Cybersecurity_Incident_Response_Team_social_maturity_handbook.pdf
* FireEye, Purple Team Assessment: https://www.fireeye.fr/content/dam/fireeye-www/regional/fr_FR/services/pdfs/ds-purple-team-assessment.pdf  
* FIRST, CVSS v3.1 specs: https://www.first.org/cvss/specification-document 

## Nice to read:
* NIST, SP800-53 rev5 (Security and Privacy Controls for Information Systems and Organizations): https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final 
* Amazon,	AWS Security Fundamentals: https://aws.amazon.com/fr/training/digital/aws-security-fundamentals/   
* Microsoft, PAW Microsoft: https://docs.microsoft.com/en-us/security/compass/privileged-access-devices 
* CIS, Business Impact Assessment: https://bia.cisecurity.org/ 
* Abdessabour Boukari, RACI template (in French): https://github.com/cyberabdou/SOC/blob/77f01ba82c22cb11028cde4a862ae0bea4258378/SOC%20RACI.xlsx 
* Trellix, XDR Gartner market guide: https://www.trellix.com/fr-fr/solutions/gartner-report-market-guide-xdr.html
