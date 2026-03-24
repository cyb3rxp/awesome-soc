[![Awesome](https://awesome.re/badge.svg)](https://awesome.re) ![Last Update](https://img.shields.io/github/last-commit/cyb3rxp/awesome-soc) ![GitHub stars](https://img.shields.io/github/stars/cyb3rxp/awesome-soc?style=social) ![License](https://img.shields.io/github/license/cyb3rxp/awesome-soc) ![Contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen)
# Awesome SOC

An operational handbook and knowledge base to build, run and mature a SOC (including CSIRT). Covering:
- SOC basics
- detection engineering
- threat intelligence
- SOC metrics/KPI
- SOC automation
- SOP (SOC playbooks)

Those are my view, based on my own experience as SOC/CSIRT analyst and team manager, as well as well-known papers. Focus is more on SOC than on CERT/CSIRT.

My motto is: without reaction (response), detection is useless.

NB: Generally speaking, SOC here refers to detection activity, and CERT/CSIRT to incident response activity. CERT is a well-known (formerly) US trademark, managed by [CERT-CC](https://www.sei.cmu.edu/about/divisions/cert/index.cfm), but I prefer the term [CSIRT](https://www.enisa.europa.eu/sites/default/files/publications/Incident_Management_guide.pdf) as it precisely refers to incident response.


# Table of Contents
* [Must read](#must-read)
* [Fundamental concepts](#Fundamental-concepts)
* [Mission-critical means (tools/sensors)](#mission-critical-means-toolssensors)
* [SOC internals/core](#soc-internals)
* [Gen AI / ML](ml_genai.md)
* [IT/security Watch](#itsecurity-watch)
* [SOAR](#SOAR)
* [Detection engineering](#detection-engineering)
* [Threat intelligence](#threat-intelligence)
* [Playbooks/SOP](#playbooks)
* [SOC metrics (KPI/SLA)](#soc-metrics-kpisla)
* [SOC Management](#management)
* [HR and training](#hr-and-training)
* [IT achitecture](#it-achitecture-of-a-soc)
* [To go further (next steps)](#to-go-further)
* [Appendix](#appendix)

# Must read

## For a SOC
* SOC build:
  * MITRE, [11 strategies for a world-class SOC](https://www.mitre.org/publications/technical-papers/11-strategies-world-class-cybersecurity-operations-center) (or use [local file](https://github.com/cyb3rxp/awesome-soc/blob/main/11-strategies-of-a-world-class-cybersecurity-operations-center.pdf)): part 0 (Fundamentals).
  * FIRST, [Building a SOC](https://www.first.org/resources/guides/Factsheet_Building_a_SOC_start_small.pdf)
  * NCSC, [Building a SOC](https://www.ncsc.gov.uk/collection/building-a-security-operations-centre)
  * Gartner, [SOC model guide](https://fr.scribd.com/document/732782046/Gartner-SOC-Model-Guide-2023)
  * Splunk, [State of Security 2023](https://www.splunk.com/en_us/pdfs/gated/ebooks/state-of-security-2023.pdf)
  * Microsoft, [Secure your business with 365](https://learn.microsoft.com/en-us/microsoft-365/admin/security-and-compliance/m365b-security-best-practices?view=o365-worldwide) 
* SOC training/interview:
  * LetsDefend [SOC analyst interview questions](https://github.com/LetsDefend/SOC-Interview-Questions)
* SOC management:
  * FIRST, [ISO 27035 Practical value for CSIRT and SOCs ](https://www.first.org/resources/papers/conf2023/FIRSTCON23-TLPCLEAR-Benetis-ISO-27035-practical-value-for-CSIRTs-and-SOCs.pdf)
  * SANS, [2024 SOC survey](https://swimlane.com/wp-content/uploads/SANS-SOC-Survey_2024.pdf)
  * SOC CMM, [SOC Metrics](https://www.soc-cmm.com/img/upload/files/31-soc-cmm-metrics-101.pdf)
* SOC assessment:
  * CMM, [SOC-CMM](https://www.soc-cmm.com/)
  * Rabobank CDC, [DeTTECT](https://github.com/rabobank-cdc/DeTTECT)
  * SANS, [Continous purple teaming](https://www.sans.org/blog/continuous-purple-teaming-practical-approach-strengthening-offensive-capabilities)


## For a CERT/CSIRT
* CSIRT build:
  * FIRST, [CERT-in-a-box](https://www.first.org/resources/guides/cert-in-a-box.zip) 
  * FIRST, [CSIRT Services Framework](https://www.first.org/standards/frameworks/csirts/csirt_services_framework_v2.1)
* Security incident response management:
  * ENISA, [Good practice for incident management](https://www.enisa.europa.eu/publications/good-practice-guide-for-incident-management)
  * EE-ISAC [Incident Response whitepaper](https://www.ee-isac.eu/media/2023/05/EE-ISAC-Incident-Response-White-Paper.pdf)
  * LinkedIn Pulse, [Security incident management according to ISO 27005](https://www.linkedin.com/pulse/security-incident-management-according-iso-27035-dipen-das-)
  * Microsoft/EY/Edelman, [Incident response reference guide](https://www.linkedin.com/posts/the-cyber-security-hub_incident-response-reference-guide-activity-7033563558642642944-0zav?utm_source=share&utm_medium=member_desktop)
  * Microsoft, [IR lessons on cloud ID compromise](https://www.microsoft.com/en-us/security/blog/2023/12/05/microsoft-incident-response-lessons-on-preventing-cloud-identity-compromise/?msockid=07788c7fcb0c689a2a5d98f6ca0169fb)
* Forensics:
  * NIST, [SP800-86, integration forensics techniques into IR](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-86.pdf)
  * [ForensicsArtefacts](https://github.com/ForensicArtifacts/artifacts)
* Incident response playbooks:
  * Kaspersky, [Incident Response Playbook: Dark Web Breaches](https://dfi.kaspersky.com/blog/dark-web-threats-response-guideline#form)
  * CISA, [Incident Response playbooks](https://www.cisa.gov/sites/default/files/2024-08/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf)
  * SANS, [IR Mitigations tasks](https://board.flexibleir.com/b/VtdssIfCJ6Z2LYLED/1)

## Globally (SOC and CERT/CSIRT)
* Terms and concepts:
  * Shubham, [Security 360](https://twitter.com/Shubham_pen/status/1655192003448020993?s=20)
  * Vilius Benetis, [CSIRT, SOC, ISAC and PSIRT definitions](https://www.linkedin.com/pulse/csirt-soc-isac-psirt-definitions-vilius-benetis)
  * Thomas Roccia, [Visual Threat Intelligence](https://www.amazon.fr/Visual-Threat-Intelligence-Illustrated-Researchers/dp/B0C7JCF8XD)
  * SentinelOne, [What is SecOps](https://www.sentinelone.com/cybersecurity-101/secops/?utm_content=white-paper&utm_medium=paid-display&utm_source=gdn-paid&utm_campaign=emea-t1-en-g-dsa&utm_term={demo-request}&utm_campaignid=19179764064&gclid=EAIaIQobChMItYzg5amQ_gIV6pBoCR1u0ACxEAAYAiAAEgJ1ofD_BwE)
  * Purp1eW0lf, [Blue Team Notes](https://github.com/Purp1eW0lf/Blue-Team-Notes)
  * PAN, [Security orchestration for dummies](https://www.paloaltonetworks.com/content/dam/pan/en_US/assets/pdf/cortex-xsoar/Security-Orchestration-For-Dummies-Demisto-Special-Edition.pdf)
  * ThreatConnect, [SIRP / SOA / TIP benefits](https://threatconnect.com/blog/realizing-the-benefits-of-security-orchestration-automation-and-response-soar/)
  * Medium, [Compromise assessment methodology](https://evrenbey.medium.com/compromise-assessment-methodology-820910efb6a4)
* SOC/CSIRT processes:
  * NIST, [SP800-61 rev3, incident handling guide](https://csrc.nist.gov/pubs/sp/800/61/r3/ipd)
* CSIRT build:
  * ENISA, [How to set-up a CSIRT and SOC](https://www.enisa.europa.eu/publications/how-to-set-up-csirt-and-soc)
* Frameworks and materials:
  * MITRE, [ATT&CK: Getting started](https://attack.mitre.org/resources/getting-started/)
  * NIST, [Cybersecurity framework](https://www.nist.gov/cyberframework)
  * FIRST, [CVSS v4 specs](https://www.first.org/cvss/v4-0/)
  * CERT-EU, [CTI Framework](https://www.cert.europa.eu/publications/threat-intelligence/cyber-threat-intelligence-framework/)
  * OASIS Open, [STIX](https://oasis-open.github.io/cti-documentation/stix/intro.html)
  * FIRST, [TLP](https://www.first.org/tlp/) (intelligence sharing and confidentiality), and [PAP](https://cert.ssi.gouv.fr/csirt/sharing-policy/)
  * CIS, [18 critical security controls](https://www.cisecurity.org/controls/cis-controls-list)
* Security capabilities mappings:
  * CTID, [Mappings explorer](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/)
* Threat matrix:
  * Push Security, [SaaS attack matrix](https://github.com/pushsecurity/saas-attacks#the-saas-attacks-matrix)
  * Microsoft, [Threat Matrix for Azure Storage services](https://microsoft.github.io/Threat-matrix-for-storage-services/)
  * MITRE, [Threat Matrix for AI-systems](https://github.com/mitre/advmlthreatmatrix/blob/master/pages/adversarial-ml-threat-matrix.md#adversarial-ml-threat-matrix)
* SOAR solutions:
  * Swimlane, [Cyber Threat readiness report 2023](https://swimlane.com/wp-content/uploads/Cyber-Threat-Readiness-Report-2023.pdf);
  * Gartner, [Market Guide for Security Orchestration, Automation and Response Solutions](https://fr.scribd.com/document/619736260/Gartner-Market-Guide-for-Security-Orchestration-Automation)
* NIS2:
  * NIS2Directive: [NIS2 10 main requirements](https://nis2directive.eu/nis2-requirements/) 
  * LinkedIn: [How will NIS2 impact your organization?](https://www.linkedin.com/pulse/how-eu-directive-nis2-impact-your-organization-anders-fleinert-larsen%3FtrackingId=Vq3GCGlOTXe1u0dllhn9MA%253D%253D/?_l=fr_FR)
  * CyberArk: [NIS2, how to address the security control gaps](https://event.on24.com/eventRegistration/console/apollox/mainEvent?simulive=y&eventid=4110743&sessionid=1&username=&partnerref=&format=fhvideo1&mobile=&flashsupportedmobiledevice=&helpcenter=&key=588150776CAE70D7F02ECF2848FF11FA&newConsole=true&nxChe=true&newTabCon=true&consoleEarEventConsole=false&text_language_id=en&playerwidth=748&playerheight=526&eventuserid=600843623&contenttype=A&mediametricsessionid=517006274&mediametricid=5797475&usercd=600843623&mode=launch)
  * ENISA: [NIS2 technical implementation guidance](https://www.enisa.europa.eu/publications/nis2-technical-implementation-guidance)
* AI Models and systems:
  * ETSI, [Baseline Cyber Security Requirements for  AI Models and Systems](https://www.etsi.org/deliver/etsi_en/304200_304299/304223/02.01.01_60/en_304223v020101p.pdf)
  * NIST, [Challenges to the Monitoring of Deployed AI Systems](https://www.nist.gov/news-events/news/2026/03/new-report-challenges-monitoring-deployed-ai-systems)
  * OWASP, [Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
  * CISCO, [State of AI Security 2026](https://www.cisco.com/site/us/en/products/security/state-of-ai-security.html)
  * Microsoft [Turning threat reports into detection insights with AI](https://www.microsoft.com/en-us/security/blog/2026/01/29/turning-threat-reports-detection-insights-ai/)
* Management:
  * Gartner, [Cybersecurity business value benchmark](https://emtemp.gcom.cloud/ngw/globalassets/en/doc/documents/775537-gartner-cybersecurity-business-value-benchmark-1st-generation.pdf)
  * CrowdStrike, [State of SIEM market 2025](https://go.crowdstrike.com/rs/281-OBQ-266/images/Whitepaper2025StateofSIEMMarketCribl.pdf?version=0)
  * Microsoft, ["While the initial trigger event was a Distributed Denial-of-Service (DDoS) attack... initial investigations suggest that an error in the implementation of our defences amplified the impact of the attack rather than mitigating it"](https://www.bbc.com/news/articles/c903e793w74o)
* SOP (Standard Operating Procedures):
  * [Antimalware check SOP](https://github.com/cyb3rxp/awesome-soc/blob/main/sop_malware_critical_controls.md)
  * [M365/Azure compromise asssessment SOP](https://github.com/cyb3rxp/awesome-soc/blob/main/sop_M365_compromise_assessment.md)
  * [Web server compromise assessment SOP](https://github.com/cyb3rxp/awesome-soc/blob/main/sop_web_server_compromise_assessment.md)


# Fundamental concepts

## Concepts, tools, missions, attack lifecycle, red/blue/purple teams

## MITRE references:
* [11 strategies for a world-class SOC](https://github.com/cyb3rxp/awesome-soc/blob/main/11-strategies-of-a-world-class-cybersecurity-operations-center.pdf), Strategy 5: Prioritize Incident Response, pages 101-123,
> Prepare for handling incidents by defining incident categories, response steps, and escalation
paths, and codifying those into SOPs and playbooks. Determine the priorities of incidents for
the organization and allocate the resources to respond. Execute response with precision and
care toward constituency mission and business.

## Dedicated page
Cf.: [SOC/CSIRT Basic and fundamental concepts](https://github.com/cyb3rxp/awesome-soc/blob/main/soc_basics.md).


# Mission-critical means (tools/sensors)

## MITRE references
* [11 strategies for a world-class SOC](https://github.com/cyb3rxp/awesome-soc/blob/main/11-strategies-of-a-world-class-cybersecurity-operations-center.pdf), Strategy 7: Select and Collect the Right Data, pages 101-123,
> Choose data by considering relative value of different data types such as sensor and log data
collected by network and host systems, cloud resources, applications, and sensors. Consider
the trade-offs of too little data and therefore not having the relevant information available and
too much data such that tools and analysts become overwhelmed.

## Dedicated page
Cf. [Mission-critical means](https://github.com/cyb3rxp/awesome-soc/blob/main/mission-critical-means.md)


# SOC internals

## MITRE references:

* [11 strategies for a world-class SOC](https://github.com/cyb3rxp/awesome-soc/blob/main/11-strategies-of-a-world-class-cybersecurity-operations-center.pdf), Strategy 8: Leverage Tools to Support Analyst Workflow, pages 101-123,
> Consolidate and harmonize views into tools and data and integrate them to maximize SOC
workflow. Consider how the many SOC tools, including SIEM, UEBA, SOAR, and others fit
in with the organization’s technical landscape, to include cloud and OT environments

## Dedicated page
Cf. [SOC internals/core](https://github.com/cyb3rxp/awesome-soc/blob/main/soc_internals.md)


# IT/security Watch 

## MITRE reference
* [11 strategies for a world-class SOC](https://github.com/cyb3rxp/awesome-soc/blob/main/11-strategies-of-a-world-class-cybersecurity-operations-center.pdf), Strategy 6: Illuminate Adversaries with Cyber Threat Intelligence, pages 101-123,
> Tailor the collection and use of cyber threat intelligence by analyzing the intersection of
adversary information, organization relevancy, and technical environment to prioritize
defenses, monitoring, and other actions.

## Dedicated page
Cf. [Watch](https://github.com/cyb3rxp/awesome-soc/blob/main/watch.md)

# SOAR

## MITRE references
* [11 strategies for a world-class SOC](https://github.com/cyb3rxp/awesome-soc/blob/main/11-strategies-of-a-world-class-cybersecurity-operations-center.pdf), Strategy 8: Leverage Tools to Support Analyst Workflow, pages 101-123,
> Consolidate and harmonize views into tools and data and integrate them to maximize SOC
workflow. Consider how the many SOC tools, including SIEM, UEBA, SOAR, and others fit
in with the organization’s technical landscape, to include cloud and OT environments.


## Dedicated page
Cf. [SOAR](https://github.com/cyb3rxp/awesome-soc/blob/main/soar.md)


# Detection engineering

## MITRE reference
* [11 strategies for a world-class SOC](https://github.com/cyb3rxp/awesome-soc/blob/main/11-strategies-of-a-world-class-cybersecurity-operations-center.pdf), Strategy 1: Know What You Are Protecting and Why, pages 101-123,
> Develop situational awareness through understanding the mission; legal regulatory
environment; technical and data environment; user, user behaviors and service interactions;
and the threat. Prioritize gaining insights into critical systems and data and iterate understanding
over time.

* [11 strategies for a world-class SOC](https://github.com/cyb3rxp/awesome-soc/blob/main/11-strategies-of-a-world-class-cybersecurity-operations-center.pdf), Strategy 7: Select and Collect the Right Data, pages 101-123, 
> Choose data by considering relative value of different data types such as sensor and log data
collected by network and host systems, cloud resources, applications, and sensors. Consider
the trade-offs of too little data and therefore not having the relevant information available and
too much data such that tools and analysts become overwhelmed.

* [11 strategies for a world-class SOC](https://github.com/cyb3rxp/awesome-soc/blob/main/11-strategies-of-a-world-class-cybersecurity-operations-center.pdf), Strategy 11: Turn up the Volume by Expanding SOC Functionality, pages 101-123,
> Enhance SOC activities to include threat hunting, red teaming, deception, malware analysis,
forensics, and/or tabletop exercises, once incident response is mature. Any of these can
improve the SOCs operating ability and increase the likelihood of finding more sophisticated
adversaries.


## Dedicated page
Cf. [detection engineering](https://github.com/cyb3rxp/awesome-soc/blob/main/detection_engineering.md).


# Threat intelligence

## MITRE reference
* [11 strategies for a world-class SOC](https://github.com/cyb3rxp/awesome-soc/blob/main/11-strategies-of-a-world-class-cybersecurity-operations-center.pdf), Strategy 6: Illuminate Adversaries with Cyber Threat Intelligence, pages 101-123,
> Tailor the collection and use of cyber threat intelligence by analyzing the intersection of
adversary information, organization relevancy, and technical environment to prioritize
defenses, monitoring, and other actions.

## Dedicated page
Cf. [threat intelligence](https://github.com/cyb3rxp/awesome-soc/blob/main/threat_intelligence.md).



# Playbooks

Based on experience, I propose a few SOP (Standard Operating Procedures), that one may want to call playbooks.

## Dedicated pages

- [Windows malware critical controls](https://github.com/cyb3rxp/awesome-soc/blob/main/sop_malware_critical_controls.md)
- [Microsoft 365 and Entra ID compromise assessment](https://github.com/cyb3rxp/awesome-soc/blob/main/sop_M365_compromise_assessment.md)
- [Web server compromise assessment](https://github.com/cyb3rxp/awesome-soc/blob/main/sop_web_server_compromise_assessment.md)


# Management

## MITRE reference
* [11 strategies for a world-class SOC](https://github.com/cyb3rxp/awesome-soc/blob/main/11-strategies-of-a-world-class-cybersecurity-operations-center.pdf), Strategy 1: Know What You Are Protecting and Why, pages 101-123
> Develop situational awareness through understanding the mission; legal regulatory
environment; technical and data environment; user, user behaviors and service interactions;
and the threat. Prioritize gaining insights into critical systems and data and iterate understanding
over time.

* [11 strategies for a world-class SOC](https://github.com/cyb3rxp/awesome-soc/blob/main/11-strategies-of-a-world-class-cybersecurity-operations-center.pdf), Strategy 3: Build a SOC Structure to Match Your Organizational Needs, pages 101-123
> Structure SOCs by considering the constituency, SOC functions and responsibilities, service
availability, and any operational efficiencies gained by selecting one construct over another

* [11 strategies for a world-class SOC](https://github.com/cyb3rxp/awesome-soc/blob/main/11-strategies-of-a-world-class-cybersecurity-operations-center.pdf), Strategy 9: Communicate Clearly, Collaborate Often, Share Generously, pages 101-123
> Engage within the SOC, with stakeholders and constituents, and with the broader cyber
community to evolve capabilities and contribute to the overall security of the broader
community.

* [11 strategies for a world-class SOC](https://github.com/cyb3rxp/awesome-soc/blob/main/11-strategies-of-a-world-class-cybersecurity-operations-center.pdf), Strategy 11: Turn up the Volume by Expanding SOC Functionality, pages 101-123
> Enhance SOC activities to include threat hunting, red teaming, deception, malware analysis,
forensics, and/or tabletop exercises, once incident response is mature. Any of these can
improve the SOCs operating ability and increase the likelihood of finding more sophisticated
adversaries.


## Dedicated page
Cf. [Management](https://github.com/cyb3rxp/awesome-soc/blob/main/management.md).


# SOC metrics (KPI/SLA)

## MITRE reference
* [11 strategies for a world-class SOC](https://github.com/cyb3rxp/awesome-soc/blob/main/11-strategies-of-a-world-class-cybersecurity-operations-center.pdf), Strategy 10: Measure Performance to Improve Performance, pages 101-123
> Determine qualitative and quantitative measures to know what is working well, and where to
improve. A SOC metrics program includes business objectives, data sources and collection,
data synthesis, reporting, and decision-making and action

## Dedicated page
Cf. [SOC metrics (KPI/SLA)](https://github.com/cyb3rxp/awesome-soc/blob/main/metrics-kpi.md)



# HR and training

## MITRE reference
* [11 strategies for a world-class SOC](https://github.com/cyb3rxp/awesome-soc/blob/main/11-strategies-of-a-world-class-cybersecurity-operations-center.pdf), Strategy 4: Hire AND Grow Quality Staff, pages 101-123
> Create an environment to attract the right people and encourage them to stay through career
progression opportunities and great culture and operating environment. Plan for turnover
and build a pipeline to hire. Consider how many personnel are needed for the different SOC
functions.

## Dedicated page
Cf. [HR and training](https://github.com/cyb3rxp/awesome-soc/blob/main/hr_training.md).


# IT achitecture of a SOC

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
*	Kaspersky, [AV / EP / EPP / EDR / XDR](https://usa.kaspersky.com/blog/introducing-kedr-optimum/27062/?reseller=usa_regular-sm_acq_ona_smm__onl_b2c_lii_post_sm-team______&utm_source=linkedin&utm_medium=social&utm_campaign=us_regular-sm_en0177&utm_content=sm-post&utm_term=us_linkedin_organic_pmgk1776sk4g1qp)
* Wavestone, [Security bastion (PAM) and Active Directory tiering mode: how to reconcile the two paradigms?](https://www.riskinsight-wavestone.com/en/2022/10/security-bastion-pam-and-active-directory-tiering-mode-how-to-reconcile-the-two-paradigms/)
* MalAPI, [list of Windows API and their potential use in offensive security](https://malapi.io/)
*	FireEye, [OpenIOC format](https://github.com/fireeye/OpenIOC_1.1/blob/master/IOC_Terms_Defs.md)
* Herman Slatman, [Awesome Threat Intel](https://github.com/hslatman/awesome-threat-intelligence)
*	Microsoft, [SOC/IR hierarchy of needs](https://github.com/swannman/ircapabilities) 
* Betaalvereniging, [TaHiTI (threat hunting methodology)](https://www.betaalvereniging.nl/wp-content/uploads/TaHiTI-Threat-Hunting-Methodology-whitepaper.pdf) 
* ANSSI (FR), [EBIOS RM methodology](https://messervices.cyber.gouv.fr/guides/en-ebios-risk-manager-method)
* GMU, [Improving Social Maturity of Cybersecurity Incident Response Teams](https://web.archive.org/web/20250816141217/https://edu.anarcho-copy.org/Against%20Security%20-%20Self%20Security/GMU_Cybersecurity_Incident_Response_Team_social_maturity_handbook.pdf)
* J0hnbX, [RedTeam resources](https://archive.org/details/github.com-J0hnbX-RedTeam-Resources_-_2022-02-20_01-12-12)
* Europa.eu, [TIBER EU](https://www.ecb.europa.eu/pub/pdf/other/ecb.tiber_eu_framework_2025~b32eff9a10.en.pdf?0309990e5e167a47ca4748370a949064)
* Fabacab, [Awesome CyberSecurity BlueTeam](https://github.com/fabacab/awesome-cybersecurity-blueteam)
* Microsoft, [Windows 10 and Windows Server 2016 security auditing and monitoring reference](https://www.microsoft.com/en-us/download/details.aspx?id=52630).
* iDNA, [how to mange FP in a SOC?](https://www.idna.fr/2018/11/06/comment-gerer-les-faux-positifs-dans-un-soc/), in FR
* Soufiane Tahiri, [Playbook for ransomware incident response](https://github.com/soufianetahiri/ransomware_Incident_Response_FR), in FR
* PwnDefend, [AD post-compromise checklist](https://www.pwndefend.com/2021/09/15/post-compromise-active-directory-checklist/)
* Gartner, [Market guide for NDR](https://stellarcyber.ai/learn/gartner-ndr/)
* Rawsec, [Resources inventory](https://inventory.raw.pm/resources.html)
* Quest, [Best practices for AD disaster recovery](https://www.quest.com/webcast-ondemandt/best-practices-for-active-directory-disaster-recovery/?param=L4qcdiH1R46lWbN5Jxs%2fNN0Qky57LDYQTnsyaoWVqKYZTocd3n1RpFTyQegqps0MbW7yx4UWSKyVRVyz%2bwo0XRB2%2fXpFzrMZeOA%2fne%2f4Fm3oH5YJAnFCP%2fnRqs9Rq%2fRD0VTXvdBaojCx5J46htyILvanM5FhOVa7MCGDGYBcq6925YtpmANy9OA1%2fjdtlDrp)
* Microsoft, [Isolate Tier 0 assets with group policy](https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/initially-isolate-tier-0-assets-with-group-policy-to-start/ba-p/1184934)
* Securenvoy, [How to be compliant with NIS2?](https://securenvoy.com/blog/how-to-be-compliant-with-new-nis-directive/)
* CyberVigilance, [Mitre Engenuity Evaluations 2022 review](https://www.cybervigilance.uk/post/2022-mitre-att-ck-engenuity-results)
* [Wazuh at the heart of a SOC architecture for public/critical infrastructures](https://medium.com/@ludovic.doamba/wazuh-at-the-heart-of-sovereign-soc-architecture-for-public-and-critical-infrastructures-f0d18562d14b)
* ENISA, [List of trusted cybersecurity services providers](https://www.enisa.europa.eu/sites/default/files/2025-07/EU%20Cybersecurity%20Reserve%20companies.pdf) 
red


## Nice to read
* NIST, [SP800-53 rev5 (Security and Privacy Controls for Information Systems and Organizations)](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
* Amazon,	[AWS Security Fundamentals](https://aws.amazon.com/fr/training/digital/aws-security-fundamentals/)   
* Microsoft, [PAW Microsoft](https://docs.microsoft.com/en-us/security/compass/privileged-access-devices) 
* CIS, [Business Impact Assessment](https://bia.cisecurity.org/) 
* Abdessabour Boukari, [RACI template (in French)](https://github.com/cyberabdou/SOC/blob/77f01ba82c22cb11028cde4a862ae0bea4258378/SOC%20RACI.xlsx) 
* Sekoia, [What is XDR?](https://www.sekoia.io/en/glossary/what-is-xdr/)
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
* Gartner, [PAM Magic Quadrant reprint](https://www.beyondtrust.com/resources/gartner-magic-quadrant-for-pam)
* Rawsec, [Tools inventory](https://inventory.raw.pm/tools.html)
* Microsoft, [command line reference](https://cmd.ms/)
* Microsoft, [Sentinel data collection scenarios](https://learn.microsoft.com/en-us/azure/sentinel/connect-cef-ama#how-collection-works-with-the-common-event-format-cef-via-ama-connector)
* SOC CMM, [SOCTOM](https://soc-cmm.com/img/upload/files/54-soctom-whitepaper.pdf)
* [PTES](http://www.pentest-standard.org/index.php/Main_Page)
* OWASP, [WSTG](https://owasp.org/www-project-web-security-testing-guide/)
* BitDefender, [Analyzing MITRE ATT&CK evaluations 2023](https://explore.bitdefender.com/epp-nurture-2023_2/blog-mitre-attck-evaluations-2023?cid=emm%7Cb%7Chubspot%7Cnrt-epp-2023&utm_campaign=nurture-epp-2023&utm_medium=email&_hsmi=280552612&utm_content=280552612&utm_source=hs_automation)
* Microsoft, [Licensing maps, eg. for Defender](https://m365maps.com/) & [Modern work plan comparison SMB](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/modern-work-plan-comparison-smb5.pdf)
* CyberFlooD [SwitchToOpen](https://github.com/CyberFlooD/SwitchToOpen)


## SOC sensors, nice to have
* **Dark Web monitoring** (data leaks, etc.)
  * My recommendation: [AIL Framework](https://github.com/CIRCL/AIL-framework)
  * for paid SaaS solutions, I recommend to have a look at this [top 10](https://expertinsights.com/insights/the-top-dark-web-monitoring-solutions/)
* **Deceptive technology:**
    * My recommendation: implement [AD decoy acounts](https://medium.com/securonix-tech-blog/detecting-ldap-enumeration-and-bloodhound-s-sharphound-collector-using-active-directory-decoys-dfc840f2f644) and [AD DNS canary](https://www.protect.airbus.com/blog/active-directory-a-canary-under-your-hat/)
* WAF for internet-facing websites/apps:
  * My recommendations:
     * FOSS: [Crowdsec WAF](https://www.crowdsec.net/solutions/application-security), [Bunkerweb](https://github.com/bunkerity/bunkerweb?tab=readme-ov-file=)
     * paid but good price: [CloudFlare](https://www.cloudflare.com/plans/)
* MDM:
  * My recommendation: [Microsoft Intune](https://docs.microsoft.com/en-us/mem/intune/fundamentals/what-is-intune)
* (full-featured) Honeypot:
  * My recommendation: [Canary.tools](https://canary.tools/)
  * Or, have a look at [Awesome honeypots Git](https://github.com/paralax/awesome-honeypots)
* Phishing and brand infringement protection (domain names):
  * My recommendation: [PhishLabs](https://www.phishlabs.com/), [Netcraft](https://www.netcraft.com/cybercrime/fraud-detection/)
* NIDS:
  * My recommendation: [Crowdsec](https://www.crowdsec.net/product/crowdsec-security-engine)
* NDR:
  * My recommendation: [Gatewatcher](https://www.gatewatcher.com/en/our-solutions/trackwatch/)
  * See [Gartner MAgic Quadrant for NDR](https://www.gatewatcher.com/en/resource/2025-gartner-magic-quadrant-for-network-detection-and-response/)
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
  * You may want to use throwable machines (virtual machines) for incident response or specific artefacts analysis. Here are my recommendations:
    * [Microsoft Developer virtual machines](https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/);
    * Windows 11 [clean-up script](https://github.com/simeononsecurity/Windows-Optimize-Harden-Debloat);
    * Windows 11 [hardening tool](https://apps.microsoft.com/detail/9p7ggfl7dx57?hl=en-US&gl=US)
    * If needed, [Flare-VM](https://github.com/mandiant/flare-vm) framework to automate security tools installation on analysts workstations;


# Appendix

## License
[CC-BY-SA](https://en.wikipedia.org/wiki/Creative_Commons_license)

## Special thanks
Yann F., Wojtek S., Nicolas R., Clément G., Alexandre C., Jean B., Frédérique B., Pierre d'H., Julien C., Hamdi C., Fabien L., Michel de C., Gilles B., Olivier R., Jean-François L., Fabrice M., Pascal R., Florian S., Maxime P., Pascal L., Jérémy d'A., Olivier C. x2, David G., Guillaume D., Patrick C., Lesley K., Gérald G., Jean-Baptiste V., Antoine C., David Q., Philippe M., ...
