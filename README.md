[![Awesome](https://awesome.re/badge.svg)](https://awesome.re) ![Last Update](https://img.shields.io/github/last-commit/cyb3rxp/awesome-soc) ![GitHub stars](https://img.shields.io/github/stars/cyb3rxp/awesome-soc?style=social) ![License](https://img.shields.io/github/license/cyb3rxp/awesome-soc) ![Contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen) ![Lychee](https://github.com/cyb3rxp/awesome-soc/actions/workflows/link-check.yml/badge.svg)
# Awesome SOC

An operational handbook and knowledge base to build, run and mature a SOC (including CSIRT). Covering:
- SOC basics
- detection engineering
- threat intelligence
- SOC metrics/KPI
- SOC automation
- AI use cases and best practices
- SOP (SOC playbooks)

Those are my view, based on my own experience as SOC/CSIRT analyst and team manager, as well as well-known papers. Focus is more on SOC than on CERT/CSIRT.

My motto is: without reaction (response), detection is useless.

NB: Generally speaking, SOC here refers to detection activity, and CERT/CSIRT to incident response activity. CERT is a well-known (formerly) US trademark, managed by [CERT-CC](https://www.sei.cmu.edu/about/divisions/cert/index.cfm), but I prefer the term [CSIRT](https://www.enisa.europa.eu/sites/default/files/publications/Incident_Management_guide.pdf) as it precisely refers to incident response.


# Table of Contents
* [Must read](#must-read)
* [Fundamental concepts](#Fundamental-concepts)
* [Mission-critical means (tools/sensors)](#mission-critical-means-toolssensors)
* [SOC internals/core](#soc-internals)
* [AI (ML, LLM, GenAI, Agentic AI)](#AI)
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
* **SOC build**:
  * MITRE, [11 strategies for a world-class SOC](https://www.mitre.org/publications/technical-papers/11-strategies-world-class-cybersecurity-operations-center) (or use [local file](https://github.com/cyb3rxp/awesome-soc/blob/main/11-strategies-of-a-world-class-cybersecurity-operations-center.pdf)): part 0 (Fundamentals).
  * FIRST, [Building a SOC](https://www.first.org/resources/guides/Factsheet_Building_a_SOC_start_small.pdf)
  * NCSC, [Building a SOC](https://www.ncsc.gov.uk/collection/building-a-security-operations-centre)
  * Gartner, [SOC model guide](https://fr.scribd.com/document/732782046/Gartner-SOC-Model-Guide-2023)
  * Splunk, [State of Security 2025](https://www.splunk.com/en_us/pdfs/gated/ebooks/state-of-security-2025.pdf)
  * Microsoft, [Secure your business with 365](https://learn.microsoft.com/en-us/microsoft-365/admin/security-and-compliance/m365b-security-best-practices?view=o365-worldwide) 
* **SOC training for interview**:
  * LetsDefend [SOC analyst interview questions](https://github.com/LetsDefend/SOC-Interview-Questions)
* **SOC management**:
  * FIRST, [ISO 27035 Practical value for CSIRT and SOCs ](https://www.first.org/resources/papers/conf2023/FIRSTCON23-TLPCLEAR-Benetis-ISO-27035-practical-value-for-CSIRTs-and-SOCs.pdf)
  * SANS, [2025 SOC survey](https://www.elastic.co/pdf/sans-soc-survey-2025.pdf)
  * SOC CMM, [SOC Metrics](https://www.soc-cmm.com/img/upload/files/31-soc-cmm-metrics-101.pdf)
* **SOC assessment**:
  * CMM, [SOC-CMM](https://www.soc-cmm.com/)
  * Rabobank CDC, [DeTTECT](https://github.com/rabobank-cdc/DeTTECT)
  * SANS, [Continous purple teaming](https://www.sans.org/blog/continuous-purple-teaming-practical-approach-strengthening-offensive-capabilities)


## For a CERT/CSIRT
* **Global overview**:
  * SANS, [Incident Response](https://www.sans.org/security-resources/glossary-of-terms/incident-response)
  * FlexibleIR, [IR phases](https://playbooks.flexibleir.com/incident-response-phases-best-practices/)
* **CSIRT build**:
  * FIRST, [CERT-in-a-box](https://www.first.org/resources/guides/cert-in-a-box.zip) 
  * FIRST, [CSIRT Services Framework](https://www.first.org/standards/frameworks/csirts/csirt_services_framework_v2.1)
* **Security incident response management**:
  * ENISA, [Good practice for incident management](https://www.enisa.europa.eu/publications/good-practice-guide-for-incident-management)
  * EE-ISAC [Incident Response whitepaper](https://www.ee-isac.eu/media/2023/05/EE-ISAC-Incident-Response-White-Paper.pdf)
  * LinkedIn Pulse, [Security incident management according to ISO 27035](https://www.linkedin.com/pulse/security-incident-management-according-iso-27035-dipen-das-)
  * Microsoft/EY/Edelman, [Incident response reference guide](https://www.linkedin.com/posts/the-cyber-security-hub_incident-response-reference-guide-activity-7033563558642642944-0zav?utm_source=share&utm_medium=member_desktop)
  * Microsoft, [IR lessons on cloud ID compromise](https://www.microsoft.com/en-us/security/blog/2023/12/05/microsoft-incident-response-lessons-on-preventing-cloud-identity-compromise/?msockid=07788c7fcb0c689a2a5d98f6ca0169fb)
* **Forensics**:
  * NIST, [SP800-86, integration forensics techniques into IR](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-86.pdf)
  * [ForensicsArtefacts](https://github.com/ForensicArtifacts/artifacts)
  * [ForensicsWiki](https://forensics.wiki/)
* **Incident response playbooks & methodology**:
  * Kaspersky, [Incident Response Playbook: Dark Web Breaches](https://dfi.kaspersky.com/blog/dark-web-threats-response-guideline#form)
  * CISA, [Incident Response playbooks](https://www.cisa.gov/sites/default/files/2024-08/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf)
  * CERT-SG, [Incident Response Methodology](https://github.com/certsocietegenerale/irm)

## Globally (SOC and CERT/CSIRT)
* **Processes and concepts**:
  * PAN, [What is SecOps?](https://www.paloaltonetworks.com/cyberpedia/what-is-security-operations)
  * Flavio Queiroz, [SecOPS vs. OPSEC](https://www.linkedin.com/pulse/clearing-fog-secops-vs-opsec-cybersecurity-flavio-queiroz--jfief/)
  * Shubham, [Security 360](https://twitter.com/Shubham_pen/status/1655192003448020993?s=20)
  * Vilius Benetis, [CSIRT, SOC, ISAC and PSIRT definitions](https://www.linkedin.com/pulse/csirt-soc-isac-psirt-definitions-vilius-benetis)
  * Thomas Roccia, [Visual Threat Intelligence](https://www.amazon.fr/Visual-Threat-Intelligence-Illustrated-Researchers/dp/B0C7JCF8XD)
  * SentinelOne, [What is SecOps](https://www.sentinelone.com/cybersecurity-101/secops/?utm_content=white-paper&utm_medium=paid-display&utm_source=gdn-paid&utm_campaign=emea-t1-en-g-dsa&utm_term={demo-request}&utm_campaignid=19179764064&gclid=EAIaIQobChMItYzg5amQ_gIV6pBoCR1u0ACxEAAYAiAAEgJ1ofD_BwE)
  * Purp1eW0lf, [Blue Team Notes](https://github.com/Purp1eW0lf/Blue-Team-Notes)
  * PAN, [Security orchestration for dummies](https://www.paloaltonetworks.com/content/dam/pan/en_US/assets/pdf/cortex-xsoar/Security-Orchestration-For-Dummies-Demisto-Special-Edition.pdf)
  * ThreatConnect, [SIRP / SOA / TIP benefits](https://threatconnect.com/blog/realizing-the-benefits-of-security-orchestration-automation-and-response-soar/)
  * Medium, [Compromise assessment methodology](https://evrenbey.medium.com/compromise-assessment-methodology-820910efb6a4)
  * Hunt.io, [Threat Hunting Framework](https://hunt.io/glossary/tahiti-threat-hunting-framework)
* **SOC/CSIRT processes**:
  * NIST, [SP800-61 rev3, incident handling guide](https://csrc.nist.gov/pubs/sp/800/61/r3/ipd)
* **CSIRT build**:
  * ENISA, [How to set-up a CSIRT and SOC](https://www.enisa.europa.eu/publications/how-to-set-up-csirt-and-soc)
* **Frameworks and materials**:
  * MITRE, [ATT&CK: Getting started](https://attack.mitre.org/resources/getting-started/)
  * NIST, [Cybersecurity framework](https://www.nist.gov/cyberframework)
  * FIRST, [CVSS v4 specs](https://www.first.org/cvss/v4-0/)
  * CERT-EU, [CTI Framework](https://www.cert.europa.eu/publications/threat-intelligence/cyber-threat-intelligence-framework/)
  * OASIS Open, [STIX](https://oasis-open.github.io/cti-documentation/stix/intro.html)
  * FIRST, [TLP](https://www.first.org/tlp/) (intelligence sharing and confidentiality), and [PAP](https://cert.ssi.gouv.fr/csirt/sharing-policy/)
  * CIS, [18 critical security controls](https://www.cisecurity.org/controls/cis-controls-list)
* **Security capabilities mappings**:
  * CTID, [Mappings explorer](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/)
* **Threat matrix**:
  * Push Security, [SaaS attack matrix](https://github.com/pushsecurity/saas-attacks#the-saas-attacks-matrix)
  * Microsoft, [Threat Matrix for Azure Storage services](https://microsoft.github.io/Threat-matrix-for-storage-services/)
  * MITRE, [Threat Matrix for AI-systems](https://github.com/mitre/advmlthreatmatrix/blob/master/pages/adversarial-ml-threat-matrix.md#adversarial-ml-threat-matrix)
* **SOAR solutions**:
  * Swimlane, [Cyber Threat readiness report 2023](https://swimlane.com/wp-content/uploads/Cyber-Threat-Readiness-Report-2023.pdf);
  * Gartner, [Market Guide for Security Orchestration, Automation and Response Solutions](https://fr.scribd.com/document/619736260/Gartner-Market-Guide-for-Security-Orchestration-Automation)
* **NIS2**:
  * NIS2Directive: [NIS2 10 main requirements](https://nis2directive.eu/nis2-requirements/) 
  * LinkedIn: [How will NIS2 impact your organization?](https://www.linkedin.com/pulse/how-eu-directive-nis2-impact-your-organization-anders-fleinert-larsen%3FtrackingId=Vq3GCGlOTXe1u0dllhn9MA%253D%253D/?_l=fr_FR)
  * Microsoft, [NIS2 webinar](https://info.microsoft.com/CE-NoGEP-VDEO-FY24-10Oct-09-What-is-NIS20-and-how-to-prepare-your-organization-and-customers-for-it-SREVM23845_LP02-Thank-You---Standard-Hero.html)
  * CyberArk: [NIS2, how to address the security control gaps](https://event.on24.com/eventRegistration/console/apollox/mainEvent?simulive=y&eventid=4110743&sessionid=1&username=&partnerref=&format=fhvideo1&mobile=&flashsupportedmobiledevice=&helpcenter=&key=588150776CAE70D7F02ECF2848FF11FA&newConsole=true&nxChe=true&newTabCon=true&consoleEarEventConsole=false&text_language_id=en&playerwidth=748&playerheight=526&eventuserid=600843623&contenttype=A&mediametricsessionid=517006274&mediametricid=5797475&usercd=600843623&mode=launch)
  * ENISA: [NIS2 technical implementation guidance](https://www.enisa.europa.eu/publications/nis2-technical-implementation-guidance)
* **AI (genAI, LLM, agentic AI): monitoring, threat landscape, management**:
  * CSOOnline, [SOCs face a challenge as AI speeds alerts and threats](https://www.csoonline.com/article/4198016/socs-face-a-human-challenge-as-ai-speeds-alerts-and-threats.html?utm_date=20260721140359&utm_campaign=CSO%20Security%20Leadership&utm_content=slotno-1-readmore-The%20future%20of%20the%20security%20operations%20center%20may%20depend%20less%20on%20technology%20than%20on%20how%20well%20security%20leaders%20manage%20human%20attention%2C%20expertise%2C%20and%20resilience.&utm_term=CSO%20US%20Editorial%20Newsletters&utm_medium=email&utm_source=Adestra&aid=8242015&huid=677465b3-4cd2-44f5-ba75-a9eb7364bc6c)
  * ETSI, [Baseline Cyber Security Requirements for AI Models and Systems](https://www.etsi.org/deliver/etsi_en/304200_304299/304223/02.01.01_60/en_304223v020101p.pdf)
  * NIST, [Challenges to the Monitoring of Deployed AI Systems](https://www.nist.gov/news-events/news/2026/03/new-report-challenges-monitoring-deployed-ai-systems)
  * NIST, [AI 100-1](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf)
  * OWASP, [Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
  * CISCO, [State of AI Security 2026](https://www.cisco.com/site/us/en/products/security/state-of-ai-security.html)
  * ENISA, [ENISA's view on cybersecurity in the frontier AI era](https://www.enisa.europa.eu/publications/enisas-view-on-cybersecurity-in-the-frontier-ai-era)
  * Microsoft [Turning threat reports into detection insights with AI](https://www.microsoft.com/en-us/security/blog/2026/01/29/turning-threat-reports-detection-insights-ai/)
* **Management**:
  * Gartner, [Cybersecurity business value benchmark](https://emtemp.gcom.cloud/ngw/globalassets/en/doc/documents/775537-gartner-cybersecurity-business-value-benchmark-1st-generation.pdf)
  * CrowdStrike, [State of SIEM market 2025](https://go.crowdstrike.com/rs/281-OBQ-266/images/Whitepaper2025StateofSIEMMarketCribl.pdf?version=0)
  * Microsoft, ["While the initial trigger event was a Distributed Denial-of-Service (DDoS) attack... initial investigations suggest that an error in the implementation of our defences amplified the impact of the attack rather than mitigating it"](https://www.bbc.com/news/articles/c903e793w74o)
* **SOP (Standard Operating Procedures)**:
  * [Antimalware check SOP](https://github.com/cyb3rxp/awesome-soc/blob/main/sop_malware_critical_controls.md)
  * [M365/Azure compromise asssessment SOP](https://github.com/cyb3rxp/awesome-soc/blob/main/sop_M365_compromise_assessment.md)
  * [Web server compromise assessment SOP](https://github.com/cyb3rxp/awesome-soc/blob/main/sop_web_server_compromise_assessment.md)


# Fundamental concepts

## Concepts, tools, missions, attack lifecycle, red/blue/purple teams

## MITRE references
* [11 strategies for a world-class SOC](https://github.com/cyb3rxp/awesome-soc/blob/main/11-strategies-of-a-world-class-cybersecurity-operations-center.pdf), Strategy 5: Prioritize Incident Response, pages 101-123,
> Prepare for handling incidents by defining incident categories, response steps, and escalation
paths, and codifying those into SOPs and playbooks. Determine the priorities of incidents for
the organization and allocate the resources to respond. Execute response with precision and
care toward constituency mission and business.

## Dedicated page
Cf. [SOC/CSIRT Basic and fundamental concepts](https://github.com/cyb3rxp/awesome-soc/blob/main/soc_basics.md).


# Mission-critical means (tools/sensors)

## MITRE reference
* [11 strategies for a world-class SOC](https://github.com/cyb3rxp/awesome-soc/blob/main/11-strategies-of-a-world-class-cybersecurity-operations-center.pdf), Strategy 7: Select and Collect the Right Data, pages 101-123,
> Choose data by considering relative value of different data types such as sensor and log data
collected by network and host systems, cloud resources, applications, and sensors. Consider
the trade-offs of too little data and therefore not having the relevant information available and
too much data such that tools and analysts become overwhelmed.

## Dedicated page
Cf. [Mission-critical means](https://github.com/cyb3rxp/awesome-soc/blob/main/mission-critical-means.md)


# SOC internals

## MITRE reference

* [11 strategies for a world-class SOC](https://github.com/cyb3rxp/awesome-soc/blob/main/11-strategies-of-a-world-class-cybersecurity-operations-center.pdf), Strategy 8: Leverage Tools to Support Analyst Workflow, pages 101-123,
> Consolidate and harmonize views into tools and data and integrate them to maximize SOC
workflow. Consider how the many SOC tools, including SIEM, UEBA, SOAR, and others fit
in with the organization’s technical landscape, to include cloud and OT environments

## Dedicated page
Cf. [SOC internals/core](https://github.com/cyb3rxp/awesome-soc/blob/main/soc_internals.md)


# AI

## MITRE reference

* [11 strategies for a world-class SOC](https://github.com/cyb3rxp/awesome-soc/blob/main/11-strategies-of-a-world-class-cybersecurity-operations-center.pdf), Strategy 8: Leverage Tools to Support Analyst Workflow, pages 101-123,
> Consolidate and harmonize views into tools and data and integrate them to maximize SOC
workflow. Consider how the many SOC tools, including SIEM, UEBA, SOAR, and others fit
in with the organization’s technical landscape, to include cloud and OT environments

## Dedicated page
Cf. [AI (ML, LLM, Agentic AI...)](https://github.com/cyb3rxp/awesome-soc/blob/main/ml_llm_ai.md)


# IT/security Watch 

## MITRE reference
* [11 strategies for a world-class SOC](https://github.com/cyb3rxp/awesome-soc/blob/main/11-strategies-of-a-world-class-cybersecurity-operations-center.pdf), Strategy 6: Illuminate Adversaries with Cyber Threat Intelligence, pages 101-123,
> Tailor the collection and use of cyber threat intelligence by analyzing the intersection of
adversary information, organization relevancy, and technical environment to prioritize
defenses, monitoring, and other actions.

## Dedicated page
Cf. [Watch](https://github.com/cyb3rxp/awesome-soc/blob/main/watch.md)

# SOAR

## MITRE reference
* [11 strategies for a world-class SOC](https://github.com/cyb3rxp/awesome-soc/blob/main/11-strategies-of-a-world-class-cybersecurity-operations-center.pdf), Strategy 8: Leverage Tools to Support Analyst Workflow, pages 101-123,
> Consolidate and harmonize views into tools and data and integrate them to maximize SOC
workflow. Consider how the many SOC tools, including SIEM, UEBA, SOAR, and others fit
in with the organization’s technical landscape, to include cloud and OT environments.


## Dedicated page
Cf. [SOAR](https://github.com/cyb3rxp/awesome-soc/blob/main/soar.md)


# Detection engineering

## MITRE references
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

## MITRE references
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

## 📚 **Must Read**
*Essential resources to build, run, and mature your SOC/CSIRT.*

###  **Frameworks & Methodologies**
- [MITRE, 11 strategies for a world-class SOC](11-strategies-of-a-world-class-cybersecurity-operations-center.pdf) *(PDF included in the repository)* – Comprehensive MITRE guide to building a high-performance SOC.
- [MITRE, SOC/IR hierarchy of needs](https://www.microsoft.com/en-us/security/business/soc-hierarchy-of-needs) – Framework for SOC/IR maturity.
- [Betaalvereniging, TaHiTI (threat hunting methodology)](https://www.betaalvereniging.nl/en/knowledge/threat-hunting-methodology/) – Structured threat hunting methodology.
- [Hunt.io, PEAK threat hunting framework](https://www.hunt.io/peak-threat-hunting-framework) – Framework for advanced threat hunting.
- [ANSSI (FR), EBIOS RM methodology](https://www.ssi.gouv.fr/guide/ebios-risk-manager/) – French risk management methodology.
- [GMU, Improving Social Maturity of Cybersecurity Incident Response Teams](https://cyber.gmu.edu/research/labs/csirt/improving-social-maturity/) – Research on CSIRT team dynamics.

###  **Roles & Responsibilities**
- [CISA, Cyber Defense Incident Responder role](https://www.cisa.gov/cybersecurity-and-infrastructure-security-agency/cyber-defense-incident-responder-role) – Role definition and responsibilities for incident responders.

###  **Threat Intelligence & Hunting**
- [MalAPI, list of Windows API and their potential use in offensive security](https://malapi.io/) – Windows API references for offensive/defensive security.
- [FireEye, OpenIOC format](https://www.fireeye.com/current-threats/annual-threat-report.html) – Open standard for sharing threat intelligence.
- [Herman Slatman, Awesome Threat Intel](https://github.com/hslatman/awesome-threat-intelligence) – Curated list of threat intelligence resources.

### **Compliance & Regulations**
- [Securenvoy, How to be compliant with NIS2?](https://www.securenvoy.com/en/nis2-compliance/) – Practical guide for NIS2 compliance.
- [ENISA, List of trusted cybersecurity services providers](https://www.enisa.europa.eu/topics/cybersecurity-certification/trusted-services) – List of trusted cybersecurity service providers in the EU.

### **Tools & Architectures**
- [Kaspersky, AV / EP / EPP / EDR / XDR](https://www.kaspersky.com/blog/av-ep-epp-edr-xdr/) – Explanation of endpoint security technologies.
- [Wavestone, Security bastion (PAM) and Active Directory tiering mode](https://www.wavestone.com/en/insight/security-bastion-pam-and-active-directory-tiering-mode/) – How to reconcile PAM and AD tiering.
- [PwnDefend, AD post-compromise checklist](https://github.com/pwndefend/AD-Post-Compromise-Checklist) – Checklist for Active Directory compromise assessment.
- [Quest, Best practices for AD disaster recovery](https://www.quest.com/solutions/disaster-recovery/active-directory/) – AD disaster recovery best practices.
- [Microsoft, Isolate Tier 0 assets with group policy](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-parameters-for-isolating-tier-0-assets) – Guide to isolate Tier 0 assets.
- [Gartner, Market guide for NDR](https://www.gartner.com/en/documents/4016572) – Market analysis of Network Detection and Response solutions.
- [Rawsec, Resources inventory](https://github.com/rawsec/rawsec-inventory) – Inventory of cybersecurity resources.
- [RecordedFuture](https://www.recordedfuture.com/threat-intelligence-101/tools-and-technologies/osint-tools) - Role of OSINT tools, brief history, and how to use these popular tools to deliver crucial intelligence insights.
- [MDRProviders.io, comparison of managed detection and response providers](https://www.mdrproviders.io/) – Comparison of MDR providers by pricing, SLA, and breach warranty.

###  **Use Cases & Implementations**
- [Microsoft, Windows 10 and Windows Server 2016 security auditing and monitoring reference](https://docs.microsoft.com/en-us/windows-server/security/auditing/security-auditing) – Auditing and monitoring guide for Windows.
- [Medium, Wazuh at the heart of a SOC architecture for public/critical infrastructures](https://medium.com/@wazuh/wazuh-at-the-heart-of-a-soc-architecture-for-public-critical-infrastructures-1234567890) – Use case for Wazuh in SOC architectures.
- [CyberVigilance, Mitre Engenuity Evaluations 2022 review](https://www.cybervigilance.fr/mitre-engenuity-evaluations-2022-review/) *(in French)* – Review of MITRE Engenuity evaluations.

### **French-Specific Resources**
- [iDNA, how to manage FP in a SOC?](https://www.idna.fr/en/how-to-manage-false-positives-in-a-soc/) *(in French)* – Guide for handling false positives in a SOC.
- [Soufiane Tahiri, Playbook for ransomware incident response](https://www.linkedin.com/pulse/playbook-for-ransomware-incident-response-soufiane-tahiri/) *(in French)* – Ransomware response playbook.


## 📖 **Nice to Read**
*Additional resources to expand your knowledge.*

### **Standards & Controls**
- [NIST, SP800-53 rev5 (Security and Privacy Controls)](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) – Security and privacy controls for information systems.
- [CIS, Business Impact Assessment](https://www.cisecurity.org/controls/business-impact-assessment) – Guide for assessing business impact of cyber incidents.
- [RFC2350 (CERT description)](https://tools.ietf.org/html/rfc2350) – Framework for describing a CERT.
- [SOC CMM, SOCTOM](https://soc-cmm.com/soc-tom/) – SOC maturity model and tool.
- [PTES](http://www.pentest-standard.org/index.php/Pentesting_Standard) – Penetration Testing Execution Standard.
- [OWASP, WSTG](https://owasp.org/www-project-web-security-testing-guide/) – Web Security Testing Guide.

### **Cloud & Platforms**
- [Amazon, AWS Security Fundamentals](https://aws.amazon.com/training/digital/aws-security-fundamentals/) – AWS security best practices.
- [Microsoft, PAW Microsoft](https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/privileged-access-workstations) – Privileged Access Workstation (PAW) guidance.
- [Elastic, BEATS agents](https://www.elastic.co/beats/)** – Lightweight agents for data collection.

### **Incident Response**
- [Incident Response & Computer Forensics, 3rd ed](https://www.amazon.com/Incident-Response-Computer-Forensics-Third/dp/007180131X) – Book on incident response and forensics.
- [Soufiane Tahiri, Digital Forensics Incident Response Git](https://github.com/soufiane-tahiri/DFIR) – DFIR resources and tools.
- [Austin Songer, Incident playbook](https://github.com/AustinSonger/Incident-Playbooks) – Collection of incident response playbooks.
- [CISA, Cybersecurity incident and vulnerability response playbooks](https://www.cisa.gov/resources-tools/services/cybersecurity-incident-and-vulnerability-response-playbooks) – Ready-to-use playbooks for incident response.

#### **SOC Tools & Architectures**
- [V1D1AN's Drawing: architecture of detection](https://v1d1an.github.io/2021/03/22/architecture-of-detection.html) – Visual representation of detection architectures.
- [Reprise99, Microsoft Sentinel queries](https://github.com/Reprise99/Sentinel-Queries) – KQL queries for Microsoft Sentinel.
- [MyFaberSecurity, MS Sentinel architecture and recommendations for MSSP](https://myfabersecurity.com/microsoft-sentinel-architecture-and-recommendations-for-mssp/) – Architecture and best practices for Microsoft Sentinel.
- [Microsoft, command line reference](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/windows-commands) – Windows command-line reference.
- [Microsoft, Sentinel data collection scenarios](https://docs.microsoft.com/en-us/azure/sentinel/data-collection-scenarios) – Scenarios for data collection in Microsoft Sentinel.
- [Microsoft, Licensing maps](https://docs.microsoft.com/en-us/microsoft-365/enterprise/licensing-maps?view=o365-worldwide) – Licensing comparison for Microsoft Defender and Modern Work plans.

### **Training & Surveys**
- [SANS SOC survey 2022](https://www.sans.org/reading-room/whitepapers/analyst/2022-sans-soc-survey/) – Results of the 2022 SANS SOC survey.
- [Gartner, PAM Magic Quadrant reprint](https://www.gartner.com/en/documents/4016568) – Market analysis of Privileged Access Management solutions.
- [BitDefender, Analyzing MITRE ATT&CK evaluations 2023](https://www.bitdefender.com/blog/labs/analyzing-mitre-attck-evaluations-2023/) – Analysis of MITRE ATT&CK evaluations.

### **Miscellaneous Resources**
- [Awesome Security Resources](https://github.com/vhf/awesome-security) – Curated list of security resources.
- [CyberFlooD SwitchToOpen](https://github.com/CyberFlooD/SwitchToOpen) – Guide to switch from proprietary to open-source security tools.
- [GDPR cybersecurity implications](https://www.cnil.fr/en/gdpr-and-cybersecurity) *(in French)* – GDPR implications for cybersecurity.
- [Abdessabour Boukari, RACI template](https://github.com/abdessabour/RACI-template) *(in French)* – RACI matrix template for SOC/CSIRT roles.
- [Sekoia, What is XDR?](https://www.sekoia.io/blog/what-is-xdr/) – Explanation of Extended Detection and Response (XDR).
- [Rawsec, Tools inventory](https://github.com/rawsec/rawsec-tools-inventory) – Inventory of security tools.

## SOC sensors, nice to have
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
  * My recommendation: [Crowdsec](https://www.crowdsec.net/product/crowdsec-security-engine), [ftagent-lite](https://github.com/Flowtriq/ftagent-lite) for lightweight flow-based network monitoring and DDoS detection (sFlow/NetFlow/IPFIX, adaptive baseline anomaly detection)
* NDR:
  * My recommendation: [Gatewatcher](https://www.gatewatcher.com/en/our-solutions/trackwatch/)
  * See [Gartner MAgic Quadrant for NDR](https://www.gatewatcher.com/en/resource/2026-gartner-magic-quadrant-for-network-detection-and-response/)
* DLP:
  * See [Gartner reviews and ratings](https://www.gartner.com/reviews/market/data-loss-prevention)
* OT (industrial) NIDS:
  * My recommendation: [Nozomi Guardian](https://www.nozominetworks.com/products/guardian/)
* Network TAP:
  * My recommendation: [Gigamon](https://www.gigamon.com/products/access-traffic/network-taps.html)
* Mobile network security (2G/3G):
  * My recommendation: Dust Mobile.


## Harden SOC/CSIRT environment
* Implement hardening measures on SOC workstations, servers, and IT services that are used (if possible), e.g.:
   * CIS [Benchmarks](https://www.cisecurity.org/);
   * Microsoft [Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319);
   * NIST, [SP800-63B: Digital Identity Guidelines](https://pages.nist.gov/800-63-4/sp800-63b.html)
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
