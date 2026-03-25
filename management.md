# SOC/CSIRT management: 
This page deals with SOC and CERT management

# Table of Contents

* [Must read](#must-read)
* [Challenges](#challenges)
* [SOC organization](#soc-organization)
* [CSIRT organization](#csirt-organization)
* [TTP knowledge base reference](#ttp-attack-methods-knowledge-base-reference)
* [Data quality and management](#data-quality-and-management)
* [Key documents for a SOC](#key-documents-for-a-soc)
* [Detection assessment](#detection-quality-assessment)
* [Global self assessment](#global-self-assessment)
* [To go further](#to-go-further)

# Must read

## Articles/recordings
* FIRST, [Building a SOC](https://www.first.org/resources/guides/Factsheet_Building_a_SOC_start_small.pdf) 
* NCSC, [Building a SOC](https://www.ncsc.gov.uk/collection/building-a-security-operations-centre)
* FIRST, [CERT-in-a-box](https://www.first.org/resources/guides/cert-in-a-box.zip) 
* FIRST, [CSIRT Services Framework](https://www.first.org/standards/frameworks/csirts/csirt_services_framework_v2.1)
* ENISA, [Good practice for incident management](https://www.enisa.europa.eu/publications/good-practice-guide-for-incident-management)
* CIS, [18 critical security controls](https://www.cisecurity.org/controls/cis-controls-list)
* CMM, [SOC-CMM](https://www.soc-cmm.com/img/upload/files/32-soc-cmm-whitepaper.pdf)
* Linkedin Pulse, [Evolution Security Operations Center](https://www.linkedin.com/pulse/evolution-security-operations-center-lakshminarayanan-kaliyaperumal/)
* Gartner, [Cybersecurity business value benchmark](https://emtemp.gcom.cloud/ngw/globalassets/en/doc/documents/775537-gartner-cybersecurity-business-value-benchmark-1st-generation.pdf)
* Gartner, [Priorities navigator for CISOs](https://view.ceros.com/gartner/sec31-priorities-navigator/p/1)
* LogRythm, [7 metrics to measure the effectiveness of your SOC](https://www.compuquip.com/hubfs/Vendors/LogRhythm/LogRhythm-7-Metrics-to-Measure-the-Effectiveness-of-Your-SOC-Ebook.pdf?hsCtaTracking=6f44e275-b498-4bee-af8e-c5c5b7aca241%7Cec4bcb3b-9186-4252-a4df-2e9efd8c4d47)
* Google, [Modernize your SOC for the future](https://www.brighttalk.com/webcast/18282/565440?utm_source=brighttalk-recommend&utm_campaign=network_weekly_email&utm_medium=email&utm_content=company&utm_term=132023)
* DogeSec, [Getting started with ATT&CK heatmaps](https://www.dogesec.com/blog/getting_started_attck_navigator/)
* TheHackerNews, [NIST CSF v2](https://thehackernews.com/2024/09/nist-cybersecurity-framework-csf-and.html)
* First, [ISO 27035 Practical value for CSIRT and SOCs ](https://www.first.org/resources/papers/conf2023/FIRSTCON23-TLPCLEAR-Benetis-ISO-27035-practical-value-for-CSIRTs-and-SOCs.pdf)
* Infoblox, [NIS2 & NCSC CAF](https://insights.infoblox.com/solution-notes/infoblox-solution-note-nis2-and-the-caf-framework)


# Challenges

## Generic ones

As per the [aforementioned article](https://www.linkedin.com/pulse/evolution-security-operations-center-lakshminarayanan-kaliyaperumal/), here are some typical challenges for a SOC/CSIRT:

![image](https://user-images.githubusercontent.com/16035152/205918584-361ba50e-cf5f-48d6-b115-7df9645ed36b.png)


## After pandemic

As per the [aforementioned article](https://www.linkedin.com/pulse/evolution-security-operations-center-lakshminarayanan-kaliyaperumal/), I recommend to keep in mind the following common challenges:

![image](https://user-images.githubusercontent.com/16035152/205914475-2fc16916-e4c8-47ea-a518-a288b98cc7d6.png)

# SOC organization
## Tiering or not tiering?
* No real need for tiering (L1/L2/L3)
  * this is an old model for service provider, not necesserarily for a SOC!
  * as per [MITRE paper](https://github.com/cyb3rxp/awesome-soc/blob/main/11-strategies-of-a-world-class-cybersecurity-operations-center.pdf) (p65):
  >In this book, the constructs of “tier 1” and “tier 2+” are sometimes used to describe analysts
who are primarily responsible for front-line alert triage and in-depth investigation/analysis/
response, respectively. However, not all SOCs are arranged in this manner. In fact, some
readers of this book are probably very turned off by the idea of tiering at all [38]. Some
industry experts have outright called tier 1 as “dead” [39]. Once again, every SOC is different,
and practitioners can sometimes be divided on the best way to structure operations. SOCs
which do not organize in tiers may opt for an organizational structure more based on function.
Many SOCs that have more than a dozen analysts find it necessary and appropriate to tier
analysis in response to these goals and operational demands. Others do not and yet still
succeed, both in terms of tradecraft maturity and repeatability in operations. Either arrangement
can succeed if by observing the following tips that foreshadow a longer conversation about
finding and nurturing staff in “Strategy 4: Hire AND Grow Quality Staff.”

  > Highly effective SOCs enable their staff to reach outside their assigned
duties on a routine basis, regardless of whether they use “tier” to
describe their structure.

## SOC teams
* Instead of tiering, 3 different teams should be needed, based on experience:
  * **security monitoring team** (which does actually the "job" of detecting security incident being fully autonomous)
  * **security monitoring engineering team** (which fixes/improves security monitoring like SIEM rules and SOA playbooks, generates reportings, helps with uncommon use cases handling)
  * **build / project management team** (which does tools integration, SIEM data ingestion, specific DevOps tasks, project management).
 
## SOC shifts for 24*7
* There is a huge difference between "on-call" and "24x7":
  * "on-call" service is supposed to handle pre-validated types of alerts, with maximum severity and urgency.
  * "24x7" service is supposed to provide same quality of service, no matter the time of day and date it is (night, WE, holidays).
 
* Here is an example of teams shifts to really achieve "24x7":
![image](https://github.com/user-attachments/assets/f7a3d44c-a209-41cb-81b0-4c55ea2ca648)

Source: [LinkedIn article](https://www.linkedin.com/posts/teodorchabin_soc-cybersaezcuritaez-activity-7223975633607897089-Hhrw?utm_source=share&utm_medium=member_android)


## RACI

* Define a RACI, above all if you contract with an MSSP. 
  * You may want to consider [my own template](https://github.com/cyb3rxp/awesome-soc/blob/main/SOC_RACI_template_v1.0.xlsx)

# CSIRT organization
* Designate among team analysts: 
  * triage officer;
  * incident handler;
  * incident manager;
  * deputy CERT manager.
* Generally speaking, follow best practices as described in ENISA's ("Good practice for incident management", see ["Must read"](https://github.com/cyb3rxp/awesome-soc/blob/main/README.md#for-a-cert))

# TTP (attack methods) knowledge base reference
* Use [MITRE ATT&CK](https://attack.mitre.org/matrices/enterprise/)
* Document all detections (SIEM Rules, etc.) using MITRE ATT&CK ID, whenever possible.

# Data quality and management
* Implement an information model, like the [Splunk CIM one](https://docs.splunk.com/Documentation/CIM/5.0.1/User/Overview):
  * do not hesitate to extend it, depending on your needs
  * make sure this datamodel is being implemented in the SIEM, SIRP, SOA and even TIP.

# Key documents for a SOC
* Document an **audit policy**, that is tailored of the detection needs/expectations of the SOC:
  * the document aims to answer a generic question: what to audit/log, on which equipments/OSes/services/apps?
  * Take the [Yamato Security work](https://github.com/Yamato-Security/EnableWindowsLogSettings#smbclient-security-log-2-sigma-rules) as an exemple regarding an audit policy required for the Sigma community rules.
  * Don't forget to read the [Microsoft Windows 10 and Windows Server 2016 security auditing and monitoring reference](https://www.microsoft.com/en-us/download/details.aspx?id=52630).
* Document a **detection strategy**, tailored to the needs and expectations regarding the SOC capabilities.
  * The document will aim at listing the detection rules (SIEM searches, for instance), with key examples of results, and an overview of handling procedures.
* Document and keep up-to-date a detection matrix, which aims at representing the detection capabilities, for designated (feared) events and as per the security sensors known capabilities.
  * You may want to have a look at [my detection matrix template](https://github.com/cyb3rxp/awesome-soc/blob/main/detection_matrix.md).


# Detection quality assessment
 * **Run regular [Purple teaming](https://docs.vectr.io/user/important-concepts/) sessions** in time!!
   * e.g.: [Intrinsec](https://www.intrinsec.com/purple-team/), [SpecterOps](https://specterops.io/news/specterops-introduces-purple-team-assessments-service-to-help-customers-understand-the-efficacy-of-their-detection-capabilities/)
   * To do it on your own, here are a few recommended frameworks/tools:
       * Frameworks:
         * [TIBER EU](https://www.ecb.europa.eu/pub/pdf/other/ecb.tiber_eu_framework_2025~b32eff9a10.en.pdf?0309990e5e167a47ca4748370a949064)
         * [CTID](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/tree/master)
       * Tools:
         * RedCanary [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
         * Filigran [OpenAEV](https://github.com/OpenAEV-Platform/openaev)
         * [Ytisf's zoo](https://github.com/ytisf/theZoo)
         * Abuse.ch [Malware Bazaar](https://bazaar.abuse.ch/)
         * Knowbe4 [ransomware simulator](https://www.knowbe4.com/ransomware-simulator)
   * NB: don't forget to watermark the offensive tools being used! See [ProtectMyTooling](https://web.archive.org/web/20230209131745/https://mgeeky.tech/protectmytooling/)
 * Picture the currently confirmed detection capabilities thanks to purpleteaming, with tools based on ATT&CK:
   * e.g.: [Vectr](https://github.com/securityriskadvisors/vectr)


# Detection capabilities representation 

## Standard for security technologies
*	Use [Security Stack Mappings](https://github.com/center-for-threat-informed-defense/security-stack-mappings) to picture detection capabilities for a given security solution/environment (like AWS, Azure, NDR, etc.): 

## SOC detection capabilities **simplified** view
 * Leverage the [DeTTECT framework]()
 * Leverage the [RE&CT framework](https://atc-project.github.io/react-navigator/) to drive detection activities

# Response capabilities representation :

## Response simplified view
* Leverage the [RE&CT framework](https://atc-project.github.io/react-navigator/) to drive generic and fundamental containment actions.


# Global self-assessment

## Generic / compliance assessment
* Pick-up a security standard and run an assessment thanks to [CISO Assistant](https://github.com/intuitem/ciso-assistant-community)

## SOC Self-assessment
*	SOC Basics:
 	*	Run the [Google SecOps assessment](https://securityassessments.withgoogle.com/secops/)
*	Thorough SOC assessment:
 	*	Read the [SOC Cyber maturity model](https://www.soc-cmm.com/introduction/) from CMM
 	*	Run the [SOC-CMM self-assessment tool](https://www.soc-cmm.com/downloads/latest/)


## CERT/CSIRT self-assessment
* Read the [OpenCSIRT cybersecurity maturity framework](https://www.enisa.europa.eu/topics/incident-response/csirt-capabilities/csirt-maturity) from ENISA 
  * Run the OpenCSIRT, [SIM3 self-assessment](https://sim3-check.opencsirt.org/#/v1/) 

  


# To go further

## Priorities
* **Define SOC priorities, with feared events and offensive scenarios (TTP) to be monitored**, as per risk analysis results.
  * My recommendation: leverage EBIOS RM methodology (see [Detection engineering](https://github.com/cyb3rxp/awesome-soc/blob/main/detection_engineering.md#define-risk-prioritization-as-per-bia)).

## Detections enhancements
* Leverage machine learning, wherever it can be relevant in terms of good ratio false positives / real positives.
  * My recommendations: be careful, try not to saturate SOC consoles with FP, and don't forget to grab the required context to be able to analyze (verify) the detection!

## Leverage best practices:
* Make sure to **follow the 11 strategies for a (world class) SOC**, as per MITRE paper (see [Must Read](https://github.com/cyb3rxp/awesome-soc/blob/main/README.md#must-read)).

## Follow the security industry standards:
* Publish your RFC2350, declaring what your CERT is (see ['Nice to read' on the main page](https://github.com/cyb3rxp/awesome-soc/blob/main/README.md#to-go-further))


# End

Go to [main page](https://github.com/cyb3rxp/awesome-soc)
