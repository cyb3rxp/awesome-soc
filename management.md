# SOC/CSIRT management: 
This page deals with SOC and CERT management

# Table of Content

* [Must read](https://github.com/cyb3rxp/awesome-soc/blob/main/management.md#must-read)
* [Challenges](https://github.com/cyb3rxp/awesome-soc/blob/main/management.md#challenges)
* [SOC organization](https://github.com/cyb3rxp/awesome-soc/blob/main/management.md#soc-organization)
* [CSIRT organization](https://github.com/cyb3rxp/awesome-soc/blob/main/management.md#csirt-organization)
* [TTP knowledge base reference](https://github.com/cyb3rxp/awesome-soc/blob/main/management.md#ttp-attack-methods-knowledge-base-reference)
* [Data quality and management](https://github.com/cyb3rxp/awesome-soc/blob/main/management.md#data-quality-and-management)
* [Key documents for a SOC](https://github.com/cyb3rxp/awesome-soc/blob/main/management.md#key-documents-for-a-soc)
* [Detection assessment](https://github.com/cyb3rxp/awesome-soc/blob/main/management.md#detection-quality-assessment)
* [Global self assessment](https://github.com/cyb3rxp/awesome-soc/blob/main/management.md#global-self-assessment)
* [Reporting](https://github.com/cyb3rxp/awesome-soc/blob/main/management.md#reporting)
* [To go further](https://github.com/cyb3rxp/awesome-soc/blob/main/management.md#to-go-further)

# Must read

## Articles/recordings
* FIRST, [Building a SOC](https://www.first.org/resources/guides/Factsheet_Building_a_SOC_start_small.pdf) 
* NCSC, [Building a SOC](https://www.ncsc.gov.uk/collection/building-a-security-operations-centre)
* FIRST, [CERT-in-a-box](https://www.first.org/resources/guides/cert-in-a-box.zip) 
* FIRST, [CSIRT Services Framework](https://www.first.org/standards/frameworks/csirts/csirt_services_framework_v2.1)
* ENISA, [Good practice for incident management](https://www.enisa.europa.eu/publications/good-practice-guide-for-incident-management)
* CIS, [8 critical security controls](https://www.cisecurity.org/controls/cis-controls-list)
* CMM, [SOC-CMM](https://www.soc-cmm.com/downloads/soc-cmm%20whitepaper.pdf)
* Linkedin Pulse, [Evolution Security Operations Center](https://www.linkedin.com/pulse/evolution-security-operations-center-lakshminarayanan-kaliyaperumal/)
* Gartner, [Cybersecurity business value benchmark](https://emtemp.gcom.cloud/ngw/globalassets/en/doc/documents/775537-gartner-cybersecurity-business-value-benchmark-1st-generation.pdf)
* LogRythm, [7 metrics to measure the effectiveness of your SOC](https://www.compuquip.com/hubfs/Vendors/LogRhythm/LogRhythm-7-Metrics-to-Measure-the-Effectiveness-of-Your-SOC-Ebook.pdf?hsCtaTracking=6f44e275-b498-4bee-af8e-c5c5b7aca241%7Cec4bcb3b-9186-4252-a4df-2e9efd8c4d47)
* Google, [Modernize your SOC for the future](https://www.brighttalk.com/webcast/18282/565440?utm_source=brighttalk-recommend&utm_campaign=network_weekly_email&utm_medium=email&utm_content=company&utm_term=132023)
* Signalblur, [Getting started with ATT&CK heatmaps](https://www.signalblur.io/getting-started-with-mitres-att-ck-navigator/)
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
 
## SOF shifts (24*7)
* There is a huge difference between "on-call" and "24x7":
  * "on-call" service is supposed to handle pre-validated types of alerts, with maximum severity and urgency.
  * "24*7" service is supposed to provide same quality of service, no matter the time of day and date it is (night, WE, holidays).
 
* Here is an example of teams shifts to really achieve "24*7":
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
 * **Run regular [purpleteaming sessions](https://about.gitlab.com/handbook/engineering/security/threat-management/red-team/purple-teaming/)** in time!!
   * e.g.: [Intrinsec](https://www.intrinsec.com/purple-team/), [FireEye](https://www.fireeye.fr/content/dam/fireeye-www/regional/fr_FR/services/pdfs/ds-purple-team-assessment.pdf)
   * To do it on your own, here are a few recommended frameworks/tools:
       * Frameworks:
         * RedCanary [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
         * [CTID](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/tree/master)
       * Tools:
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

## SOC Self-assessment
*	Read the [SOC Cyber maturity model](https://www.soc-cmm.com/introduction/) from CMM
*	Run the [SOC-CMM self-assessment tool](https://www.soc-cmm.com/downloads/latest/) 

## CERT/CSIRT self-assessment
* Read the [OpenCSIRT cybersecurity maturity framework](https://www.enisa.europa.eu/topics/csirts-in-europe/csirt-capabilities/csirt-maturity/) from ENISA 
  * Run the OpenCSIRT, [SIM3 self-assessment](https://sim3-check.opencsirt.org/#/v1/) 
* Read the [SOC-CMM 4CERT](https://www.soc-cmm.com/4CERT/) from CMM
  * Run the [SOC-CMM 4CERT self-assessment tool](https://www.soc-cmm.com/downloads/latest/soc-cmm%20for%20CERT%201.0%20-%20advanced.xlsx)
  
# Reporting

Generate metrics, leveraging the SIRP traceability and logging capabilities to get relevant data, as well as a bit of scripting.

As per Gartner, MTTR:

![image](https://user-images.githubusercontent.com/16035152/203334473-d210ed37-3d2d-4e03-a468-9cf72dad8c6f.png)


And MTTC:

![image](https://user-images.githubusercontent.com/16035152/203334319-4caec07c-f999-4cc1-a506-078a72000359.png)

Below are my recommendations for KPI and SLA. Unless specified, here are the recommended timeframes to compute those below KPI: 1 week, 1 month, and 6 months.

## SOC/CSIRT KPI:
* Number of alerts (SIEM).
* Number of verified alerts (meaning, confirmed security incidents).
* Top security incident types.
* Top applications associated to alerts (detections).
* Top detection rules triggering most false positives.
* Top detection rules which corresponding alerts take the longest to be handled.
* Top 10 SIEM searches (ie: detection rules) triggering false positives.
* Most seen TTP in detection.
* Most common incident types.
* Top 10 longest tickets before closure.
* Percentage of SIEM data that is not associated to SIEM searches (ie: detection rules).

## Compliance KPI:
* Percentage of known endpoints with company-required security solutions.
* Percentage of critical and high-risk applications that are protected by multifactor authentication.
* Ratio of always-on personal privileged accounts to the number of individuals in roles who should have access to these accounts.
* Percentage of employees and contractors that have completed mandatory security training.
* Percentage of employees who report suspicious emails for the standard organization-wide phishing campaigns.
* Percentage of click-throughs for the organization-wide phishing campaigns in the past 12 months.



## SOC/CSIRT SLA:
* Number of false positives.
* Number of new detection use-cases (SIEM rules) being put in production.
* Number of new detection automation use-cases (enrichment, etc.) being put in production.
* Number of new response automation use-cases (containment, eradication) being put in production.
* Number of detection rules which detection capability and handling process have been confirmed with purpleteaming session, so far.
* MTTH: for all incidents, mean time in H to handle (assign) the alerts.
* MTTT: for all incidents, mean time in H to triage ("verify") the alerts.
* MTTC: for critical and medium security incidents, mean time in H to handle the alerts and start mitigation steps (from triage to initial response).
* MTTR: for critical and medium security incidents, mean time in H to handle the alerts and remediate them (from triage to remediation).

## Compliance SLA:

* Percentage of critical assets that have successfully run ransomware recovery assessment, in the past 12 months.
* Average number of hours from the request for termination of access to sensitive or high-risk systems or information, to deprovisioning of all access.  


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
