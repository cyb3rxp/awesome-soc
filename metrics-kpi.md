# Metrics and KPI

This page deals with SOC metrics: KPI and SLA, as part of the required reporting.

# Must read

* Gartner, [Cybersecurity business value benchmark](https://emtemp.gcom.cloud/ngw/globalassets/en/doc/documents/775537-gartner-cybersecurity-business-value-benchmark-1st-generation.pdf)
* LogRythm, [7 metrics to measure the effectiveness of your SOC](https://www.compuquip.com/hubfs/Vendors/LogRhythm/LogRhythm-7-Metrics-to-Measure-the-Effectiveness-of-Your-SOC-Ebook.pdf?hsCtaTracking=6f44e275-b498-4bee-af8e-c5c5b7aca241%7Cec4bcb3b-9186-4252-a4df-2e9efd8c4d47)
* SOC-CMM, [Metrics](https://www.soc-cmm.com/img/upload/files/31-soc-cmm-metrics-101.pdf)
* [MITRE SOC strategies paper](https://github.com/cyb3rxp/awesome-soc/blob/main/11-strategies-of-a-world-class-cybersecurity-operations-center.pdf) 


# Metrics

Generate metrics, leveraging the SIRP traceability and logging capabilities to get relevant data, as well as a bit of scripting.

As per Gartner, MTTR:

![image](https://user-images.githubusercontent.com/16035152/203334473-d210ed37-3d2d-4e03-a468-9cf72dad8c6f.png)

And MTTC:

![image](https://user-images.githubusercontent.com/16035152/203334319-4caec07c-f999-4cc1-a506-078a72000359.png)

Below are my recommendations for KPI and SLA. Unless specified, here are the recommended timeframes to compute those below KPI: 1 week, 1 month, and 6 months.


# KPI

## Recommended SOC KPI

* Number of alerts (SIEM).
* Number of Dark Web related alerts.
* Number of verified alerts (ie.: confirmed security incidents).
* Percentage of verified alerts (ie.: confirmed security incidents);
   * NB: that also gives the false-positive rate.
* Top security incident types.
* Top applications associated to alerts (ie.: detections).
* Most seen TTP in detection.
* Top 10 targeted users.
* Top 10 longest tickets before closure.
* Top detection rules triggering most false positives.
* Top detection rules which corresponding alerts take the longest to be handled.
* Top 10 SIEM/XDR searches (ie: detection rules) triggering false positives.
* Number of sources/sensors' logs that are not yet integrated to the SIEM/XDR.
* Percentage of SIEM data that is not associated to SIEM searches (ie: detection rules).
* Percentage of coverage of detection matrix and/or MITRE ATT&CK.
* Number of security incidents that impacted PII;
* Number or security incidents that impacted business-critical data. 
* Number of alerts that were handled with a validated playbook.
* Number of new automation playbooks that were successfully tested and validated.
* Number of alerts that had to be handled by on-call analyst.
* List of security incidents for which containment phase failed or faced abnormal issues.
* Number of regulation violations caused by security incidents (eg.: GDPR, NIS2, DORA, HIPAA, SOC 2, etc.).
* Percentage of SOC analysts that sucessfully followed SOC-related training or passed required certifications. 
* Percentage of SOC human resources turnover year over year.


## Recommended CERT/CSIRT KPI

* Top security incident types.
* Top applications associated to alerts (detections).
* Most seen TTP in incident response.
* Top incident types.
* Top 10 targeted users.
* Top 10 targeted endpoints.
* Top 10 longest tickets (ie.: incidents) before closure.
* Number of still ongoing incidents.
* Number of IOC that were generated during incident response.
* Number of incidents response requests that came down outside business hours.
* Percentage of incidents for which CSIRT feedback has been leveraged to help improve the SOC.
* Number of regulation violations caused by security incidents (eg.: GDPR, NIS2, DORA, HIPAA, SOC 2, etc.).
* Percentage of CSIRT analysts that sucessfully followed SOC-related training or passed required certifications. 
* Percentage of CSIRT human resources turnover year over year.



## Recommended compliance KPI

* Number of confirmed business-related security risks that have been taken in to account by the SOC for coverage.
* Percentage of known endpoints **without** company-required security solutions.
* Percentage of critical and high-risk applications that are **not** protected by multifactor authentication.
* Ratio of always-on personal privileged accounts to the number of individuals in roles who should have access to these accounts.
* Percentage of employees and contractors that have **not** completed mandatory security training.
* Percentage of employees who report suspicious emails for the standard organization-wide phishing campaigns.
* Percentage of click-throughs for the organization-wide phishing campaigns in the past 12 months.
* Number of endpoints having at least one vulnerability listed in CISA [KEV list](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
* Number of user accounts for which passwords are being considered as compromised (based on dark web monitoring).
* Number of public IP addresses (belonging to the organisation) that are black-listed or reported as malicious by third parties (eg.: on CTI portals like the ones listed on [my threat intel page](https://github.com/cyb3rxp/awesome-soc/blob/main/threat_intelligence.md#sources)).
* Number of incidents that are likely to have an impact (ie.: non-compliance) on a ISO 27001 certification.


## Recommended SOC maturity KPI (from CMM)

* [SOC-CMM](https://www.soc-cmm.com/products/soc-cmm) score for Technology.
* [SOC-CMM](https://www.soc-cmm.com/products/soc-cmm) score for Process.
* [SOC-CMM](https://www.soc-cmm.com/products/soc-cmm) score for People.
* [SOC-CMM](https://www.soc-cmm.com/products/soc-cmm) score for Business.
* [SOC-CMM](https://www.soc-cmm.com/products/soc-cmm) score for Services: Security Monitoring.
* [SOC-CMM](https://www.soc-cmm.com/products/soc-cmm) score for Services: Security Incident Management.
* [SOC-CMM](https://www.soc-cmm.com/products/soc-cmm) score for Services: Security Monitoring.
* [SOC-CMM](https://www.soc-cmm.com/products/soc-cmm) score for Services: Vulnerability Management.



## Recommended CSIRT maturity KPI (from CMM)
* [SOC-CMM](https://www.soc-cmm.com/products/soc-cmm) score for Process: Use Case Management.
* [SOC-CMM](https://www.soc-cmm.com/products/soc-cmm) score for Process: Reporting & Communication.
* [SOC-CMM](https://www.soc-cmm.com/products/soc-cmm) score for Process: Operations & Facilities.
* [SOC-CMM](https://www.soc-cmm.com/products/soc-cmm) score for People.
* [SOC-CMM](https://www.soc-cmm.com/products/soc-cmm) score for Business: Customers and Stakeholders.
* [SOC-CMM](https://www.soc-cmm.com/products/soc-cmm) score for Business: Charter.
* [SOC-CMM](https://www.soc-cmm.com/products/soc-cmm) score for Business: Pricacy & Policy.
* [SOC-CMM](https://www.soc-cmm.com/products/soc-cmm) score for Services: Security Incident Management.
* [SOC-CMM](https://www.soc-cmm.com/products/soc-cmm) score for Services: CTI.
* [SOC-CMM](https://www.soc-cmm.com/products/soc-cmm) score for Services: Forensics Analysis.
* [SOC-CMM](https://www.soc-cmm.com/products/soc-cmm) score for Services: Threat Hunting.


# SLA

## Recommmended SOC SLA:
* Percentage and number of false positives (NB: 100% sucessfull detection is **not** achievable).
* Number of new detection use-cases (SIEM rules) being put in production.
* Number of new detection automation use-cases (enrichment, etc.) being put in production.
* Number of new response automation use-cases (containment, eradication) being put in production.
* Number of detection rules which detection capability and handling process have been confirmed with purpleteaming session, so far.
* Percentage of EASM reports that were taken into account by the SOC to improve its perimeter coverage.
* MTTD (Mean Time To Detect): for all alerts, mean team in min/H to generate a detection based on detection logic and data/events.
* MTTH (Mean Time To Handle): for all incidents, mean time in H to handle (ie.: assign) the alerts to an analyst (NB: detection can be generated by security solutions themselves like EDR/NDR/ITDR, etc. or it can happen within a SIEM/XDR).
* MTTT (Mean Time To Triage): for all incidents, mean time in H to triage (ie.: "verify") the alerts.
* MTTC (Mean Time To Containment): for critical and medium security incidents, mean time in H to handle the alerts and start mitigation steps (from triage to initial response, mostly **containment**).
* MTTR (Mean Time To Recovery): for critical and medium security incidents, mean time in H to handle the alerts and remediate them (from triage to **full remediation**, including containment, malware eradication, and recovery).
* Percentage of missed SLA (if defined):
   * MTTH;
   * MTTT;
   * MTTC;
   * MTTR (NB: I recommend to be cautious with that one as some remediation plans for critical security incidents can take months or even years, far longer than expected at first).
* Number of missed calls (ie.: missed acceptable reply timeframe) to the on-call analyst.
* Number of purple-teaming sessions (SOC capabilities assessment) per year (at least 1).


## Recommended compliance SLA:

* Percentage of critical assets that have successfully run ransomware recovery assessment, in the past 12 months.
* Average number of hours from the request for termination of access to sensitive or high-risk systems or information, to deprovisioning of all access.
* SOC-CMM score review (half-yearly or yearly)
 


# End

Go to [main page](https://github.com/cyb3rxp/awesome-soc)
