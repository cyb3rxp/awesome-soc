# Metrics and KPI

This page deals with SOC metrics: KPI and SLA, as part of the required reporting.

# Must read

* Gartner, [Cybersecurity business value benchmark](https://emtemp.gcom.cloud/ngw/globalassets/en/doc/documents/775537-gartner-cybersecurity-business-value-benchmark-1st-generation.pdf)
* LogRythm, [7 metrics to measure the effectiveness of your SOC](https://www.compuquip.com/hubfs/Vendors/LogRhythm/LogRhythm-7-Metrics-to-Measure-the-Effectiveness-of-Your-SOC-Ebook.pdf?hsCtaTracking=6f44e275-b498-4bee-af8e-c5c5b7aca241%7Cec4bcb3b-9186-4252-a4df-2e9efd8c4d47)
* [MITRE paper](https://github.com/cyb3rxp/awesome-soc/blob/main/11-strategies-of-a-world-class-cybersecurity-operations-center.pdf) 


# Metrics

Generate metrics, leveraging the SIRP traceability and logging capabilities to get relevant data, as well as a bit of scripting.

As per Gartner, MTTR:

![image](https://user-images.githubusercontent.com/16035152/203334473-d210ed37-3d2d-4e03-a468-9cf72dad8c6f.png)


And MTTC:

![image](https://user-images.githubusercontent.com/16035152/203334319-4caec07c-f999-4cc1-a506-078a72000359.png)

Below are my recommendations for KPI and SLA. Unless specified, here are the recommended timeframes to compute those below KPI: 1 week, 1 month, and 6 months.

# Recommended KPI 

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


# Recommended SLA

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




# End

Go to [main page](https://github.com/cyb3rxp/awesome-soc)
