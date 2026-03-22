# Mission-critical means (tools / sensors)

This page deals with tools and sensors that are critical for SOC mission and activities. 

The provided recommendations are based on experience and search.


# Critical tools for a SOC/CSIRT
* **[SIEM](https://www.gartner.com/en/information-technology/glossary/security-information-and-event-management-siem)**:
   * See [Gartner magic quadrant](https://www.bitdefender.com/en-us/business/campaign/2025-gartner-magic-quadrant-for-epp-the-only-visionary) and [Gartner critical SIEM capabilities](https://www.splunk.com/en_us/form/gartner-critical-capabilities-siem.html)
   * My recommendations: [Microsoft Azure Sentinel](https://azure.microsoft.com/en-us/products/microsoft-sentinel/#overview), [Sekoia.io XDR](https://www.sekoia.io/en/sekoia-io-xdr/), [Splunk](https://www.splunk.com), [Graylog](https://graylog.org/).
* **[SIRP](https://d3security.com/blog/whats-the-difference-between-soar-and-sao/)**:
  * e.g.: [IBM Resilient](https://www.ibm.com/qradar/security-qradar-soar?utm_content=SRCWW&p1=Search&p4=43700068028974608&p5=e&gclid=Cj0KCQjw9ZGYBhCEARIsAEUXITW2yUqAfNqWNeYXyENeUAoqLxV543LT0n2oYhYxEQ47Yjm7NfYTFHAaAtwpEALw_wcB&gclsrc=aw.ds),  [TheHive](https://thehive-project.org/), [SwimLane](https://swimlane.com/), [PAN Cortex XSOAR](https://www.paloaltonetworks.com/cortex/cortex-xsoar)
  * My recommendations:  [TheHive](https://thehive-project.org/), [PAN Cortex XSOAR](https://www.paloaltonetworks.com/cortex/cortex-xsoar)
* **[SOA](https://d3security.com/blog/whats-the-difference-between-soar-and-sao/)**:
  * I recommend to read the SoftwareReview's [SOAR Data quadrant awards](https://swimlane.com/resources/reports/soar-quadrant/)
  * e.g. of solutions: [IBM Resilient](https://www.ibm.com/qradar/security-qradar-soar?utm_content=SRCWW&p1=Search&p4=43700068028974608&p5=e&gclid=Cj0KCQjw9ZGYBhCEARIsAEUXITW2yUqAfNqWNeYXyENeUAoqLxV543LT0n2oYhYxEQ47Yjm7NfYTFHAaAtwpEALw_wcB&gclsrc=aw.ds), [SwimLane](https://swimlane.com/), [TheHive](https://thehive-project.org/), [PAN Cortex XSOAR](https://www.paloaltonetworks.com/cortex/cortex-xsoar), [Microsoft Logic Apps](https://learn.microsoft.com/en-us/azure/logic-apps/logic-apps-overview)
  * My recommendations: [SwimLane](https://swimlane.com/), [TheHive](https://thehive-project.org/), [PAN Cortex XSOAR](https://www.paloaltonetworks.com/cortex/cortex-xsoar) 
* **[TIP](https://www.enisa.europa.eu/sites/default/files/publications/ENISA%20Report%20-%20How%20to%20setup%20CSIRT%20and%20SOC.pdf)**:
   * See [Threat intel page](https://github.com/cyb3rxp/awesome-soc/blob/main/threat_intelligence.md) 
     

# Critical sensors for a SOC

* **Antimalware/antivirus** (you may want to have a look at [my antivirus vs. EDR comparison](https://github.com/cyb3rxp/awesome-soc/blob/main/soc_basics.md#what-are-the-differences-between-antivirus-and-edr):
  * See [Gartner magic quadrant](https://www.linkedin.com/posts/philipcao_gartnermq2025-epp-activity-7354304314963542016-1dzo/) or [Forrester Wave](https://explore.bitdefender.com/epp-nurture-2023_2/report-forrester-wave-endpoint-security-q4-2023?cid=emm%7Cb%7Chubspot%7Cnrt-epp-2023&utm_campaign=nurture-epp-2023&utm_medium=email&_hsmi=280555694&utm_content=280555694&utm_source=hs_automation)
  * My recommendations: [Microsoft Defender](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/microsoft-defender-antivirus-windows?view=o365-worldwide), [ESET Nod32](https://www.eset.com/int/business/solutions/learn-more-about-endpoint-protection/), [BitDefender](https://www.bitdefender.fr/business/products/workstation-security.html), [WithSecure Elements EPP](https://www.withsecure.com/fr/solutions/software-and-services/elements-endpoint-protection/computer)
* **[Endpoint Detection and Response](https://www.gartner.com/reviews/market/endpoint-detection-and-response-solutions)**:
  * See [Gartner magic quadrant](https://www.sentinelone.com/lp/gartnermq/), [MITRE ATT&CK Evaluations](https://evals.mitre.org/results/enterprise?view=cohort&evaluation=er7&result_type=DETECTION&scenarios=1,2), and [Forrester Wave](https://www.crowdstrike.com/resources/reports/crowdstrike-recognized-as-dominant-endpoint-solution-with-superior-vision/)
  * My recommendations: [SentinelOne](https://www.sentinelone.com/blog/active-edr-feature-spotlight/), [Microsoft Defender for Endpoint](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/microsoft-defender-endpoint?view=o365-worldwide), [Harfanglab](https://harfanglab.io/), [ESET XDR](https://www.eset.com/int/business/enterprise-protection-bundle/), [WithSecure Elements EDR](https://www.withsecure.com/us-en/solutions/software-and-services/elements-endpoint-detection-and-response), [CrowdStrike Falcon EDR](https://www.crowdstrike.com/wp-content/uploads/2022/03/crowdstrike-falcon-insight-data-sheet.pdf), [Tanium](https://www.tanium.com/products/tanium-threat-response/), [Wazuh](https://wazuh.com/)
* **[Secure Email Gateway](https://www.proofpoint.com/fr/threat-reference/email-gateway)** (SEG):
  * See [Gartner reviews and ratings](https://www.gartner.com/reviews/market/email-security)
  * My recommendations: [Microsoft Defender for Office365](https://www.microsoft.com/en-us/security/business/siem-and-xdr/microsoft-defender-office-365), [ProofPoint](https://www.proofpoint.com/fr/threat-reference/email-gateway), [Mimecast](https://www.mimecast.com/products/email-security/secure-email-gateway/), [WithSecure Elements Collaboration Protection](https://www.withsecure.com/en/solutions/software-and-services/elements-collaboration-protection)
* **[Secure Web Gateway](https://www.gartner.com/en/information-technology/glossary/secure-web-gateway)** (SWG) / Security Service Edge:
  * see [Forrester wave for SSE](https://www.netskope.com/wp-content/uploads/2024/03/forrester-wave-sse-solutions-diagram-1340x1640-1.png) 
  * My recommendations: [BlueCoat Edge SWG](https://www.broadcom.com/products/cybersecurity/network/web-protection/proxy-sg-and-advanced-secure-gateway), [CISCO SASE](https://www.cisco.com/site/us/en/solutions/secure-access-service-edge-sase/index.html), [Zscaler Cloud proxy](https://www.zscaler.com/resources/security-terms-glossary/what-is-cloud-proxy), [Netskope](https://www.netskope.com/security-defined/what-is-casb).
* **[Identity Threat Detection and Response](https://www.semperis.com/blog/evaluating-identity-threat-detection-response-solutions/)** **(ITDR)** for identity and AD/AAD security (audit logs, or specific security monitoring solutions):
  * My recommendations: [Semperis Directory Services Protector](https://www.semperis.com/active-directory-security/)
  * for a one-shot security assessment of AD and Enta ID, I recommend: [Semperis Purple Knight](https://www.semperis.com/purple-knight/)  or [PingCastle](https://www.pingcastle.com/download/)
* **EASM**: External Asset Security Monitoring / External Attack Surface Management:
  * My recommendations: [Intrinsec](https://www.intrinsec.com/en/easm-external-attack-surface-management/), [Mandiant](https://cloud.google.com/security/products/attack-surface-management), [Qualys EASM](https://www.qualys.com/apps/external-attack-surface-management/)
  * for a security check-up:
     * quick security assessment of your website: [ImmuniWeb](https://www.immuniweb.com/websec/)
     * AWS/Azure/GCP security assessment (community tool): [ScootSuite](https://github.com/nccgroup/ScoutSuite)
* **CASB**: [Cloud Access Security Broker](https://www.gartner.com/en/information-technology/glossary/cloud-access-security-brokers-casbs), if company's IT environment uses a lot of external services like SaaS/IaaS:
  * See [Gartner magic quadrant](https://www.netskope.com/wp-content/uploads/2025/05/2025-05-SSE-MQ-site-1040x1094-1-768x808.png)
  * My recommendations: [Microsoft MCAS](https://www.microsoft.com/en-us/security/business/siem-and-xdr/microsoft-defender-cloud-apps), [Zscaler](https://info.zscaler.com/resources-white-papers-data-protection-challenges?_bt=534426399999&_bk=%2Bzscaler%20%2Bcasb&_bm=b&_bn=g&_bg=121807608181&utm_source=google&utm_medium=cpc&utm_campaign=google-ads-na&gclid=CjwKCAjwu5yYBhAjEiwAKXk_eKLlKaMfJ-oGYItPTHguAmCA_b9WP0zNZgLPqGKjfC19IGmQFFG_9RoCgJAQAvD_BwE), [Netskope](https://www.netskope.com/security-defined/what-is-casb).
* **Mobile Threat Defense:**
  * See the [latest Forrester Wave about MTD](https://reprint.forrester.com/reports/the-forrester-wave-tm-mobile-threat-defense-solutions-q3-2024-fd48faab/index.html)
  * my recommendation : [Zimperium MTD](https://www.zimperium.com/mtd/)
   

# Critical tools for CSIRT
* **Compromise assessment tools**:
  * My recommendations:
    * Paid ones:
      * [Thor Cloud lite](https://www.nextron-systems.com/2023/10/30/introducing-thor-cloud-lite-seamless-on-demand-security-scanning-made-easy/);
      * [WithSecure Elements EDR](https://www.withsecure.com/us-en/solutions/software-and-services/elements-endpoint-detection-and-response);
    * free ones:
       * for Linux:
         * WithSecure [Cat-Scale](https://labs.withsecure.com/tools/cat-scale-linux-incident-response-collection);
         * [UAC](https://github.com/tclahr/uac);
         * [NullSec](https://github.com/bad-antics/nullsec-logreaper);
         * [Mquire](https://blog.trailofbits.com/2026/02/25/mquire-linux-memory-forensics-without-external-dependencies/);
       * for Windows:
          * simple but efficient ESET [Sysinspector](https://www.eset.com/int/support/sysinspector/);
          * [Velociraptor](https://docs.velociraptor.app/docs/);
          * [Powershell Hunter](https://github.com/MHaggis/PowerShell-Hunter/tree/main)
          * [DFIR-ORC](https://github.com/dfir-orc);
          * [Sysmon](https://learn.microsoft.com/fr-fr/sysinternals/downloads/sysmon):
            * install it (if not done already, let it run for a few hours/days), with [Olaf Hartong's config](https://github.com/olafhartong/sysmon-modular/blob/master/sysmonconfig.xml);
            * then investigate its log with a regarlar SIEM or with [Zircolite](https://github.com/wagga40/Zircolite)
       * For AD specifically: 
         * simple but efficient [ADRecon](https://github.com/tomwechsler/Active_Directory_Advanced_Threat_Hunting/blob/main/Different_hunting_methods/In-depth_investigation_active_directory.md);
         * [ADTrapper](https://github.com/MHaggis/ADTrapper);
         * [Semperis Purple Knight](https://www.semperis.com/purple-knight/);
         * [BloodHound Community](https://github.com/SpecterOps/BloodHound)
       * For MS Entra ID & M365 specifically:
         * [CrowdStrike Reporting Tool for Azure](https://github.com/CrowdStrike/CRT)
         * [Semperis Purple Knight](https://www.semperis.com/purple-knight/);
         * [365Inspect](https://github.com/soteria-security/365Inspect);
         * [Azure AD Incident Response Powershell](https://github.com/reprise99/kql-for-dfir/tree/main/Azure%20Active%20Directory)
       * For GWS specifically:
         * [ALFA](https://github.com/invictus-ir/ALFA)
       * For Azure / GCP / AWS:
         * [ScootSuite](https://github.com/nccgroup/ScoutSuite)
* **On-demand volatile data collection tool**:
  * My recommendations: [FastIR](https://github.com/OWNsecurity/fastir_artifacts), [VARC](https://github.com/cado-security/varc), [FireEye Redline](https://fireeye.market/apps/211364), [DFIR-ORC](https://github.com/dfir-orc);
* **Remote action capable tools (ie.: remote shell or equivalent)**:
  * My recommendations: [CIMSweep](https://github.com/mattifestation/CimSweep), [Velociraptor](https://docs.velociraptor.app/docs/deployment/), [CrowdStrike Falcon Toolkit](https://github.com/CrowdStrike/Falcon-Toolkit) but it relies on CrowdStrike EDR, [GRR](https://github.com/google/grr) but it needs an agent to be installed.
* **On-demand sandbox**:
  * My recommendations for online ones: [Joe's sandbox](https://www.joesandbox.com/#windows), [Hybrid Analysis](https://www.hybrid-analysis.com/), etc;
  * My recommendation for local one:
     * Windows 10 native Sandbox, with [automation](https://megamorf.gitlab.io/2020/07/19/automating-the-windows-sandbox/).
     * Linux/Docker : [CISA Thorium](https://github.com/cisagov/thorium?tab=readme-ov-file)
* **Forensics and reverse-engineering tools suite**:
  * My recommendations: [SIFT Workstation](https://www.sans.org/tools/sift-workstation/), or [Tsurugi](https://tsurugi-linux.org/);
  * My recommendation for reverse engineering and malware analysis, under Windows: [FireEye Flare-VM](https://github.com/mandiant/flare-vm);
  * My recommendation for pure malware analysis, under Linux: [Remnux](https://remnux.org/).
* **Incident maangement tracker**: 
  * My recommendations: [Timesketch](https://timesketch.org/), [DFIR IRIS](https://dfir-iris.org/)
* **Scanners**:
  * IOC scanners:
    * My recommendations: [Loki](https://github.com/Neo23x0/Loki), [DFIR-ORC](https://github.com/dfir-orc)
    * For smartphones: [Tiny Check](https://tiny-check.com/#/)
  * IOC repos for scanners:
    * Google [CTI's repo](https://github.com/chronicle/GCTI/tree/main/YARA): Yara rules for Cobalt Strike and others.
    * [Yara-rules GitHub repo](https://github.com/Yara-Rules/rules): multiple Yara rules types.
    * Spectre [Yara rules repo](https://github.com/phbiohazard/Yara)
    * Neo23x0 [Community Yara rules](https://github.com/Neo23x0/signature-base)
    * and those listed here, [Awesome threat intel](https://github.com/hslatman/awesome-threat-intelligence)
  * Offline antimalware scanners:
    * My recommendation: [Windows Defender Offline](https://support.microsoft.com/en-us/windows/help-protect-my-pc-with-microsoft-defender-offline-9306d528-64bf-4668-5b80-ff533f183d6c)
* **Logs analyzers with detection capabilities**:
    * My recommendations:
      * Paid ones: [Sekoia XDR](https://www.sekoia.io/en/product/xdr/), 
      * Community-provided / free ones: [Zircolite](https://github.com/wagga40/Zircolite), [DeepBlue](https://github.com/sans-blue-team/DeepBlueCLI), [CrowdSec](https://doc.crowdsec.net/docs/user_guides/replay_mode)
      
# Other critical tools for a SOC and a CERT/CSIRT
* **Secure secrets sharing**:
  * [OneTimeSecret](https://onetimesecret.com/)  
* **Data analysis tools**:
  * My recommendations: [CyberChef](https://github.com/NextronSystems/CyberChef), [Notepad++](https://notepad-plus-plus.org/downloads/)
* **Admin tools**: 
  * My recommendations for (free) admin tools: [Azure AD Internals suite](https://aadinternals.com/), [SysInternals Suite](https://learn.microsoft.com/fr-fr/sysinternals/downloads/sysinternals-suite), [MRemoteNG](https://mremoteng.org/)
  * My recommendations for (free) remote deployment tools: [EMCO Remote installer](https://emcosoftware.com/remote-installer)
* **Internal ticketing system** (NB: **not** SIRP, not for incident response!):
  * My recommendation: [GitLab](https://github.com/diffblue/gitlab/blob/master/doc/operations/incident_management/incidents.md)
* **Knowledge sharing and management tool**:
  * My recommendations: [Microsoft SharePoint](https://www.microsoft.com/en-us/microsoft-365/sharepoint/collaboration), Wiki (choose the one you prefer, or [use GitLab as a Wiki](https://docs.gitlab.com/ee/user/project/wiki/)).
* **Vizualization tool for OSINT search and IOC**:
  * My recommendation: [OSINTracker](https://app.osintracker.com/)
* **Secure file sharing service**:
  * My recommandation: [Chapril](https://drop.chapril.org/)


# End
Go to [main page](https://github.com/cyb3rxp/awesome-soc/blob/main/README.md).
