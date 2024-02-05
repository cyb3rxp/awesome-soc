# SOC HR and training

This page deals with SOC HR and training topics.

# ToC

* [Must read](https://github.com/cyb3rxp/awesome-soc/blob/main/hr_training.md#must-read)
* [HR roles and organization](https://github.com/cyb3rxp/awesome-soc/blob/main/hr_training.md#hr-roles-and-organization)
* [Recommended SOC trainings](https://github.com/cyb3rxp/awesome-soc/blob/main/hr_training.md#recommended-soc-trainings)
* [Recommended CERT/CSIRT trainings](https://github.com/cyb3rxp/awesome-soc/blob/main/hr_training.md#recommended-certcsirt-trainings)
* [Recommended offesnsive security trainings](https://github.com/cyb3rxp/awesome-soc/edit/main/hr_training.md#recommended-offensive-security-trainings)



# Must read
* MITRE, [11 strategies for a world-class SOC](https://github.com/cyb3rxp/awesome-soc/blob/main/11-strategies-of-a-world-class-cybersecurity-operations-center.pdf), Strategy 4, pages 101-123

![image](https://user-images.githubusercontent.com/16035152/208257245-e481c2ad-4523-438c-9e49-a5e0999c300f.png)


# HR roles and organization

As per what is explained on the [management page](https://github.com/cyb3rxp/awesome-soc/blob/main/management.md#soc-organization), I would recommend to make sure the following roles are being assigned to people:
* SOC analyst;
* SOC analyst lead;
* SOC detection engineer;
* Threat intel analyst;
* Threat intel lead (if several analysts)
* SIEM expert and data scientist;
* Pentester (offensive team);
* Incident handler;
* Incident manager;
* SOC/CSIRT tools admin;
* SecDevOps analyst;
* SOC/CERT/CSIRT deputy manager.
* SOC/CERT/CSIRT manager.

They can be FTE or outsourced, it will depend on your needs and constraints. My recommendations are explained in the RACI template that I propose.


# Recommended SOC trainings

## Regular trainings
* PaloAlto, [Fundamentals of SOC](https://beacon.paloaltonetworks.com/student/path/521672-the-fundamentals-of-soc-security-operations-center), mainly modules 1 to 8 :) (free);
* LetsDefend, [Fundamentals of SOC](https://app.letsdefend.io/training/lessons/soc-fundamentals) (free)
* [Cybrary, MITRE ATT&CK threat hunting](https://www.cybrary.it/course/mitre-attack-threat-hunting/), free!
* [ENISA trainings](https://www.enisa.europa.eu/topics/trainings-for-cybersecurity-specialists/online-training-material), free!
* Active Directory:
   * train on AD specific attacks, [Orange Cyberdefense GOAD](https://github.com/Orange-Cyberdefense/GOAD) (free).
   * Populate AD with "real life" objects, in an automated way, [Badblood](https://github.com/davidprowe/badblood)

### Challenges
* [BlueTeamLabs challenges and investigations](https://blueteamlabs.online/home/challenges), here are a few free trainings that I recommend:
   * https://blueteamlabs.online/home/challenge/the-report-ii-82ea7781c5
   * https://blueteamlabs.online/home/challenge/the-report-a6dd340dba
   * https://blueteamlabs.online/home/challenge/attck-0e4914db5d
   * https://blueteamlabs.online/home/challenge/d3fend-6c9dcd4b79
   * https://blueteamlabs.online/home/challenge/bruteforce-16629bf9a2
   * https://blueteamlabs.online/home/challenge/phishing-analysis-f92ef500ce
   * https://blueteamlabs.online/home/challenge/phishing-analysis-2-a1091574b8
   * https://blueteamlabs.online/home/challenge/log-analysis-sysmon-fabcb83517
   * https://blueteamlabs.online/home/challenge/meta-b976cec9e2
   * https://blueteamlabs.online/home/challenge/follina-f1a3452f34
   * https://blueteamlabs.online/home/challenge/powershell-analysis-keylogger-9f4ab9a11c
   * https://blueteamlabs.online/home/challenge/secrets-85aa2bb3a9
   * https://blueteamlabs.online/home/challenge/paranoid-e5e164befb
   * https://blueteamlabs.online/home/investigation/deep-blue-a4c18ce507
   * https://blueteamlabs.online/home/investigation/sam-d310695187
* [Cyberdefenders](https://cyberdefenders.org/), here are a few free trainings that I recommend:
  * https://cyberdefenders.org/blueteam-ctf-challenges/91
  * https://cyberdefenders.org/blueteam-ctf-challenges/47
  * https://cyberdefenders.org/blueteam-ctf-challenges/84
  * https://cyberdefenders.org/blueteam-ctf-challenges/77
  * https://cyberdefenders.org/blueteam-ctf-challenges/74
  * https://cyberdefenders.org/blueteam-ctf-challenges/73
  * https://cyberdefenders.org/blueteam-ctf-challenges/67
  * https://cyberdefenders.org/blueteam-ctf-challenges/68
  * https://cyberdefenders.org/blueteam-ctf-challenges/60
  * https://cyberdefenders.org/blueteam-ctf-challenges/32
  * https://cyberdefenders.org/blueteam-ctf-challenges/17
* [LetsDefend](https://letsdefend.io/), here are a few free trainings that I recommend:
  * https://app.letsdefend.io/monitoring/alerts/
  * https://app.letsdefend.io/challenge/conti-ransomware/
  * https://app.letsdefend.io/challenge/IcedID-Malware-Family/
  * https://app.letsdefend.io/challenge/shellshock-attack/
  * https://app.letsdefend.io/challenge/phishing-email/
  * https://app.letsdefend.io/challenge/conti-ransomware/
  * https://app.letsdefend.io/challenge/investigate-web-attack/
  * https://app.letsdefend.io/challenge/infection-cobalt-strike/
  * https://app.letsdefend.io/challenge/malicious-chrome-extension
* [SOC Vel](https://socvel.com/challenges/).

### SIEM
* Splunk: 
  * Trainings [free]:
    * [Getting data into Splunk](https://education.splunk.com/Saba/Web_spf/NA10P2PRD105/app/me/learningeventdetail/cours000000000003373?returnurl=common%2Flearningcatalog%2F)
    * [Intro to SPL2](https://education.splunk.com/Saba/Web_spf/NA10P2PRD105/app/me/learningeventdetail;spf-url=common%2Fledetail%2Fcours000000000017620%3Fcontext%3Duser&learnerId%3Dpersn000000000844498&returnPage%3Dlearningcatalog)
    * [Comparing values](https://education.splunk.com/Saba/Web_spf/NA10P2PRD105/app/me/learningeventdetail/cours000000000003246?returnurl=common%2Fsearchresults%2Fxxemptyxx%2FLEARNINGEVENT,OFFERINGTEMPLATE,CERTIFICATION,CURRICULUM,PLAYLIST,OFFERING,PACKAGE,LXPCONTENT,LEARNINGPATHWAY%3Fadvsearch%3Dtrue&amp;categoryId=categ000000000003041&amp;embeddedInTorque=true)
    * [Working with time](https://education.splunk.com/Saba/Web_spf/NA10P2PRD105/app/me/learningeventdetail/cours000000000003621?returnurl=common%2Fsearchresults%2Fxxemptyxx%2FLEARNINGEVENT,OFFERINGTEMPLATE,CERTIFICATION,CURRICULUM,PLAYLIST,OFFERING,PACKAGE,LXPCONTENT,LEARNINGPATHWAY%3Fadvsearch%3Dtrue&amp;categoryId=categ000000000003041&amp;embeddedInTorque=true)
    * [Result modification](https://education.splunk.com/Saba/Web_spf/NA10P2PRD105/app/me/learningeventdetail/cours000000000003392?returnurl=common%2Fsearchresults%2Fxxemptyxx%2FLEARNINGEVENT,OFFERINGTEMPLATE,CERTIFICATION,CURRICULUM,PLAYLIST,OFFERING,PACKAGE,LXPCONTENT,LEARNINGPATHWAY%3Fadvsearch%3Dtrue&categoryId=categ000000000003041&embeddedInTorque=true)
    * [Scheduling reports & alerts](https://education.splunk.com/Saba/Web_spf/NA10P2PRD105/app/me/learningeventdetail/cours000000000003397?returnurl=common%2Fsearchresults%2Fxxemptyxx%2FLEARNINGEVENT,OFFERINGTEMPLATE,CERTIFICATION,CURRICULUM,PLAYLIST,OFFERING,PACKAGE,LXPCONTENT,LEARNINGPATHWAY%3Fadvsearch%3Dtrue&categoryId=categ000000000003041&embeddedInTorque=true)
    * [Visualizations](https://education.splunk.com/Saba/Web_spf/NA10P2PRD105/app/me/learningeventdetail/cours000000000003643?returnurl=common%2Fsearchresults%2Fxxemptyxx%2FLEARNINGEVENT,OFFERINGTEMPLATE,CERTIFICATION,CURRICULUM,PLAYLIST,OFFERING,PACKAGE,LXPCONTENT,LEARNINGPATHWAY%3Fadvsearch%3Dtrue&amp;categoryId=categ000000000003041&amp;embeddedInTorque=true)
    * [Using fields](https://education.splunk.com/Saba/Web_spf/NA10P2PRD105/app/me/learningeventdetail/cours000000000003611?returnurl=common%2Fsearchresults%2Fxxemptyxx%2FLEARNINGEVENT,OFFERINGTEMPLATE,CERTIFICATION,CURRICULUM,PLAYLIST,OFFERING,PACKAGE,LXPCONTENT,LEARNINGPATHWAY%3Fadvsearch%3Dtrue&amp;categoryId=categ000000000003041&amp;embeddedInTorque=true)
    * [Creating field extraction](https://education.splunk.com/Saba/Web_spf/NA10P2PRD105/app/me/learningeventdetail/cours000000000003321?returnurl=common%2Fsearchresults%2Fxxemptyxx%2FLEARNINGEVENT,OFFERINGTEMPLATE,CERTIFICATION,CURRICULUM,PLAYLIST,OFFERING,PACKAGE,LXPCONTENT,LEARNINGPATHWAY%3Fadvsearch%3Dtrue&categoryId=categ000000000003041&embeddedInTorque=true)
    * [Intro to dashboards](https://education.splunk.com/Saba/Web_spf/NA10P2PRD105/app/me/learningeventdetail/cours000000000003411?returnurl=common%2Fsearchresults%2Fxxemptyxx%2FLEARNINGEVENT,OFFERINGTEMPLATE,CERTIFICATION,CURRICULUM,PLAYLIST,OFFERING,PACKAGE,LXPCONTENT,LEARNINGPATHWAY%3Fadvsearch%3Dtrue&amp;categoryId=categ000000000003041&amp;embeddedInTorque=true)
    * [Intro to knowledge objects](https://education.splunk.com/Saba/Web_spf/NA10P2PRD105/app/me/learningeventdetail/cours000000000003413?returnurl=common%2Fsearchresults%2Fxxemptyxx%2FLEARNINGEVENT,OFFERINGTEMPLATE,CERTIFICATION,CURRICULUM,PLAYLIST,OFFERING,PACKAGE,LXPCONTENT,LEARNINGPATHWAY%3Fadvsearch%3Dtrue&amp;categoryId=categ000000000003041&amp;embeddedInTorque=true)
    * [Datamodels](https://education.splunk.com/Saba/Web_spf/NA10P2PRD105/app/me/learningeventdetail/cours000000000003337?returnurl=common%2Fsearchresults%2Fxxemptyxx%2FLEARNINGEVENT,OFFERINGTEMPLATE,CERTIFICATION,CURRICULUM,PLAYLIST,OFFERING,PACKAGE,LXPCONTENT,LEARNINGPATHWAY%3Fadvsearch%3Dtrue&amp;categoryId=categ000000000003041&amp;embeddedInTorque=true)
    * [Security operations and defense analyst](https://education.splunk.com/Saba/Web_spf/NA10P2PRD105/app/me/learningeventdetail/cours000000000014180?returnurl=common%2Fsearchresults%2Fxxemptyxx%2FLEARNINGEVENT,OFFERINGTEMPLATE,CERTIFICATION,CURRICULUM,PLAYLIST,OFFERING,PACKAGE,LXPCONTENT,LEARNINGPATHWAY%3Fadvsearch%3Dtrue&categoryId=categ000000000003041&embeddedInTorque=true)
    * [Intro to Splunk Security Essentials](https://education.splunk.com/Saba/Web_spf/NA10P2PRD105/app/me/learningeventdetail/cours000000000003433?returnurl=common%2Fsearchresults%2Fxxemptyxx%2FLEARNINGEVENT,OFFERINGTEMPLATE,CERTIFICATION,CURRICULUM,PLAYLIST,OFFERING,PACKAGE,LXPCONTENT,LEARNINGPATHWAY%3Fadvsearch%3Dtrue&amp;categoryId=categ000000000003041&amp;embeddedInTorque=true)
    * [Splunk Enterprise installation & configuration](https://education.splunk.com/Saba/Web_spf/NA10P2PRD105/app/me/learningeventdetail/cours000000000003503?returnurl=common%2Fsearchresults%2Fxxemptyxx%2FLEARNINGEVENT,OFFERINGTEMPLATE,CERTIFICATION,CURRICULUM,PLAYLIST,OFFERING,PACKAGE,LXPCONTENT,LEARNINGPATHWAY%3Fadvsearch%3Dtrue&categoryId=categ000000000003041&embeddedInTorque=true)
    * [Using the monitoring console](https://education.splunk.com/Saba/Web_spf/NA10P2PRD105/app/me/learningeventdetail/cours000000000003639?returnurl=common%2Fsearchresults%2Fxxemptyxx%2FLEARNINGEVENT,OFFERINGTEMPLATE,CERTIFICATION,CURRICULUM,PLAYLIST,OFFERING,PACKAGE,LXPCONTENT,LEARNINGPATHWAY%3Fadvsearch%3Dtrue&categoryId=categ000000000003041&embeddedInTorque=true)
    
    * Attack simulation & investigation: [Splunk attack range](https://github.com/splunk/attack_range_cloud).
  * CTF: BOTS [free]:
    * https://cyberdefenders.org/search/labs/?q=splunk
 
* Microsoft Sentinel (Defender XDR), [Become an Azure Sentinel Ninja](https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/become-a-microsoft-sentinel-ninja-the-complete-level-400/ba-p/1246310) [free];


## Certifications

### Free certifications:
* CrowdSec, [cybersecurity fundamentals](https://academy.crowdsec.net/course/cybersecurity-fundamentals)
* FIRST, [CVSS v4](https://learn.first.org/catalog/info/id:126)
* Microsoft, [Microsoft Sentinel Ninja](https://forms.office.com/pages/responsepage.aspx?id=v4j5cvGGr0GRqy180BHbR1irKnVJZ_RBhccteqa39A9UN08wTjY4MzROVDhUUFRZRTgwME1HSUlFQS4u).
* Amazon, [AWS Security Fundamentals](https://aws.amazon.com/training/digital/aws-security-fundamentals/?nc1=h_ls).
* PaloAlto, [Fundamentals of network security](https://beacon.paloaltonetworks.com/student/path/673504/activity/726463).
* PaloALto, [PAN, Fundamentals of SOC](https://beacon.paloaltonetworks.com/student/path/521672-the-fundamentals-of-soc-security-operations-center).

### Paid certifications:
* BlueTeamLabs, [BTL](https://securityblue.team/why-btl1/) (level 1 & 2).
* SANS [SEC555: SIEM with tactical analytics](https://www.sans.org/cyber-security-courses/siem-with-tactical-analytics/).
* SANS, [SEC450: Blue Team Fundamentals: Security Operations and Analysis](https://www.sans.org/cyber-security-courses/blue-team-fundamentals-security-operations-analysis/).
* Microsoft, [SC-200: Microsoft Security Operations Analyst](https://learn.microsoft.com/fr-fr/credentials/certifications/exams/sc-200/)
* EC-Council, [CEH](https://www.eccouncil.org/programs/certified-ethical-hacker-ceh/).
* OffensiveSecurity, [OSDA SOC-200](https://www.offensive-security.com/soc200-osda/).
* XMCyber, [Exposure Management](https://xmcyber.com/exposure-management-course/).
* Microsoft, [SC-100: Cybersecurity Architect](https://docs.microsoft.com/en-us/certifications/cybersecurity-architect-expert/).
* Splunk, [Certified Power User](https://www.splunk.com/en_us/training/certification-track/splunk-core-certified-power-user.html)
* Splunk, [Certified Cyberdefense Analyst](https://www.splunk.com/en_us/training/certification-track/splunk-certified-cybersecurity-defense-analyst.html)
* SANS, [SEC587: Advanced Open-Source Intelligence (OSINT) gathering and analysis](https://www.sans.org/cyber-security-courses/advanced-open-source-intelligence-gathering-analysis/).
* SANS, [SEC501: Advanced Security Essentials - Enterprise Defender](https://www.sans.org/cyber-security-courses/advanced-security-essentials-enterprise-defender/).
* SANS, [SEC541: Cloud Security Attacker Techniques, Monitoring, and Threat Detection](https://www.sans.org/cyber-security-courses/cloud-security-attacker-techniques-monitoring-threat-detection/).
* SANS, [SEC699: Purple Team Tactics - Adversary Emulation for Breach Prevention & Detection](https://www.sans.org/cyber-security-courses/purple-team-tactics-adversary-emulation/).


Not working anymore ATOW: EthicalHackersAcademy, [SOC & SIEM Security program: L1, L2, L3](https://ethicalhackersacademy.com/products/soc-siem-security-training-program?_pos=1&_sid=b1d241af4&_ss=r).

# Recommended CERT/CSIRT trainings

## Regular trainings & challenges [Free]
* ENISA, [trainings](https://www.enisa.europa.eu/topics/trainings-for-cybersecurity-specialists/online-training-material).
* FIRST, [trainings](https://www.first.org/education/trainings).
* [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/).
* Microsoft, [Become a Microsoft Sentinel Ninja](https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/become-a-microsoft-sentinel-ninja-the-complete-level-400/ba-p/1246310).
* A. Borges, [MAS series](https://exploitreversing.com/2021/12/03/malware-analysis-series-mas-article-1/).
* [Hack The Box](https://www.hackthebox.com/).
* Root-me, ["Entretien avec l'ANSSI"-named challenges](https://www.root-me.org/).
* Embee Research, [Unpacking .Net malware](https://embee-research.ghost.io/unpacking-net-malware-with-process-hacker/)

## Certifications

### Paid certifications:

* GIAC, [GCIH](https://www.giac.org/certifications/certified-incident-handler-gcih/).
* SANS, [SEC541: Cloud Security Attacker Techniques, Monitoring, and Threat Detection](https://www.sans.org/cyber-security-courses/cloud-security-attacker-techniques-monitoring-threat-detection/).
* SANS, [FOR508: Advanced Incident Response, Threat Hunting, and Digital Forensics](https://www.giac.org/certifications/certified-incident-handler-gcih/).
* SANS, [SEC555: SIEM with tactical analytics](https://www.sans.org/cyber-security-courses/siem-with-tactical-analytics/).
* SANS, [FOR572: Advanced Network Forensics: Threat Hunting, Analysis, and Incident Response](https://www.sans.org/cyber-security-courses/siem-with-tactical-analytics/).
* SANS, [FOR578: Cyber Threat Intelligence](https://www.sans.org/cyber-security-courses/cyber-threat-intelligence/).
* SANS, [FOR610: Reverse-Engineering Malware: Malware Analysis Tools and Techniques](https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/).
  
### Free certifications:
* CrowdSec, [CrowdSec Fundamentals](https://academy.crowdsec.net/course/crowdsec-fundamentals)  [free]
* Splunk, [Core User](https://education.splunk.com/single-subject-courses?_ga=2.213139857.446951445.1644415141-362195814.1644415141).




# Recommended offensive security trainings

NB: this is mainly for red/purpleteaming activities.

## Regular trainings
* Mariusz Banach, [Evasion in Depth - Techniques Across the Kill-Chain](https://www.youtube.com/watch?v=IbA7Ung39o4&ab_channel=x33fcon)
* Cybrary, [MITRE ATT&CK threat hunting](https://www.cybrary.it/course/mitre-attack-threat-hunting/).
* [HackTheBox](https://www.hackthebox.com/).
* CybersecurityUp, [OSCE complete guide](https://github.com/CyberSecurityUP/OSCE-Complete-Guide).
* [RTFM](https://www.amazon.com/RTFM-Red-Team-Field-Manual/dp/1075091837).

## Certifications
* Offensive Security [OSCP](https://www.offensive-security.com/pwk-oscp/).
* SANS, [SEC541: Cloud Security Attacker Techniques, Monitoring, and Threat Detection](https://www.sans.org/cyber-security-courses/cloud-security-attacker-techniques-monitoring-threat-detection/).
* SANS, [SEC565: Red Team Operations and Adversary Emulation](https://www.sans.org/offensive-operations/).
* SANS, [SEC699: Purple Team Tactics - Adversary Emulation for Breach Prevention & Detection](https://www.sans.org/cyber-security-courses/purple-team-tactics-adversary-emulation/).
* SANS, [SEC760: Advanced Exploit Development for Penetration Testers](https://www.sans.org/cyber-security-courses/advanced-exploit-development-penetration-testers/).

# Recommended management trainings

## Paid certifications

* SANS, [MGT512: Security Leadership Essentials for Managers](https://www.sans.org/cyber-security-courses/security-leadership-essentials-managers/)
* SANS, [SEC450: Blue Team Fundamentals: Security Operations and Analysis](https://www.sans.org/cyber-security-courses/blue-team-fundamentals-security-operations-analysis/).
* ISC2, [CISSP](https://www.isc2.org/certifications/cissp)

# To go further

* [The best BlackHat and DefCon talks of all time](https://portswigger.net/daily-swig/the-best-black-hat-and-def-con-talks-of-all-time)
 
# End
Go to [main page](https://github.com/cyb3rxp/awesome-soc/blob/main/README.md).
