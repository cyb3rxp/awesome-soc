# SOC HR and training

This page deals with SOC HR and training topics.

# ToC

* [Must read](https://github.com/cyb3rxp/awesome-soc/blob/main/hr_training.md#must-read)
* [HR roles and organization](https://github.com/cyb3rxp/awesome-soc/blob/main/hr_training.md#hr-roles-and-organization)
* [Recommended SOC trainings](https://github.com/cyb3rxp/awesome-soc/blob/main/hr_training.md#recommended-soc-trainings)
* [Recommended CERT/CSIRT trainings](https://github.com/cyb3rxp/awesome-soc/blob/main/hr_training.md#recommended-certcsirt-trainings)
* [Recommended offesnsive security trainings](https://github.com/cyb3rxp/awesome-soc/edit/main/hr_training.md#recommended-offensive-security-trainings)



# Must read
* MITRE, [11 strategies for a world-class SOC]([https://top-attack-techniques.mitre-engenuity.org/](https://github.com/cyb3rxp/awesome-soc/blob/main/11-strategies-of-a-world-class-cybersecurity-operations-center.pdf)), Strategy 4, pages 101-123

![image](https://user-images.githubusercontent.com/16035152/208257245-e481c2ad-4523-438c-9e49-a5e0999c300f.png)


# HR roles and organization

As per what is explained on the [management page](https://github.com/cyb3rxp/awesome-soc/blob/main/management.md#soc-organization), I would recommend to make sure the following roles are being assigned to people:
* SOC analyst;
* SOC analyst senior;
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

They can be FTE or outsourced, it will depend on your needs and constraints. My recommendations are explained in the RACI template that I propose.


# Recommended SOC trainings

## Regular trainings
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
* [SOC Vel](https://socvel.com/challenges/)
* [ENISA trainings](https://www.enisa.europa.eu/topics/trainings-for-cybersecurity-specialists/online-training-material), free!
* Splunk: 
  * Free trainings: 
    * https://education.splunk.com/course/intro-to-splunk-elearning
    * https://education.splunk.com/course/using-fields
    * https://education.splunk.com/course/intro-to-dashboards-elearning
    * https://education.splunk.com/course/scheduling-reports-alerts-elearning
    * https://education.splunk.com/course/creating-knowledge-objects-elearning
    * https://education.splunk.com/catalog?category=getting-data-in
    * https://education.splunk.com/course/intro-to-knowledge-objects-elearning
    * https://education.splunk.com/catalog?category=search-under-the-hood
    * https://education.splunk.com/course/visualizations-elearning
    * https://education.splunk.com/course/creating-field-extractions-elearning
    * https://education.splunk.com/course/enriching-data-with-lookups-elearning  
  * CTF: BOTS (free):
    * https://cyberdefenders.org/search/labs/?q=splunk
  * Attack simulation & investigation: [Splunk attack range](https://github.com/splunk/attack_range_cloud)
* PaloAlto, Fundamentals of SOC](https://beacon.paloaltonetworks.com/student/path/521672-the-fundamentals-of-soc-security-operations-center), mainly modules 1 to 8 :)
* Microsoft, [Become an Azure Sentinel Ninja](https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/become-a-microsoft-sentinel-ninja-the-complete-level-400/ba-p/1246310) (free).


## Certifications
* [BlueTeamLabs](https://securityblue.team/why-btl1/) (level 1 & 2)
* [SANS SEC555: SIEM with tactical analytics](https://www.sans.org/cyber-security-courses/siem-with-tactical-analytics/)
* [SANS SEC450: Blue Team Fundamentals: Security Operations and Analysis](https://www.sans.org/cyber-security-courses/blue-team-fundamentals-security-operations-analysis/)
* [SOC & SIEM Security program: L1, L2, L3](https://ethicalhackersacademy.com/products/soc-siem-security-training-program?_pos=1&_sid=b1d241af4&_ss=r)
* [Splunk Core User](https://education.splunk.com/single-subject-courses?_ga=2.213139857.446951445.1644415141-362195814.1644415141)
* [Microsoft Cybersecurity Architect](https://docs.microsoft.com/en-us/certifications/cybersecurity-architect-expert/)
* [Microsoft Sentinel Ninja](https://forms.office.com/pages/responsepage.aspx?id=v4j5cvGGr0GRqy180BHbR1irKnVJZ_RBhccteqa39A9UN08wTjY4MzROVDhUUFRZRTgwME1HSUlFQS4u)
* [AWS Security Fundamentals](https://aws.amazon.com/training/digital/aws-security-fundamentals/?nc1=h_ls)
* [PAN, Fundamentals of network security](https://beacon.paloaltonetworks.com/student/path/673504/activity/726463)
* [PAN, Fundamentals of SOC](https://beacon.paloaltonetworks.com/student/path/521672-the-fundamentals-of-soc-security-operations-center)
* [CEH](https://www.eccouncil.org/programs/certified-ethical-hacker-ceh/)
* [OSDA SOC-200](https://www.offensive-security.com/soc200-osda/)
* SANS, SEC501: Advanced Security Essentials - Enterprise Defender
* SANS, SEC541: Cloud Security Attacker Techniques, Monitoring, and Threat Detection
* SANS, SEC699: Purple Team Tactics - Adversary Emulation for Breach Prevention & Detection
* SANS, SEC497: Practical Open-Source Intelligence (OSINT).


# Recommended CERT/CSIRT trainings

## Regular trainings
* [ENISA trainings](https://www.enisa.europa.eu/topics/trainings-for-cybersecurity-specialists/online-training-material)
* [FIRST trainings](https://www.first.org/education/trainings)
* [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/)
* [Become a Microsoft Sentinel Ninja](https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/become-a-microsoft-sentinel-ninja-the-complete-level-400/ba-p/1246310)
* A. Borges, [MAS series](https://exploitreversing.com/2021/12/03/malware-analysis-series-mas-article-1/)
* [Hack The Box](https://www.hackthebox.com/)

## Certifications
* [SANS FOR572: Advanced Network Forensics: Threat Hunting, Analysis, and Incident Response](https://www.sans.org/cyber-security-courses/siem-with-tactical-analytics/)
* SANS, SEC541: Cloud Security Attacker Techniques, Monitoring, and Threat Detection
* [Splunk Core User](https://education.splunk.com/single-subject-courses?_ga=2.213139857.446951445.1644415141-362195814.1644415141)
* [GCIH](https://www.giac.org/certifications/certified-incident-handler-gcih/)
* [SANS FOR508: Advanced Incident Response, Threat Hunting, and Digital Forensics](https://www.giac.org/certifications/certified-incident-handler-gcih/)
* [SANS FOR610: Reverse-Engineering Malware: Malware Analysis Tools and Techniques](https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/)
* [SANS SEC555: SIEM with tactical analytics](https://www.sans.org/cyber-security-courses/siem-with-tactical-analytics/)
* [SANS FOR578: Cyber Threat Intelligence](https://www.sans.org/cyber-security-courses/cyber-threat-intelligence/)


# Recommended offensive security trainings

NB: this is for red/purpleteaming activities.

## Regular trainings
* CybersecurityUp, [OSCE complete guide](https://github.com/CyberSecurityUP/OSCE-Complete-Guide)
* [RTFM](https://www.amazon.com/RTFM-Red-Team-Field-Manual/dp/1075091837).

## Certifications
* Offensive Securiy [OSCP](https://www.offensive-security.com/pwk-oscp/)
* SANS, [SEC565: Red Team Operations and Adversary Emulation](https://www.sans.org/offensive-operations/)
* SANS, SEC760: Advanced Exploit Development for Penetration Testers
* SANS, SEC699: Purple Team Tactics - Adversary Emulation for Breach Prevention & Detection.
* SANS, SEC541: Cloud Security Attacker Techniques, Monitoring, and Threat Detection

# Recommended management trainings

## Certifications

* [SANS, MGT512: Security Leadership Essentials for Managers](https://www.sans.org/cyber-security-courses/security-leadership-essentials-managers/)

# To go further

## Must read

 
# End
Go to [main page](https://github.com/cyb3rxp/awesome-soc/blob/main/README.md).

