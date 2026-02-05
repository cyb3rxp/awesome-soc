# Threat intelligence: Table of Content

* [Must read](https://github.com/cyb3rxp/awesome-soc/blob/main/threat_intelligence.md#must-read)
* [Generic workflow](https://github.com/cyb3rxp/awesome-soc/blob/main/threat_intelligence.md#generic-workflow)
* [Platform](https://github.com/cyb3rxp/awesome-soc/blob/main/threat_intelligence.md#platform)
* [Sources](https://github.com/cyb3rxp/awesome-soc/blob/main/threat_intelligence.md#sources)
* [Threat intelligence and automation](https://github.com/cyb3rxp/awesome-soc/blob/main/threat_intelligence.md#threat-intelligence-and-automation)


# Must read/watch

## Books/articles/recordings

* Thomas Roccia, [Visual Threat Intelligence](https://www.amazon.fr/Visual-Threat-Intelligence-Illustrated-Researchers/dp/B0C7JCF8XD);
* MITRE, [top TTP for ransomwares](https://top-attack-techniques.mitre-engenuity.org/);
* David J. Bianco, [Pyramid of pain](https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html);
* OASIS Open, [STIX](https://oasis-open.github.io/cti-documentation/stix/intro.html);
* FIRST, [TLP](https://www.first.org/tlp/) (intelligence sharing and confidentiality);
* [Awesome Threat Intelligence](https://github.com/hslatman/awesome-threat-intelligence);
* RecordedFuture, [Accelerate SecOps workflows in Microsoft Sentinel](https://go.recordedfuture.com/recordings/webinar-how-to-accelerate-secops-workflows-in-microsoft-azure-sentinel);
* Frost & Sullivan, [Frost Radar™: Cyber Threat Intelligence Radar, 2024](https://go.recordedfuture.com/hubfs/reports/Frost%20Radar_Cyber%20Threat%20Intelligence%20Radar%2c%202024.pdf?utm_medium=email&_hsmi=315810587&utm_content=315810587&utm_source=hs_automation)
* SecurityAffairs, [UKR/RU cyberwar](https://securityaffairs.com/128727/cyber-warfare-2/feb-27-mar-05-ukraine-russia-cyberwar.html)
* Gartner, [Market Guide for Security Threat Intelligence Products and Services](https://www.gartner.com/doc/reprints?id=1-2IJMCHZX&ct=240815&st=sb)
* Filigran & RecordedFuture, [Automate security response with RecordedFuture and Filigran](https://go.recordedfuture.com/automate-security-response-with-recorded-future-and-filigran?utm_medium=email&_hsmi=333916307&utm_content=333916307&utm_source=hs_email)
* ENISA [Threat landscape 2025](https://www.enisa.europa.eu/publications/enisa-threat-landscape-2025)


## What is threat intel (service)?

As per [Gartner](https://www.gartner.com/doc/reprints?id=1-2IJMCHZX&ct=240815&st=sb):
> The mandatory features for services in this market include:
> * Indicators of compromise (IoCs), including malicious or suspicious ratings, such as IP addresses, URLs, domains and file hashes.
> * Direct technical intelligence collection or research, enabling the consumer to tailor collection or search functionality for relevant IoCs.
> * Configuration of alerting thresholds based on predefined criteria.
> * Machine-to-machine integrations to either push or pull intelligence artifacts through to multiple solutions.
> * Out-of-the-box enrichments to IoCs, such as tentative attribution, geolocation data and registration information.
> * An interactive user portal with built-in analysis functionalities such as contextualized dashboards, configurable alerting and search features.
> * IOC scoring or risk rating as a way to illustrate confidence in maliciousness or suspiciousness.
> * Investigative support options, which may include ad hoc requests-for-information, longer-term analysis or recurring analyst augmentation.


## TI / DRPS / EASM

Reminder:
* DRPS = digital risk protection services.
  * As per Gartner:
   > DRPS stretch detection and monitoring activities outside of the enterprise perimeter by searching for threats to enterprise digital resources, such as IP addresses, domains and brand-related assets. DRPS solutions provide visibility into the open (surface) web, dark web and deep web environments by providing contextual information on threat actors and the tactics and processes that they exploit to conduct malicious activities.
    > DRPS providers support a variety of roles (such as chief information security officers, risk, compliance and legal teams, HR and marketing professionals) to map and monitor digital assets. They also support mitigating activities such as site/account takedowns and the generation of customized reporting. Takedown services can include forensics (postinvestigation and data recovery) and after-action monitoring.
* EASM = external attack surface management
  * As per Gartner:
  > EASM is an adjacent technology market that overlaps with DRPS and TI. It is a combination of technology, processes and managed services that provides visibility of known and unknown digital assets to give organizations an outside-in view of their environment [...]. This, in turn, can help organizations prioritize threat and exposure treatment activity. However, Gartner predicts that EASM capabilities will be assimilated into other security solutions (i.e., DRPS, TI, vulnerability management, exposure assessment and adversarial exposure validation) in the near future, and may no longer be a stand-alone market in the next three to five years.

As per [Gartner](https://www.gartner.com/doc/reprints?id=1-2IJMCHZX&ct=240815&st=sb):

![image](https://github.com/user-attachments/assets/899ff352-3eb3-460f-8a0e-9d6cce5bdfa3)



## Threat Intel DIKI Pyramid

As per [Gartner](https://www.gartner.com/doc/reprints?id=1-2IJMCHZX&ct=240815&st=sb), 
![image](https://github.com/user-attachments/assets/4c7a673f-8eb6-4873-a01f-3d5d1db0efad)


# Threat intel life cycle

Here is [an overview](https://erdalozkaya.com/2021/06/06/cyber-threat-intelligence/) of a generic cyber threat intel lifecycle, with the following key steps:
* Plannning & Direction,
* Collection,
* Processing & Exploitation;
* Analysis & Production,
* Dissemination & Integration.

![image](https://github.com/user-attachments/assets/64762e93-6266-4a5f-874b-a6d1dd639ac0)



# Platform

## TIP choice 
Here are my recommendations:
* for community ones: [MISP](https://www.misp-project.org/), [OpenCTI](https://www.filigran.io/en/products/opencti/);
* for paid ones: [Sekoia.io](https://www.sekoia.io/fr/produire-et-personnaliser-votre-propre-intelligence/), [ThreatQuotient](https://www.threatq.com/).

## Common TIP integrations (dataflow)

As per [Forrester article](https://www.forrester.com/blogs/15-11-07-starting_soon_threat_intelligence_platforms_research_0/), here is a drawing about examples of common integration between threat intel sources, TIP, and security solutions:

![image](https://user-images.githubusercontent.com/16035152/232339967-dfa4bab5-79eb-496c-ac19-6d7e3e98af92.png)

## Architecture example

Here is [an example](https://securityonline.info/s1em-siem-with-sirp-and-threat-intel/) of an architecture with:
 * SIEM: Elastic;
 * TIP: MISP / OpenCTI;
 * SIRP: TheHive;
 * Threat intel orchestrator: Cortex.
 
![image](https://user-images.githubusercontent.com/16035152/204066143-6c0a9cf0-67ab-44c7-b67e-af5df5a07219.png)


# Sources
* Feeds and portals:
   * My recommendations for paid ones: 
     * [ESET](https://www.eset.com/us/business/services/threat-intelligence/);
     * [Sekoia.io](https://www.sekoia.io/fr/sekoia-io-cti/); 
     * [Mandiant](https://www.mandiant.com/advantage/threat-intelligence/subscribe); 
     * [RecordedFuture](https://www.recordedfuture.com/platform/threat-intelligence); 
     * [Netcraft](https://www.netcraft.com/cybercrime/malicious-site-feeds/); 
     * [Gatewatcher](https://www.gatewatcher.com/en/our-solutions/lastinfosec/);
     * [CrowdSec](https://www.crowdsec.net/pricing);
     * [HaveIBeenPwned](https://haveibeenpwned.com/API/Key)
   * My recommendations for community ones: 
     * [URLHaus](https://urlhaus.abuse.ch/api/#csv);
     * [ISAC](https://www.enisa.europa.eu/publications/information-sharing-and-analysis-center-isacs-cooperative-models);
     * [VX Vault URL](http://vxvault.net/URL_List.php);
     * [Feodo Tracker](https://feodotracker.abuse.ch/blocklist/)
     * [PAN Unit42](https://github.com/pan-unit42/iocs);
     * [PAN Unit42 Timely threat intel](https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/tree/main)
     * [ESET IOC](https://github.com/eset/malware-ioc);
     * [WithSecure IOC](https://github.com/WithSecureLabs/iocs/tree/master);
     * [Intrinsec IOC](https://github.com/Intrinsec/IOCs);
     * [Malware-IOC](https://github.com/executemalware/Malware-IOCs);
     * [OpenPhish](https://openphish.com/feed.txt);
     * [Bazaar](https://bazaar.abuse.ch/export/csv/recent/);
     * [C2IntelFeeds](https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv);
     * [Circle's MISP feed](https://www.circl.lu/doc/misp/feed-osint/);
     * [Viriback](https://tracker.viriback.com/dump.php);
     * [CERT-FR's MISP feed](https://misp.cert.ssi.gouv.fr/feed-misp/);
     * Orange CyberDefense, [Log4Shell IOC](https://github.com/Orange-Cyberdefense/log4shell_iocs);
     * Orange CyberDefense, [RU/UKR IOC](https://github.com/Orange-Cyberdefense/russia-ukraine_IOCs);
     * [RedFlag Domains](https://red.flag.domains/);
     * Jeroen Steeman, [IPBlock lists](https://jeroen.steeman.org/IPBlock);
     * [si3t.ch](http://si3t.ch/evils/);
     * [Execute Malware](https://github.com/executemalware/Malware-IOCs/tree/main);
     * [FireHOL project: GreenSwow IP set](https://github.com/firehol/blocklist-ipsets/blob/master/greensnow.ipset);
     * Snort, [IP list to block](https://www.snort.org/downloads/ip-block-list);
     * Turris' [Sentinel Graylist](https://view.sentinel.turris.cz/greylist-data/greylist-latest.csv);
     * Laurent Minne's [blacklist](https://github.com/duggytuxy/malicious_ip_addresses);
     * MalTrail's [daily blacklist](https://raw.githubusercontent.com/stamparm/aux/master/maltrail-malware-domains.txt);
     * [Awesome Cobalt Strike](https://github.com/MichaelKoczwara/Awesome-CobaltStrike-Defence);
     * [AVAST](https://github.com/avast/ioc?tab=readme-ov-file);
     * [ThreatFox](https://threatfox.abuse.ch/);
     * MontySecurity, [C2-Tracker](https://github.com/montysecurity/C2-Tracker/tree/main/data);
     * CrowdSec, [Free Paris2024 Olympic Games blocklist](https://app.crowdsec.net/blocklists/665d96cf0a60f8f3808a5d5c);
     * Mhtcht, [Security lists for SOC/DFIR detections](https://github.com/mthcht/awesome-lists);
     * Sekoia, [Happy YARA Christmas](https://github.com/SEKOIA-IO/Community/tree/main/yara_rules);
     * [Maltiverse](https://whatis.maltiverse.com/feeds/)
     * [StalkPhish](https://www.stalkphish.io/)
     * CIRCL [GCVE Vulnerability Lookup](https://vulnerability.circl.lu/)
  * To go further, some lists of feeds that could be of interest:
    * [Covert.io list](http://www.covert.io/threat-intelligence/);
    * [Intel471](https://intel471.com/modules);
    * [Bert JanP](https://github.com/Bert-JanP/Open-Source-Threat-Intel-Feeds/tree/main);
  * And a reference framework to analyze data information leaks: [AIL Framework](https://github.com/CIRCL/AIL-framework).

     

* Portals to query on-the-fly:
  * My recommendations: 
     * [VirusTotal API](https://docs.virustotal.com/reference/overview);  
     * [CrowdSec community](https://app.crowdsec.net/cti);
     * [AbuseIPDB](https://www.abuseipdb.com/);
     * [URLHaus](https://urlhaus.abuse.ch/api/);
     * [OTX](https://otx.alienvault.com/api);

* Well-known OSINT portals/websites:
  * CyberChef >> https://cyberchef.io/
  * URL/IP multi-search portal:
     * CyberGordon >> https://cybergordon.com/
  * URL analysis >> https://urlscan.io/
  * Data breaches search portals:
     * https://haveibeenpwned.com/
     * https://www.pcloud.com/fr/pass/free-personal-data-breach-checker.html
  * Cisco Reputation Check >> https://www.talosintelligence.com/
  * IBM Reputation Check >> https://exchange.xforce.ibmcloud.com/
  * IP Reputation Check >>https://www.abuseipdb.com/
  * Domain/IP investigation >> https://cipher387.github.io/domain_investigation_toolbox/ip.html
  * Malicious IPs and domains >> https://check-the-sum.fr
  * Domain diagnostic & lookup tools >> https://mxtoolbox.com/
  * DNS related tools >> https://viewdns.info/
  * Search Engine for IoTs >> https://www.shodan.io/
  * OSINT Framework >> https://lnkd.in/gXaz_Wry
  * Malfrat's OSINT >> https://map.malfrats.industries/
  * Find Emails >> https://hunter.io/
  * Internet Archieve >> https://archive.org/web/
  * Reverse Image search >> https://tineye.com  
  * Cyberspace Search >> https://www.zoomeye.org/
  * Search Engine >> https://search.censys.io/
  * Website Profiler Tool >> https://builtwith.com/
  * Email Info >> https://epieos.com/
  * Email & Phone Info >> https://www.predictasearch.com
  * File Search engine >> https://filepursuit.com/
  * Hudson Rock Free Infostealer Intelligence Toolset - https://www.hudsonrock.com/threat-intelligence-cybercrime-tools
  
* TOR search:
  * [OnionSearch](https://github.com/megadose/OnionSearch)
  * [DarkDump2](https://github.com/josh0xA/darkdump)

# Threat intelligence and automation

## Threat intel data collection and automation

Considering the huge number of OSINT sources you are likely to need to watch for threat intel (IOC, etc.), my recommendation is to try to automate as much as possible the manual part of this recurring process.

Thus, you may want to have a look at tools such as: [Watcher](https://github.com/thalesgroup-cert/Watcher). Here is a sample screenshot of it: 
![image](https://github.com/user-attachments/assets/8a2b2c15-76ee-42de-bcdb-23f4648a3422)


## Threat intel program and automation

As per [ThreatConnect article](https://threatconnect.com/blog/tip-soar-creating-increased-capability-for-less-mature-teams/):
> As threat intelligence drives your orchestrated actions, the result of those actions can be used to create or enhance existing threat intelligence. Thus, a feedback loop is created — threat intelligence drives orchestration, orchestration enhances threat intelligence.

![image](https://user-images.githubusercontent.com/16035152/204065697-12466101-aa54-41a6-a462-a5831a1f22ef.png)


## Identity-based detections
 
* Correlate identity-related detections (from sensors like EDR, CASB, proxies, WAF, AD, ...) with identity intelligence (for instance, passwords leak/sell detection); 
  * Here is an example of the global detection process (with courtesy of RecordedFuture):
  
  ![Capture9](https://user-images.githubusercontent.com/16035152/202507017-15903302-2a61-40ba-9266-30b27de92af6.PNG)
  
    
# End
Go to [main page](https://github.com/cyb3rxp/awesome-soc/blob/main/README.md).
