# ToC

* [Must read](https://github.com/cyb3rxp/awesome-soc/blob/main/threat_intelligence.md#must-read)
* [Generic workflow](https://github.com/cyb3rxp/awesome-soc/blob/main/threat_intelligence.md#generic-workflow)
* [Platform](https://github.com/cyb3rxp/awesome-soc/blob/main/threat_intelligence.md#platform)
* [Sources](https://github.com/cyb3rxp/awesome-soc/blob/main/threat_intelligence.md#sources)
* [Threat intelligence and automation](https://github.com/cyb3rxp/awesome-soc/blob/main/threat_intelligence.md#threat-intelligence-and-automation)


# Must read

* MITRE, [top TTP for ransomwares](https://top-attack-techniques.mitre-engenuity.org/)
* David J. Bianco, [Pyramid of pain](https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html)
* OASIS Open, [STIX](https://oasis-open.github.io/cti-documentation/stix/intro.html)
* FIRST, [TLP](https://www.first.org/tlp/) (intelligence sharing and confidentiality)
* [Awesome Threat Intelligence](https://github.com/hslatman/awesome-threat-intelligence) 

# Generic workflow

Here is [an example](https://www.erdalozkaya.com/cyber-threat-intelligence/) of what we could expect to have:

![image](https://user-images.githubusercontent.com/16035152/204064894-943ad4e9-c1f6-4e5e-a7d8-ac5eb22f13fe.png)


# Platform
## TIP choice 
Here are my recommendations:
* for community ones: [MISP](https://www.misp-project.org/), [OpenCTI](https://www.filigran.io/en/products/opencti/);
* for paid ones: [Sekoia.io](https://www.sekoia.io/fr/produire-et-personnaliser-votre-propre-intelligence/), [ThreatQuotient](https://www.threatq.com/)

## Common TIP integrations (dataflow)

As per [Forrester article](https://www.forrester.com/blogs/15-11-07-starting_soon_threat_intelligence_platforms_research_0/), here is a drawing about examples of common integration between threat intel sources, TIP, and security solutions:

![image](https://user-images.githubusercontent.com/16035152/204065814-2fc1b048-94d7-4f73-885e-b12d24ae2939.png)

## Architecture example

Here is [an example](https://securityonline.info/s1em-siem-with-sirp-and-threat-intel/) of an architecture with:
 * SIEM: Elastic;
 * TIP: MISP / OpenCTI;
 * SIRP: TheHive;
 * Threat intel orchestrator: Cortex.
 
![image](https://user-images.githubusercontent.com/16035152/204066143-6c0a9cf0-67ab-44c7-b67e-af5df5a07219.png)


# Sources
* Feeds:
   * My recommendations for paid ones: 
     * [ESET](https://www.eset.com/us/business/services/threat-intelligence/);
     * [Sekoia.io](https://www.sekoia.io/fr/sekoia-io-cti/); 
     * [Mandiant](https://www.mandiant.com/advantage/threat-intelligence/subscribe); 
     * [RecordedFuture](https://www.recordedfuture.com/platform/threat-intelligence); 
     * [Netcraft](https://www.netcraft.com/cybercrime/malicious-site-feeds/); 
     * [Gatewatcher](https://www.gatewatcher.com/en/our-solutions/lastinfosec/);
     * [CrowdSec](https://app.crowdsec.net/cti)...
   * My recommendations for community ones: 
     * [URLHaus](https://urlhaus.abuse.ch/api/); 
     * [ISAC](https://www.enisa.europa.eu/publications/information-sharing-and-analysis-center-isacs-cooperative-models);
     * [OTX](https://otx.alienvault.com/api);
     * [VX Vault URL](http://vxvault.net/URL_List.php);
     * [AbuseIPDB](https://www.abuseipdb.com/);
     * [Feodo Tracker](https://feodotracker.abuse.ch/blocklist/)
     * [PAN Unit42](https://github.com/pan-unit42/iocs);
     * [ESET IOC](https://github.com/eset/malware-ioc);
     * [Intrinsec IOC](https://github.com/Intrinsec/IOCs);
     * [Malware-IOC](https://github.com/executemalware/Malware-IOCs);
     * [OpenPhish](https://openphish.com/feed.txt);
     * [Bazaar](https://bazaar.abuse.ch/export/csv/recent/);
     * [C2IntelFeeds](https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv);
     * [Circle's MISP feed](https://www.circl.lu/doc/misp/feed-osint/);
     * [Viriback](https://tracker.viriback.com/dump.php);
     * [CERT-FR's MISP feed](https://misp.cert.ssi.gouv.fr/feed-misp/);
     * [Orange CyberDefense, Log4Shell IOC](https://github.com/Orange-Cyberdefense/log4shell_iocs);
     * [Orange CyberDefense, RU/UKR IOC](https://github.com/Orange-Cyberdefense/russia-ukraine_IOCs);
     * The [Covert.io list](http://www.covert.io/threat-intelligence/);
     


* Portals to query on-the-fly:
  * My recommendations: [VirusTotal API](https://support.virustotal.com/hc/en-us/articles/115002100149-API).

* well-known OSINT portals:
  * Threat Intelligience 101 >> https://lnkd.in/gfpd__xz
  * URL, IP, domain, file hash >> https://lnkd.in/gNqxtn4d
  * URL Sandbox >> https://urlscan.io/
  * Cisco Reputation Check >> https://lnkd.in/g7uWdC5q
  * Diagnostic & lookup tools >> https://mxtoolbox.com/
  * CyberChef >> https://lnkd.in/gVjZywKu
  * Browser Sandbox>> https://lnkd.in/gjA-QqdX
  * IBM Reputation Check >> https://lnkd.in/gt8iyHE5
  * IP Reputation Check >>https://www.abuseipdb.com/
  * DNS related tools >> https://viewdns.info/
  * OSINT Framework >> https://lnkd.in/gXaz_Wry
  * Malfrat's OSINT >> https://lnkd.in/e4nhK2hK
  * Find Emails >> https://hunter.io/
  * Find People >> https://lnkd.in/g4bcUH_b
  * Internet Archieve >> https://archive.org/web/
  * Reverse Image search >> https://tineye.com  
  * Link and data mining >>https://lnkd.in/gf9BUFWk
  * Data breaches >> https://lnkd.in/gvbzhceV
  * Search Engine for IoTs>> https://www.shodan.io/
  * Cyberspace Search >> https://www.zoomeye.org/
  * Search Engine >> https://search.censys.io/
  * Website Profiler Tool >>https://builtwith.com/
  * Email Info >>https://epieos.com/
  * File Search engine >> https://filepursuit.com/
  * Domain investigation >> https://lnkd.in/e2c27zc7
  * CyberGordon >> https://cybergordon.com/


# Threat intelligence and automation

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
