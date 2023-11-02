# Threat intelligence: Table of Content

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

![image](https://user-images.githubusercontent.com/16035152/232339967-dfa4bab5-79eb-496c-ac19-6d7e3e98af92.png)

## Architecture example

Here is [an example](https://securityonline.info/s1em-siem-with-sirp-and-threat-intel/) of an architecture with:
 * SIEM: Elastic;
 * TIP: MISP / OpenCTI;
 * SIRP: TheHive;
 * Threat intel orchestrator: Cortex.
 
![image](https://user-images.githubusercontent.com/16035152/204066143-6c0a9cf0-67ab-44c7-b67e-af5df5a07219.png)


# Sources
* Feeds and portails:
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
     * Jeroen Steeman, [IPBlock lists](https://jeroen.steeman.org/IPBlock)
     * [si3t.ch](http://si3t.ch/evils/)
     * [Execute Malware](https://github.com/executemalware/Malware-IOCs/tree/main)
     * [FireHOL project: GreenSwow IP set](https://github.com/firehol/blocklist-ipsets/blob/master/greensnow.ipset)
     * [Snort, IP list to block](https://www.snort.org/downloads/ip-block-list)
     * [Turris' Sentinel Graylist](https://view.sentinel.turris.cz/greylist-data/greylist-latest.csv)
     * [Laurent Minne"s blacklist](https://raw.githubusercontent.com/duggytuxy/malicious_ip_addresses/main/botnets_zombies_scanner_spam_ips.txt)
     * [MalTrail's daily blacklist](https://raw.githubusercontent.com/stamparm/aux/master/maltrail-malware-domains.txt)
     * [Awesome Cobalt Strike](https://github.com/MichaelKoczwara/Awesome-CobaltStrike-Defence)
  * To go further, some lists of feeds that could be of interest:
    * [Covert.io list](http://www.covert.io/threat-intelligence/);
    * [Intel471](https://intel471.com/modules)
  * And a reference framework to analyze data information leaks: [AIL Framework](https://github.com/CIRCL/AIL-framework)

     

* Portals to query on-the-fly:
  * My recommendations: 
     * [VirusTotal API](https://support.virustotal.com/hc/en-us/articles/115002100149-API).
     * [CrowdSec community](https://app.crowdsec.net/cti)
     * [AbuseIPDB](https://www.abuseipdb.com/);
     * [URLHaus](https://urlhaus.abuse.ch/api/);
     * [OTX](https://otx.alienvault.com/api);

* Well-known OSINT portals:
  * CyberGordon >> https://cybergordon.com/
  * URL analysis >> https://urlscan.io/
  * Data breaches >> https://haveibeenpwned.com/
  * Cisco Reputation Check >> https://www.talosintelligence.com/
  * IBM Reputation Check >> https://lnkd.in/gt8iyHE5
  * IP Reputation Check >>https://www.abuseipdb.com/
  * Domain diagnostic & lookup tools >> https://mxtoolbox.com/
  * Domain/IP investigation >> https://cipher387.github.io/domain_investigation_toolbox/ip.html
  * CyberChef >> https://lnkd.in/gVjZywKu
  * DNS related tools >> https://viewdns.info/
  * Search Engine for IoTs >> https://www.shodan.io/
  * OSINT Framework >> https://lnkd.in/gXaz_Wry
  * Malfrat's OSINT >> https://lnkd.in/e4nhK2hK
  * Find Emails >> https://hunter.io/
  * Internet Archieve >> https://archive.org/web/
  * Reverse Image search >> https://tineye.com  
  * Cyberspace Search >> https://www.zoomeye.org/
  * Search Engine >> https://search.censys.io/
  * Website Profiler Tool >> https://builtwith.com/
  * Email Info >> https://epieos.com/
  * File Search engine >> https://filepursuit.com/
  
* TOR search:
  * [OnionSearch](https://github.com/megadose/OnionSearch)
  * [DarkDump2](https://github.com/josh0xA/darkdump)

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
