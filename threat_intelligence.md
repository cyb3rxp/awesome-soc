# ToC

# Must read

* MITRE, [top TTP for ransomwares](https://top-attack-techniques.mitre-engenuity.org/)
* David J. Bianco, [Pyramid of pain](https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html)

# Generic workflow example:

![image](https://user-images.githubusercontent.com/16035152/204064894-943ad4e9-c1f6-4e5e-a7d8-ac5eb22f13fe.png)
(source: https://www.erdalozkaya.com/cyber-threat-intelligence/)

# Threat intel platform
* TIP: 
  * My recommendations for community ones: [MISP](https://www.misp-project.org/), [OpenCTI](https://www.filigran.io/en/products/opencti/);
  * My recommendations for paid ones: [Sekoia.io](https://www.sekoia.io/fr/produire-et-personnaliser-votre-propre-intelligence/), [ThreatQuotient](https://www.threatq.com/)

# Threat intel sources
* Feeds:
     * My recommendations for paid ones: [ESET](https://www.eset.com/us/business/services/threat-intelligence/), [Sekoia.io](https://www.sekoia.io/fr/sekoia-io-cti/), [Mandiant](https://www.mandiant.com/advantage/threat-intelligence/subscribe), [RecordedFuture](https://www.recordedfuture.com/platform/threat-intelligence), [Netcraft](https://www.netcraft.com/cybercrime/malicious-site-feeds/), [Gatewatcher](https://www.gatewatcher.com/en/our-solutions/lastinfosec/)...
     * My recommendations for community ones: [URLHaus](https://urlhaus.abuse.ch/api/), [ISAC](https://www.enisa.europa.eu/publications/information-sharing-and-analysis-center-isacs-cooperative-models), [OTX](https://otx.alienvault.com/api), the [Covert.io list](http://www.covert.io/threat-intelligence/), [MISP default feeds list](https://www.misp-project.org/feeds/).


# Threat intelligence and automation

## Identity-based detections:
 
 * Correlate identity-related detections (from sensors like EDR, CASB, proxies, WAF, AD, ...) with identity intelligence (for instance, passwords leak/sell detection); 
   * Here is an example of the global detection process (with courtesy of RecordedFuture):
  
  ![Capture9](https://user-images.githubusercontent.com/16035152/202507017-15903302-2a61-40ba-9266-30b27de92af6.PNG)
  
  
  
  # End
Go to [main page](https://github.com/cyb3rxp/awesome-soc/blob/main/README.md).
