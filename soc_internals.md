# SOC internals/core 

This page deals with SOC internals: generic architecture, logs to alerts workflow, detection handling workflow, and underlying tools.


# Generic SOC architecture example

Here is [an example](https://docs.tguard.org/) of an architecture, open source based, with:
 * SIEM: Wazuh;
 * TIP: MISP;
    * plus VirusTotal, etc. _via_ automated API requests by SOA.
 * SIRP: IRIS;
 * SOA: Suffle
![image](https://mintcdn.com/sgu-84307e83/drHFaNd1sEsBAeon/images/architect.png?w=1100&fit=max&auto=format&n=drHFaNd1sEsBAeon&q=85&s=95cdb285594dbfe154c419ff6ec05ed4)

As per the [project's GitHub README page](https://github.com/sguresearcher/nusantara/blob/main/README.md):
* Wazuh: Real-time monitoring and alerting for security events.
* DFIR-IRIS: Streamlined incident response and forensics capabilities.
* Shuffle: Automated workflow management to streamline security processes.
* MISP: Open source threat intelligence platform.


# Logs to alerts global workflow

Quoted from [this article](https://www.managedsentinel.com/siem-traditional-vs-cloud/):

![image](https://user-images.githubusercontent.com/16035152/206025151-759a0040-365e-4145-aa88-f7a7b737f8be.png)

Following the arrows, we go from log data sources to data management layer, to then data enrichment layer (where detection happens), to end-up in behavior analytics or at user interaction layer (alerts, threat hunting...). All of that being enabled and supported by automation.


# SOC detection handling workflow

Based on [CYRAIL's paper drawing](https://slideplayer.com/slide/15779727/), that I've slightly modified, here is an example of detection handling workflow with the underlying tools achitecture (SIEM, SIRP, TIP interconnections):
![image](https://user-images.githubusercontent.com/16035152/207597681-22c9da6d-d430-4660-b807-3e86138a0d9c.png)

* Sensors log sources are likely to be: audit logs, security sensors (antimalware, FW, NIDS, proxies, EDR, NDR, CASB, identity threat detection, honeypot...).



 
# End
Go to [main page](https://github.com/cyb3rxp/awesome-soc/blob/main/README.md).
