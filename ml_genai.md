# Gen AI and machine learning opportunities for a SOC
[WIP]

This page deals with what Gen AI, AI agents, and machine leaning can effectively bring to a SOC (plus their downsides). Not marketing speech here, only watch and field feedback.


# Machine learning use cases for a SOC

## Network trafic abnomalies detection

* RAW data: Sysmon logs, DNS logs, firewall logs, router logs
* Goal of the detection: detect unusual trafic peaks that could become denial of service, or information leak
* Use of machine learning: learn usual trafic, including common sources and common peaks (frequency, protocol, sources, etc.), and then alert on uncommon/unseen sources and peaks.
* Field feedback: likely prone to false positives, and may require months of training plus a huge amount of data to train the machine learning system.


## Files executions abnomalies detection

* RAW data: Sysmon logs, System (Windows/linux) logs, HIDS logs, EDR logs
* Goal of the detection:
   * detect never previously seen files that are being executed = > potential new malware/variant
   * detect files that are suddenly and unexpectedly executed on a large number of endpoints  = > potential infection spread or lateral movement
* Use of machine learning: learn usually executed files (path, hash) to alert on unexpected/uncommon executions
* Field feedback: likely prone to false positives if you don't have a good systems/applications inventory and required logs, to train the machine learning system.





# Gen AI use cases for a SOC

## Artefacts analysis acceleration

### Command line

* Context: EDR alert for a process or a file
* Elments to be analyzed: long commandline with numerous arguments and potential obfuscation
* Use of Gen IA: quickly understand the command line and then determine wether it is malicious or not, based on the alert details.

### Registry keys

* Context: EDR alert for a registry key change/access/deletion
* Elments to be analyzed: unknwon registry key or value, as well as its impact on the system/security configuration
* Use of Gen IA: quickly understand the registry key use (values, effects), and then determiner wether it is malicious or not, based on the alert details.



## Cyber-attack understanding

### Security solutions detections 

* Context: EDR, NDR, SEG, SWG, ITDR, CASB, etc. alert 
* Elments to be analyzed: artefacts associated to the alert, as well as the attack type itself as per the detected attack name
* Use of Gen IA: quickly understand the attack type (TTP) and the ways it works, then determine wether the alert is confirmed or not, based on the information it contains.



