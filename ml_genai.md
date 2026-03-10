# Gen AI and machine learning opportunities for a SOC
[WIP]

This page deals with what Gen AI, AI agents, and machine leaning can effectively bring to a SOC (plus their downsides). Not marketing speech here, only watch and field feedback.


# Must read

* ENISA, [Multilayer framework for good cybersecurity practices for AI](https://www.enisa.europa.eu/publications/multilayer-framework-for-good-cybersecurity-practices-for-ai)
* OWASP, [LLM and Gen AI security best practices](https://genai.owasp.org/resource/llm-and-gen-ai-data-security-best-practices/)
* NIST, [AI 600](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)
* CyberSecurityForme, [Microsoft Copilot Security vulnerabilities and safety measures](https://cybersecurityforme.com/copilot-security-vulnerabilities-and-safety-measures-for-enterprises/)
  

# Machine learning use cases for a SOC

## Network trafic abnomalies detection

* RAW data: Sysmon logs, DNS logs, firewall logs, router logs
* Goal of the detection: detect unusual trafic peaks that could become denial of service, or information leak
* Use of machine learning: learn usual trafic, including common sources and common peaks (frequency, protocol, sources, etc.), and then alert on uncommon/unseen sources and peaks.
* Field feedback: interesting but likely prone to false positives, and may require months of training plus a huge amount of data to train the machine learning system.


## Binaries execution abnomalies detection

* RAW data: Sysmon logs, System (Windows/linux) logs, HIDS logs, EDR logs
* Goal of the detection:
   * detect never previously seen files that are being executed = > potential new malware/variant
   * detect files that are suddenly and unexpectedly executed on a large number of endpoints  = > potential infection spread or lateral movement
* Use of machine learning: learn usually executed files (path, hash) to alert on unexpected/uncommon executions
* Field feedback: interesting but likely prone to false positives if you don't have a good systems/applications inventory and required logs, to train the machine learning system.





# Gen AI / LLM use cases for a SOC

## Analysis acceleration

### Command line

* Context: EDR alert for a process or a file
* Elements to be analyzed: long commandline with numerous arguments and potential obfuscation
* Use of Gen AI: quickly understand the command line and then determine wether it is malicious or not, based on the alert details.
* Field feedback: quite efficient and relevant.


### Registry keys

* Context: EDR alert for a registry key change/access/deletion
* Elements to be analyzed: unknown registry key or value, as well as its impact on the system/security configuration
* Use of Gen AI: quickly understand the registry key use (values, effects), and then determiner wether it is malicious or not, based on the alert details.
* Field feedback: quite efficient and relevant.


### Business app 

* Context: specific business app associated to an EDR/NDR alert 
* Elements to be analyzed: business app activity and artefacts (binaries, files tree, network traffic, etc.)
* Use of Gen Ai: quickly have an overview of the business app components, architecture, use cases, then determine wether the alert is confirmed or not, based on the alert details.
* Field feedback: quite useful but mMay be challenging anyhow if the business app is a proprietary one, with almost no open documentation.


## Watch 

* Context: there are more and more papers regarding cyberthreats analysis, plus cybersecurity standards, that are time-consuming to read
* Elements to be analyzed: reports (PDF), blog posts and KB articles
* use of Gen AI: quickly summarize the reports and texts, to get the msot important part of them with a global understanding
* Field feedback: really efficient and relevant.



## Cyber-attack understanding

### Security solutions detections 

* Context: EDR, NDR, SEG, SWG, ITDR, CASB, etc. alert 
* Elments to be analyzed: artefacts associated to the alert, as well as the attack type itself as per the detected attack name
* Use of Gen IA: quickly understand the attack type (TTP) and the ways it works, then determine wether the alert is confirmed or not, based on the information it contains.
* Field feedback: can be useful but may lead to wrong assumtions if analysts don't take the time to deep dive and search, to go beyong the first Gen AI results.



