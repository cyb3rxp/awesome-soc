# Artificial intelligence: machine learning, LLM, and Agentic AI opportunities for SOC and/or CSIRT
[WIP]

This page deals with what Generative AI, AI agents, and machine learning can effectively bring to a SOC (**plus their known downsides**) and/or CSIRT. No marketing speech here, only cybersec watch and field feedback based intel.

# TOC
* [Must read](#must-read)
* [ML use cases for a SOC](#machine-learning-use-cases)
* [GenAI / LLM use cases for a SOC](#gen-ai--llm-use-cases)

# Must read

## Key concepts and underlying technologies
* Medium, [How do LLM work?](https://medium.com/data-science-at-microsoft/how-large-language-models-work-91c362f5b78f) (NB: this also covers machine learning, neural networks, deep learning, GPT, etc.)
* Youtube, [5 types of AI agents](https://www.youtube.com/watch?v=fXizBc03D7E)
* Medium, [Prompt engineering](https://medium.com/@egopgogojob/prompt-engineering-explained-understanding-top-k-top-p-temperature-and-advanced-techniques-b7ae7fa49fda)

## Best practices for SOC/CSIRT teams in the AI era
* ENISA, [View on cybersecurity in the frontier AI era](https://www.enisa.europa.eu/publications/enisas-view-on-cybersecurity-in-the-frontier-ai-era)
* NIST [AI 800-4](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.800-4.pdf): Challenges to the Monitoring of Deployed AI Systems

## Field feedback 
* Microsoft, [Turning threat reports into detection insights with AI](https://www.microsoft.com/en-us/security/blog/2026/01/29/turning-threat-reports-detection-insights-ai/)
* Fr0gger, [Malware Reverse Engineering is no longer a human problem!](https://x.com/fr0gger_/status/2028014798546378938?s=20)
* CSOOnline, [SOCs face a challenge as AI speeds alerts and threats](https://www.csoonline.com/article/4198016/socs-face-a-human-challenge-as-ai-speeds-alerts-and-threats.html?utm_date=20260721140359&utm_campaign=CSO%20Security%20Leadership&utm_content=slotno-1-readmore-The%20future%20of%20the%20security%20operations%20center%20may%20depend%20less%20on%20technology%20than%20on%20how%20well%20security%20leaders%20manage%20human%20attention%2C%20expertise%2C%20and%20resilience.&utm_term=CSO%20US%20Editorial%20Newsletters&utm_medium=email&utm_source=Adestra&aid=8242015&huid=677465b3-4cd2-44f5-ba75-a9eb7364bc6c)

## Best practices for securing AI systems/apps
* ETSI, [Baseline Cyber Security Requirements for AI Models and Systems](https://www.etsi.org/deliver/etsi_en/304200_304299/304223/02.01.01_60/en_304223v020101p.pdf)
* ENISA, [Multilayer framework for good cybersecurity practices for AI](https://www.enisa.europa.eu/publications/multilayer-framework-for-good-cybersecurity-practices-for-ai) 
* OWASP, [LLM and Gen AI security best practices](https://genai.owasp.org/resource/llm-and-gen-ai-data-security-best-practices/)
* NIST, [AI 600](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf): Artificial Intelligence Risk Management Framework: Generative Artificial Intelligence Profile
* NIST, [R 8596](https://csrc.nist.gov/pubs/ir/8596/iprd): Cybersecurity Framework Profile for Artificial Intelligence
* Google, [SAIF](https://safety.google/intl/en/safety/saif/), Secure AI Framework
* CloudSecurityAlliance, [AI Control Matrix](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1)
  * I recommand to read the [related presentation](https://s3.amazonaws.com/content-production.cloudsecurityalliance/hqhtrzyp720yippr3w2wta7qvv4i?response-content-disposition=inline%3B%20filename%3D%22AICM%20v1.1%20Presentation.pdf%22%3B%20filename%2A%3DUTF-8%27%27AICM%2520v1.1%2520Presentation.pdf&response-content-type=application%2Fpdf&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAS6XDIRHKHO4F5SU4%2F20260630%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20260630T161934Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=ddff18eb89298401635f85ac1613f1eb6c1713bbdb6fab80ac984a3dee827d45)

## Threat landscape
* CISCO, [State of AI Security 2026](https://www.cisco.com/site/us/en/products/security/state-of-ai-security.html)
* CrowdStrike, [Global threat landscape 2026: AI Accelerates Adversaries and Reshapes the Attack Surface](https://www.crowdstrike.com/en-us/press-releases/2026-crowdstrike-global-threat-report/)
* Google GTIG, [Adversaries Leverage AI for Vulnerability Exploitation, Augmented Operations, and Initial Access](https://cloud.google.com/blog/topics/threat-intelligence/ai-vulnerability-exploitation-initial-access?hl=en)
* Google GTIC, [Continued Integration of AI for Adversarial Use](https://www.brighttalk.com/webcast/18282/669120?utm_campaign=communication_missed_you&utm_medium=email&utm_source=brighttalk-transact&player-preauth=WpeByEIABmlF9OmrZ8Mr5xMzcFT8gfHVp76f5Ed4%2FaI%3D&utm_content=webcast)
* OWASP, [Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
* CyberSecurityForMe, [Microsoft Copilot Security vulnerabilities and safety measures](https://cybersecurityforme.com/copilot-security-vulnerabilities-and-safety-measures-for-enterprises/)

## Knowledge bases
* Jivoi, [Awesome ML for cybersecurity](https://github.com/jivoi/awesome-ml-for-cybersecurity)


# Machine learning use cases 

## Network traffic anomalies detection

* **RAW data:** Sysmon logs, DNS logs, firewall logs, router logs
* **Goal of the detection:** detect unusual traffic peaks that could become denial of service, or information leak
* **Use of machine learning:** learn usual traffic, including common sources and common peaks (frequency, protocol, sources, etc.), and then alert on uncommon/unseen sources and peaks.
* **Field feedback:** interesting but likely prone to false positives, and may require months of training plus a huge amount of data to train the machine learning system.


## Binaries execution anomalies detection

* **RAW data:** Sysmon logs, System (Windows/linux) logs, HIDS logs, EDR logs
* **Goal of the detection:**
   * detect never previously seen files that are being executed = > potential new malware/variant
   * detect files that are suddenly and unexpectedly executed on a large number of endpoints  = > potential infection spread or lateral movement
* **Use of machine learning:** learn usually executed files (path, hash) to alert on unexpected/uncommon executions
* **Field feedback:** interesting but likely prone to false positives if you don't have a good systems/applications inventory and required logs, to train the machine learning system.





# GenAI / LLM use cases 

## Analysis acceleration (alert/sample)

### Command line

* **Context:** EDR alert for a process or a file
* **Elements to be analyzed:** long commandline with numerous arguments and potential obfuscation
* **Use of GenAI:** quickly understand the command line and then determine whether it is malicious or not, based on the alert details.
* **Field feedback:** quite efficient and relevant.


### Registry keys

* **Context:** EDR alert for a registry key change/access/deletion
* **Elements to be analyzed:** unknown registry key or value, as well as its impact on the system/security configuration
* **Use of GenAI:** quickly understand the registry key use (values, effects), and then determine whether it is malicious or not, based on the alert details.
* **Field feedback:** quite efficient and relevant.


### File sample

* **Context:** you get/grab a sample from an user submission or a "suspicious"-type alert (AV/EDR, proxy, SEG, etc.)
* **Elements to be analyzed:** file sample
* **Use of GenAI:** quickly and automatically produce static analysis, CTI search automation, evasion/persistence detection, and network behavior reports...
* **Field feedback:** See [Malware Reverse Engineering is no longer a human problem!](https://x.com/fr0gger_/status/2028014798546378938?s=20) from Thomas Roccia:
  * Static Analysis: Extract binary features, detect packing/obfuscation
  * Enrichment and Pivoting: OSINT via CTI tools, identify related campaigns/families
  * Reverse Engineering: Disassemble key functions, detect evasion/persistence (e.g., via Unprotect), analyze network behaviors
  * Output Generation: Extract IOCs, map to MITRE ATT&CK, create YARA rules (tested/uploaded for hunting), generate diagrams/graphs, and compile a grounded report with recommendations.


### Business app 

* **Context:** specific business app associated to an EDR/NDR alert 
* **Elements to be analyzed:** business app activity and artefacts (binaries, files tree, network traffic, etc.)
* **Use of GenAI:** quickly have an overview of the business app components, architecture, use cases, then determine whether the alert is confirmed or not, based on the alert details.
* **Field feedback:** quite useful but may be challenging anyhow if the business app is a proprietary one, with almost no open documentation.


## Watch 

* **Context:** there are more and more papers regarding cyberthreats analysis, plus cybersecurity standards, and all of that is time-consuming to read
* **Elements to be analyzed:** reports (PDF), blog posts and KB articles
* **Use of GenAI:** quickly summarize the reports and texts, to get the most important part of them with a global understanding
* **Field feedback:** really efficient and relevant
* **Real life example:** ask ChatGPT, or [Mistral AI](https://mistral.ai/products/vibe/) to summarize the following [CTI report from Sekoia](https://blog.sekoia.io/oysterloader-unmasked-the-multi-stage-evasion-loader/), which is supposed to take **19min** to read. The generated sum-up would only take 4-5 min reading :)



## Cyber-attack understanding

### Security solutions detections 

* **Context:** an alert from EDR, NDR, SEG, SWG, ITDR, CASB, etc.  
* **Elements to be analyzed:** artefacts associated to the alert, as well as the attack type itself as per the detected attack name
* **Use of GenAI:** quickly understand the attack type (TTP) and the ways it works, then determine whether the alert is confirmed or not, based on the information it contains.
* **Field feedback:** can be useful but may lead to wrong assumptions if analysts don't take the time to deep dive and search, to go beyond the first GenAI results.



