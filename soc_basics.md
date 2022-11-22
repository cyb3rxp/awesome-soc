# SOC/CSIRT Basic and fundamental concepts

# ToC

* What is a SOC?
* SOC Activities vs. CSIRT activities
* What is a SIEM? What for?
* SOC mission and context
* SOC/CERT processes and workflow
* What is purple/red/blue team?
* Attack lifecycle
* Most common infection vectors


# What is a SOC? 
## SOC definition:
As per MITRE paper (SOC strategies, see [below](https://github.com/cyb3rxp/awesome-soc/blob/main/README.md#for-a-soc)):
![image](https://user-images.githubusercontent.com/16035152/186421761-ff5bab84-5982-43e1-8d0c-fa9406422b2c.png)

## Typical SOC:
Data, tools, and capabilities:
![image](https://user-images.githubusercontent.com/16035152/186420020-8507b3b3-7fb8-46cf-a5f9-9d6506284cb2.png)

# SOC activities vs. CSIRT activities

## SOC activities:

As per [ENISA's whitepaper](https://www.enisa.europa.eu/publications/how-to-set-up-csirt-and-soc/at_download/fullReport), a minimal set of services for SOCs usually includes those in bold below in accordance with the FIRST services framework:

![image](https://user-images.githubusercontent.com/16035152/203085970-7c263f73-dc37-47ac-9e8e-556103ad12b8.png)

## CSIRT activities:

As per [ENISA's whitepaper](https://www.enisa.europa.eu/publications/how-to-set-up-csirt-and-soc/at_download/fullReport), a minimal set of services for CSIRTs usually includes those in bold below in accordance with the FIRST services framework:

![image](https://user-images.githubusercontent.com/16035152/203086113-2b994d1f-9a27-4cad-8ad2-8da4166366a7.png)



# What is a SIEM? What for?
As per [this article (in French)](https://www.sartagas.fr/outils-de-la-ssi/securite-de-l-exploitation/les-outils-siem/):

![image](https://user-images.githubusercontent.com/16035152/187097902-c118a3c9-9288-44f1-9914-65551cc8ee4d.png)


# SOC mission and context

## SOC operating context:
As per MITRE paper (SOC strategies, see [below](https://github.com/cyb3rxp/awesome-soc/blob/main/README.md#for-a-soc)):

![image](https://user-images.githubusercontent.com/16035152/186769340-6c621383-d06a-4d48-8c09-f54cc29aaf3c.png)


# SOC/CERT processes and workflows

## Incident response lifecycle (detection // incident response):
As per NIST SP800-61 rev2 paper (see [below](https://github.com/cyb3rxp/awesome-soc/blob/main/README.md#for-a-soc)):
![image](https://user-images.githubusercontent.com/16035152/186421468-5136db5b-55d4-4841-9a4a-7d03904af81e.png)

As an IT security teacher used to tell his students, like a SOC motto: "Without response, detection is useless" (Freely inspired from Bruce Schneier, [Secrets and Lies: Digital Security in a Networked World](https://www.amazon.fr/Secrets-Lies-Digital-Security-Networked/dp/1119092434) book).

## Typical incident handling workflow:
As per ENISA paper see [below](https://github.com/cyb3rxp/awesome-soc/blob/main/README.md#for-a-cert) 

![image](https://user-images.githubusercontent.com/16035152/186770414-d0d75e68-7c0f-4285-9eb2-a67cabdd5fdd.png)

## SOC/CERT procedures:
* Write and maintain in time alerts/incident handling procedures.
  * My recommendation: take those from CERT-SG, [IRM](https://github.com/certsocietegenerale/IRM), as an example.



# What is purple/red/blue team?
Quoting [Lutessa (in French)](https://www.lutessa.com/?p=5524):

![image](https://user-images.githubusercontent.com/16035152/186768852-464d6e3b-1081-45ff-b0bf-0c21ea54dcaf.png)


# Attack lifecycle

As per [Mandiant article](https://www.mandiant.com/resources/insights/targeted-attack-lifecycle):

![image](https://user-images.githubusercontent.com/16035152/186893725-9da9c798-128b-416e-b93e-42cbf30baced.png)


# Most common infection vectors

Based on experience, and on numerous malware statistics, the following ones should be considered as priority:
* emails;
* web browsing;
* USB sticks / removable storage;
* exposed (internet facing) services/apps and equipments (e.g.: appliances)

# End
Go to [main page](https://github.com/cyb3rxp/awesome-soc/blob/main/README.md).
