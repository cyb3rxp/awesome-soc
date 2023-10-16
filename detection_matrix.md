# Detection matrix

## Purpose

This kind of document aims at representing detection (and even response) capabilities, for specifif ("feared") events that are considered as critical. 

The list those events is supposed to be generated or identified by security watch and/or risk analysis. See "[detection engineering page](https://github.com/cyb3rxp/awesome-soc/blob/main/detection_engineering.md#how-to-feed-the-plan-phase)" for further details.

## Matrix sample

| Feared event // sensor    | AV/EDR |  SEG  |  SWG  |  IDTP | CASB  |
| ------------------------- | ------ | ----- | ----- | ----- | ----- |
| Malware spread            |    X   |   X   |   X   |       |   X   |
| Malware cleaning error    |    X   |       |   X   |       |       |
| T1566: Business email compromise |        |   X   |       |   X   |   X   |
| T1071: C&C access from an asset  |    X   |       |   X   |       |   X   |
| T1078: Impossible travel         |        |       |   X   |   X   |   X   |
| T1566: Phishing on private employees' emails (GMail, Outlook.com, etc.) |   X    |       |   X   |      |      |
| T1059: Command and Scripting Interpreter |   X   |   X   |   X   |       |       |
| T1218: Signed Binary Proxy Execution |   X   |       |       |       |       |
| T1055: Process Injection  |   X   |       |       |       |       |
| T1569: System services    |   X   |       |       |       |       |
| T1053: Scheduled Task/Job |   X   |       |       |       |       |
| T1003: OS Credential Dumping |   X   |       |       |       |       |



## Matrix meaning/understanding

* For each feared event, the idea is to identify all the security sensors that could/should help in detecting it.
* If, for some reasons, the detection of a feared event is not considered as working for a specific sensor, then the cross should not be there in the array, for that sensor and that feared event;
  * The provided matrix is meant to be an example, for "best cases", and "not always true in every IT environment";
  * As a consequence, the detection matrix has to be adapted, and kept up-to-date in time, for every organizations' environments that have a SOC in place.
