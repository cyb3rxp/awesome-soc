# Detection matrix

## Purpose

This kind of document aimes at representing detection (and even reaction) capabilities, for specifif ("feared") events that are considered as critical. 

The list those events is supposed to be generated or identified by security watch and/or risk analysis. See "detection engineering" for details.

## Matrix sample

| Feared event // sensor    | AV/EDR |  SEG  |  SWG  |  IDTP | CASB  |
| ------------------------- | ------ | ----- | ----- | ----- | ----- |
| Business email compromise |        |   X   |       |   X   |   X   |
| Malware spread            |    X   |   X   |   X   |       |   X   |
| Malware cleaning error    |    X   |       |   X   |       |       |
| C&C access from an asset  |    X   |       |   X   |       |   X   |
| Impossible travel         |        |       |   X   |   X   |   X   |
| Phishing on private emails (GMail, Outlook.com, etc.) |   X    |       |   X   |      |      |


## Matrix meaning/understanding

* For each feared event, the idea is to identify all the security sensors that could/should help in detecting it.
* If, for some reasons, the detection of a feared event is not considered as working for a specific sensor, then the cross should not be there in the array, for that sensor and that feared event;
  * The provided matrix is meant to be an example, for "best cases", and "not always true in every IT environment";
  * As a consequence, the detection matrix has to be adapted, and kept up-to-date in time, for every organizations' environments that have a SOC in place.
