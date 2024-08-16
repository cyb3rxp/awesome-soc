#  SOP (Standard Operating Procedure) for compromise assessment on a web server (mostly Linux)

Derivated from the Incident response framework as described in NIST SP800-61 rev3 and NIST CSF.

Version: 0.3, as of 08/16/2024.

NB: All main steps of the SOP may not be always required, and depending on the context, one may want to go through the end of the SOP anyhow after a detection, or not. 


# Prerequisites

- Root access to the server(s) to be investigated.
- OpenCTI (or MISP) with threat intel feeds enabled.
- Script to query OpenCTI with a list of IP addresses/hashes.
- IOC Scanner, like THOR Lite, ready to go.
- XDR/SIEM ready to ingest event logs (Linux), with threat intel feeds being ingested to produce correlation-based detections, and if possible, ready-to-go SIEM rules.


# 1) Detection: Admin check ("who does currently own the server?")

## "root" account remote access check for past events
- Extract all IP addresses listed in SSH server logs, associated to authentications events with "root" local account.
- Extract all IP addresses listed in web server logs, associated to authentications events with "root/admin" local account.
- Extract all IP addresses listed in netstat as destination addresses (outgoing traffic).

- Run the OpenCTI script to search for those IP addresses in the TIP;
  - If detection, mark the corresponding IP address as an IOC, and consider to block it at firewall level ASAP.
- Manually check all the destination IP addresses, against online tools like cybergordon.com;
  - If detection, mark the corresponding IP address as an IOC, and consider to block it at firewall level ASAP.

  
  
## Local users check
- Check who is connected right now on the server with the "w" command;
  - If a suspicious account is found, mark it as an IOC.
- Check that all the users that are Sudoers members are legit;
  - If a suspicious account is found, mark it as an IOC.
- Check that all the users that are root group members are legit;
  - If a suspicious account is found, mark it as an IOC.

- Remove the non-legit/suspicious users that could be found, and kill their potential local session processes.

## Secure admin protocols
- Make sure that only SSH is enabled and allowed to do remote admin tasks on the server(s);
  - Block/disable other remote admin protocols, otherwise, at least temporarily.


## Temporary SOC protection
- Export the SSH logs to your XDR/SIEM solution, like Sekoia XDR for instance.


# 2) Detection: Admin (SSH) security

## Harden SSH
- Install Fail2ban ASAP, to protect against SSH brute-force attacks.
- Reset all root accounts' passwords (if there are others than yours).

## Temporary SOC protection
- Export the fail2ban logs to your XDR/SIEM solution;
  - e.g.: Sekoia XDR.


# 2) Detection: Web external checks

## Specific web page check 
- If there is a specific web page that is considered as suspicious, or even malicious, investigate it and confirm it is malicious or not;
  - If confirmed malicious:
    - mark the page URL + file path + MD5, as IOC.
    - search in the server logs for all IP addresses that have accessed this page, and mark those as IOC (C&C) or artefacts (compromised machines).

## Security reputation
- Search your TIP for the domain name of the investigated server(s);
  - If found, which may mean the server is already known as malicious/compromised, mark the associated URL as IOC.
- Search VirusTotal for history of scans for the investigated server(s), with its domain name and main web pages;
  - If found, with detections, mark the associated URL as IOC.
 
## CMS security check
- If there is a CMS like Wordpress on the investigated servers:
  - Run the security check of the CMS;
  - If needed, install the required extension (e.g.: WPscan, https://wordpress.com/plugins/wpscan, leveraging Jetpack) to scan extensions and vulnerabilities.
  - Run a scan with the security extension; 
- If there is no tool to scan the CMS extensions, review them one by one.
  - If malicious extension found, mark its name and URL as IOC.

## Public scanner
- Run a scan of the website(s) URL(s) with https://urlscan.io/ and https://sitecheck.sucuri.net/;
  - If detections, mark the files/URL as IOC. 
  

# 3) Detection: Generic antimalware/IOC local check

## ClamAV / THOST Lite install
- Install ClamAV
- Install [THOR Lite](https://www.nextron-systems.com/thor-lite/), with its dependencies.

## ClamAV / THOR Lite scan
- Run a ClamAV scan.
- Run a THOR Lite scan.

- If detections, mark the files as IOC.

## Website files advanced scan
- Extract all the files that may contain active content (HTML, PHP, JS, etc.), and run a full antimalware scan on them (searching for exploit codes, webshells, malicious script files, RAT, etc.):
  - My recommendation: Windows Defender, ESET AV.
  - If detections, mark the files/URL as IOC.



# 4) Detection: Website content source checks

## File storage service 
- If the webserver(s) uses() a file storage service (even a SAN) to store files to be served as web content, then run a full antimalware check on this file share;
  - For instance, mount the file storage over SMB and scan it against malware (using MS Defender for example).
  - If possible, also run a THOR Lite scan.

## Internal Git
- If the website uses an internal Git repository (used for instance for versioning, colalborative work, etc.):
  - Run an antimalware check on the Git repository (searching for exploit codes, webshells, malicious script files, RAT, etc.);
    - If detections, mark the files/URL as IOC.
  - Review all accounts have write permissions on the Git repository content;
    - Reset their passwords;
  - Enable MFA for all Git accounts, wherever possible.


# 5) Detection: On-the-fly alerts of XDR/SIEM 

## Existing alerts
- If any alert was generated by the XDR/SIEM after the beginning of log ingestion, handle them.
  - If any malicious IP address, or URL, or account, is being found, mark it as IOC.


# 6) Response

## Contain: 
- Make sure the IP addresses that are associated to IOC are being blocked: 
  - in the WAF configuration;
  - in the system local firewall rules.
- Make sure Fail2Ban is up and running.


## Eradicate: IOC cleaning
- Double check all artefacts marked as IOC, to confirm they are malicious;
- Clean/restore or at least block, depending on the case, the files associated to IOC.



# 7) Response/recover

## Leverage backups
- If there is any doubt on a system component, account, or web server content, restore backup from last known clean one.
- If there is no clean backup available (or not too old), reinstall a fresh new server, and export/import the web server configuration and data, from the investigated one.


# 8) Feedback/PDCA

## Improve detection
- Make sure all confirmed IOC are listed in the TIP that the SOC uses, as well as ingested in security/system tools configurations (whenever possible).
- Disable temporary XDR/SIEM monitoring service.
- Make sure the server logs are being sent to an sustainable XDR/SIEM service, for security monitoring by a SOC.

## Improve protection
- Make sure a WAF (like ModSecurity or CloudFlare) is being deployed ASAP, if not already there, to protect the web server(s).
- Make sure Fail2Ban is up and running, or if possible, install [CrowdSec WAF](https://www.crowdsec.net/solutions/application-security)
- Install potentially missing security updates, including CMS extensions/components updates.
- Install an EDR, or at least [SysmonForLinux](https://github.com/Sysinternals/SysmonForLinux), on the server.
- Enable strong authentication wherever possible.

