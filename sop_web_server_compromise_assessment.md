#  SOP (Standard Operating Procedure) for compromise assessment use case on a web server (mostly Linux)

Derivated from the Incident response framework as described in NIST SP800-61 rev3 and NIST CSF.

Version: 0.1, as of 08/12/2024.

NB: All main steps of the SOP may not be always required, and depending on the context, one may want to go through the end of the SOP anyhow after a detection, or not. 


# Prerequisites

- Root access to the server(s) to be investigated.
- script to query OpenCTI with a list of IP addresses/hashes.
- XDR/SIEM ready to ingest event logs (Linux), with threat intel feeds being ingested to produce correlation-based detections, and if possible, ready-to-go SIEM rules.


# 1) Admin check ("who does currently own the server?")

## "root" account remote access check for past events
- Extract all IP addresses listed in SSH server logs, associated to authentications events with "root" local account.
- Extract all IP addresses listed in web server logs, associated to authentications events with "root/admin" local account.
- Extract all IP addresses listed in netstat as destination addresses (outgoing traffic).

- Run the OpenCTI script to search for those IP addresses in the TIP;
  - if detection, mark the corresponding IP address as an IOC, and consider to block it at firewall level ASAP.
- Manually check all the destination IP addresses, against online tools like cybergordon.com;
  - if detection, mark the corresponding IP address as an IOC, and consider to block it at firewall level ASAP.

  
  
## Local users check
- Check who is connected right now on the server with the "w" command;
  - if a suspicious account is found, mark it as an IOC.
- Check that all the users that are Sudoers members are legit;
  - if a suspicious account is found, mark it as an IOC.
- Check that all the users that are root group members are legit;
  - if a suspicious account is found, mark it as an IOC.

- Remove the non-legit/suspicious users that could be found, and kill their potential local session processes.

## Secure admin protocols
- Make sure that only SSH is enabled and allowed to do remote admin tasks on the server(s);
  - Block/disable other protocols, otherwise, at least temporarily.


## Temporary SOC protection
- Export the SSH logs to your XDR/SIEM solution, like Sekoia XDR for instance.


# 2) Detection: Admin (SSH) security

## Harden SSH
- Install Fail2ban ASAP, to protect against SSH brute-force attacks.
- Reset all root accounts' passwords (if there are others that yours).

## Temporary SOC protection
- Export the fail2ban logs to your XDR/SIEM solution, like Sekoia XDR for instance.


# 2) Detection: Web external checks

## Specific web page check 
- If there is a specific web page that is considered as suspicious, or even malicious, investigate it and confirm it is malicious or not;
  - If confirmed malicious:
    - mark the page URL + file path + MD5, as IOC.
    - search in the server logs for all IP addresses that have accessed this page, and mark those as IOC (C&C) or artefacts (compromised machines).

## Security reputation
- Search your TIP for the domain name of the investigated server(s);
  - if found, which may mean the server is already known as malicious/compromised, mark the associated URL as IOC.
- Search VirusTotal for history of scans for the invedstigated server(s), with its domain name and main web pages;
  - if found, with detections, mark the associated URL as IOC.
 
## CMS security check
- If there is a CMS like Wordpress on the investigated servers:
  - Install the required extension (e.g.: WPscan, https://wordpress.com/plugins/wpscan, leveraging Jetpack) to scan extensions and vulnerabilities.
  - Run a scan; 
     - if malicious extension found, mark its name and URL as IOC.
- If there is no tool to scan the CMS extensions, review them one by one.
  - if malicious extension found, mark its name and URL as IOC.

## Public scanner
- Run a scan of the website(s) URL(s) with https://urlscan.io/ and https://sitecheck.sucuri.net/;
  - If detections, mark the files/URL as IOC. 
  

# 3) Detection: Generic antimalware/IOC local check

## ClamAV/Loki install
- Install ClamAV
- Install Loki, with its dependencies: https://github.com/Neo23x0/Loki?tab=readme-ov-file


## ClamAV/Loki scan
- Run a clamAV scan.
- Run a Loki scan.

- If detections, mark the files as IOC.

## Website files advanced scan
- Extract all the files that may contain active content (HTML, PHP, JS, etc.), and run a full antimalware scan on them (e.g.: with Windows Defender, ESET AV, WithSecure AV, etc.).
  - If detections, mark the files/URL as IOC. 
  
  
# 4) Response

## Contain: 
- Make sure the IP addresses that are associated to IOC are being blocked: 
  - in the WAF;
  - in the system local firewall.
- Make sure Fail2Ban is up and running.


## Eradicate: IOC cleaning
- Clean or restore, depending on the case, the files associated to IOC.



# 5) Response/recover

## Leverage backups
- If there is any doubt on a system component, account, or web server content, restore backup from last known clean one.



# 6) Feedback/PDCA

## Improve detection
- Make sure all confirmed IOC are listed in the TIP that the SOC uses, as well as ingested in security/system tools configurations (whenever possible).
- Make sure the server logs are being sent to and XDR/SIEM for security monitoring by a SOC.

## Improve protection
- Make sure a WAF (like MoedSecurity or CloudFlare) is being deployed ASAP, if not already there, to protect the web server(s).
- Make sure Fail2Ban is up and running.
- Install potentially missing security updates, including CMS extensions/components updates.
- Enable strong authentication wherever possible.

