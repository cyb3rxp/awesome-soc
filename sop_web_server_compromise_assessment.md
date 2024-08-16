#  Standard Operating Procedure for compromise assessment on a web server (mostly Linux)

Derivated from the Incident response framework as described in NIST SP800-61 rev3,  NIST CSF, and this [paper](https://media.defense.gov/2020/Jun/09/2002313081/-1/-1/0/CSI-DETECT-AND-PREVENT-WEB-SHELL-MALWARE-20200422.PDF).

Version: 0.3, as of 08/16/2024.

NB: All main steps of the SOP may not be always required, and depending on the context, one may want to go through the end of the SOP anyhow after a detection, or not. 


# Prerequisites

- Root access to the server(s) to be investigated.
- OpenCTI (or MISP) with threat intel feeds enabled.
- Script to query OpenCTI with a list of IP addresses/hashes.
- IOC Scanner, like [THOR Lite](https://www.nextron-systems.com/thor-lite/), ready to go.
- OSINTracker or Timesketch, to document and work on discovered IOC.
- XDR/SIEM ready to ingest event logs (Linux), with threat intel feeds being ingested to produce correlation-based detections, and if possible, ready-to-go SIEM rules.


# 0) Prepair: Cautiousness

## Srver backup for investigation
- [If possible] Run a backup of the server(s) to be investigated, before touching them. 
  - Then work as much as possible on the copy of the server(s)

## Copy the minimum required file
- At least, copy the following folders to a safe and remote place: 
  - /var/log/
  - /etc/


# 1) Detection: Admin and remote access check ("who does currently own the server?")

## "root" account remote access check for past events
- Extract all IP addresses listed in SSH server logs, associated to authentications events with "root" local account.
- Extract all IP addresses listed in web server logs, associated to authentications events with "root/admin" local account.

- Run the OpenCTI script to search for those IP addresses in the TIP;
  - If detection, mark the corresponding IP address as an IOC, and consider to block it at firewall level ASAP.

## Outgoing traffic
- Extract all IP addresses listed in netstat as destination addresses (outgoing traffic).
- [If possible] extract all IP addresses that could be found in files located in /var/log/*

- Run the OpenCTI script to search for those IP addresses in the TIP;
  - If detection, mark the corresponding IP address as an IOC, and consider to block it at firewall level ASAP.
- Manually check all the destination IP addresses, against online tools like [CyberGordon](cybergordon.com);
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
 
## Persistence 
- Check all services set to be started at boot-up time;
  - If a suspicious item is found, mark it as an IOC (path, hash).
- Check all scheduled tasks.
  - If a suspicious item is found, mark it as an IOC (path, hash).


## Temporary SOC protection
- Export the SSH logs to your XDR/SIEM solution, like Sekoia XDR for instance.


# 2) Detection: Admin security

## Harden SSH
- Install Fail2ban ASAP, to detect and protect against SSH brute-force attacks.
- Reset all root accounts' passwords (if there are others than yours).

## Check CMS / Web admin panel
- Check that default admin passwords have been changed for CMS [if present];
- Check that default admin passwords have been changed for web admin panel [if present]

## Temporary SOC protection
- Export the fail2ban and SSH logs to your XDR/SIEM solution;
  - e.g.: Sekoia XDR.


# 3) Detection: Web external checks

## Specific web page check 
- If there is a specific web page that is considered as suspicious, or even malicious, investigate it and confirm it is malicious or not;
  - If confirmed malicious:
    - mark the page URL + file path + MD5, as IOC.
    - search in the server logs for all IP addresses that have accessed this page, and mark those as IOC (attacker's access) or artefacts (internal/legit compromised machines).

## Security reputation
- Search your TIP for the domain name of the investigated server(s);
  - If found, which may mean the server(s) is(are) already known as malicious/compromised, mark the associated URL as IOC.
- Search VirusTotal for history of scans for the investigated server(s), with its domain name and main web pages;
  - If found, with detections, mark the associated URL as IOC.
 
## CMS security check
- If there is a CMS like Wordpress on the investigated servers:
  - Run the security check of the CMS;
  - If needed, install the required extension (e.g.: WPscan, https://wordpress.com/plugins/wpscan, leveraging Jetpack) to scan extensions and vulnerabilities.
  - Run a scan with the security extension; 
- If there is no tool to scan the CMS extensions, review them one by one;
  - If malicious extension found, mark its name and URL as IOC.

## Public scanner
- Run a scan of the website(s) URL(s) with [URLScan](https://urlscan.io/) and [Sucuri](https://sitecheck.sucuri.net/);
  - If detections, mark the files/URL as IOC. 
  

# 4) Detection: Generic antimalware/IOC local check

## ClamAV / THOST Lite install
- Install ClamAV
- Install THOR Lite, with its dependencies.

## ClamAV / THOR Lite scan
- Run a ClamAV scan.
- Run a THOR Lite scan.

- If detections, mark the files as IOC.

## Website files advanced scan
- Filter all the files that may contain active content (HTML, PHP, JS, etc.), and run a full antimalware scan on them (searching for exploit codes, webshells, malicious script files, RAT, etc.):
  - My recommendation: Windows Defender, ESET AV.
  - If detections, mark the files/URL as IOC.

## Manual search
- On the web server(s) disk, look for files that were recently modified (a few hours/days ago, for instance).
  - If any malicious file is being found: mark it as IOC.
- [If possible] compare the investigated server(s) with last known clean backups, and double check the changes.


# 5) Detection: Website content source checks

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


# 6) Detection: XDR/SIEM alerts and logs investigation

## Existing alerts
- If any alert was generated by the XDR/SIEM after the beginning of log ingestion, handle them.
  - If any malicious IP address, or URL, or account, is being found, mark it as IOC.
 
## Manual investigation
- In the web server(s) logs, look for the following patterns:
  - HTTP code equals 200, HTTP request type POST, and string ".php" at the end of the query (Note the User-agent, URL, artefact being requested, etc.).
  - HTTP code equals 200, HTTP request type POST, and string "panel" in the query (Note the User-agent, URL, artefact being requested, etc.).
  - HTTP code equals 200, HTTP request type POST, and one of the following strings in the query (Note the User-agent, URL, page being requested on disk, etc.):
    - "shell";
    - "panel";
    - "admin". 
  - HTTP code equals 200, HTTP request type GET, and one of the following strings in the query (Note the User-agent, URL, page being requested on disk, etc.):
    - "whoami";
    - "uname";
    - "ifconfig";
    - "netstat";
    - "etc/passwd";
    - "install".
  - HTTP code equals 200, HTTP request type GET, and the following strings in the query (Note the User-agent, URL, page being requested on disk, etc.):
    - single quote + "or";
    - "UNION";
    - "SELECT".
  - HTTP code equals 40X, HTTP request type GET or POST, and string "shell" in the query (Note the User-agent, URL, artefact being requested, etc.).
  - IP addresses trigerring the most HTTP code 50X: double check the requests (Note the User-agent, URL, artefact being requested, etc.).
  - IP addresses trigerring the most HTTP codes 404, 403, or 400: double check the requests (Note the User-agent, URL, artefact being requested, etc.).
  - IP addresses that poll a particular server URL with a constant frequency (Note the IP, User-agent, URL, artefact being requested, etc.).
  - Rare User-Agent.
  - Longest URL.
- If any malicious IP address, or user-agent, or file, is being found: mark it as IOC.

- In the AuditD logs, look for the following patterns:
  - Apache/Nginx process' children, such as one the followings:
    - "cat";
    - "ifconfig";
    - "ls";
    - "crontab";
    - "netstat";
    - "iptables";
    - "whoami"   


# 7) Response: contain/eradicate

## Contain: 
- Make sure the IP addresses that are associated to IOC are being blocked: 
  - in the WAF configuration;
  - in the system local firewall rules.
- Make sure Fail2Ban is up and running.


## Eradicate: IOC cleaning
- Double check all artefacts marked as IOC, to confirm they are malicious.
- Clean/restore or at least block, depending on the case, the files associated to IOC.



# 8) Response/recover

## Leverage backups
- If there is any doubt on a system component, account, or web server(s) content, restore backup from last known clean one.
- If there is no clean backup available (or not too old), reinstall a fresh new server(s), and export/import the web server(s) configuration and data, from the investigated one(s).


# 9) Feedback/PDCA

## Final check
- Run again the online checks on the "Public scanner" part of the SOP, to make sure there no malicious leftover artefact:
  - If any malicious IP address, or URL, is being found: mark it as IOC;
    - Extend the temporarily SOC for a few weeks.
	  - Clean the malicious artefact(s).


## Improve detection
- Make sure all confirmed IOC are listed in the TIP that the SOC uses, as well as ingested in security/system tools configurations (whenever possible).
- Disable temporary XDR/SIEM monitoring service.
- Make sure the server(s) logs are being sent to an sustainable XDR/SIEM service, for security monitoring by a SOC.


## Improve protection
- Make sure a WAF is being deployed ASAP, if not already there, to protect the web server(s);
  - My recommendations: [CrowdSec WAF](https://www.crowdsec.net/solutions/application-security) or [CloudFlare](https://www.cloudflare.com/) with OWASP Core Ruleset and CloudFlare Managed Ruleset.
- Make sure automated ban of non-web malicious traffic is implemented;
  - My recommendations: Fail2Ban, or if possible, [CrowdSec Firewall bouncer](https://docs.crowdsec.net/u/bouncers/firewall/).
- Install potentially missing security updates, including CMS extensions/components updates.
- Install an EDR, or at least [SysmonForLinux](https://github.com/Sysinternals/SysmonForLinux), on the server(s).
- Enable strong authentication wherever possible.
- Harden admin workstations.
- Update server(s) backups.

