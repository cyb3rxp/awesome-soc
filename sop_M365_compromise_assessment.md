# Standard Operating Procedure for Microsoft 365 compromise assessment (including Azure Entra ID checks)

All main steps of the SOP may not be always required, and depending on the context, one may want to go through the end of the SOP anyhow after a detection, or not. 

Version: 0.2 as of 03/14/2024

# 1) Admin check

## List users having privileged roles (Entra ID)
* Run a scan with [365Inspect](https://github.com/soteria-security/365Inspect):
  * Check Users found in Azure AD Roles:
    * Check that there are at least 2 users having "global administrator" role for redundancy and recovery purposes;
    * Check that they are all legitimate (known admins, that do require such high privileges);
    * Check that they all have MFA enabled.

## Check sessions (Entra ID)
* Check IP addresses from which users having admin roles authenticate (over the last weeks/months):
  * If any suspicious track is found, request password reset for the associated account (and enable MFA if it was not already).

## Sync'ed global admins (Entra ID)
* Check that there are no on-premises synced accounts for Microsoft Entra ID role assignments:
  * If yes, check their authentication logs;
     * if possible, disable them or at least, reset their password and enable MFA.


# 2) Generic authentication and configuration checks

## Modern authentication
* Check that modern authentication is enabled;
  * if no, enable it with the following PS command:
    > Set-OrganizationConfig -OAuth2ClientProfileEnabled $true

## Run a scan with relevant tools:
   * [Semperis Purple Knight](https://www.purple-knight.com/active-directory-security-tool/);
       * review in priority any item reported as "IOC" in the report.
   * [365Inspect](https://github.com/soteria-security/365Inspect)
   * [Sparrow](https://github.com/cisagov/Sparrow)


# 3) User/mailbox checks

## Risk detections
* Review all the reported risks in Entra ID [MS Entra ID console link](https://portal.azure.com/#view/Microsoft_AAD_IAM/RiskDetectionsBlade)

## Risky sign-ins
* Review all the reported risky sign-ins [MS Entra ID console link](https://portal.azure.com/#view/Microsoft_AAD_IAM/RiskySignInsBlade);
  * if any real suspicion of a compromise, reset user password and enable MFA.

## Guests
* Check Guest user permissions is being set to: "Guest user access is restricted to properties and memberships of their own directory objects (most restrictive)";
* Check Guest invite restrictions is being set to: "Only users assigned to specific admin roles can invite guest users".
  
## Password compromise
* If there are user accounts that were identified as potentially compromised, search for password compromise for their email addresses on: [HaveIBeenPwned](https://haveibeenpwned.com/Passwords)
  * reset password for any user that was found in the results.

## Mailboxes
* Run a scan with [365Inspect](https://github.com/soteria-security/365Inspect):
  * Check the delegations settings for all mailboxes associated to the identified suspicious (or potentially compromised) accounts; 
  * Check the Exchange mailboxes that are hidden from Global Address Lists;
  * Check Exchange mailboxes with internal forwarding rules enabled;
  * Check Exchange mailboxes with SendAs delegates;
  * Check Exchange mailboxes with SendOnBehalfOf delegates 



# 4) Applications checks

## Security settings
* Run a scan with [365Inspect](https://github.com/soteria-security/365Inspect):
   * Review all applications-related detections, for instance:
      * Applications Registered to Tenant with Certificate Credentials
      * Applications Registered to Tenant with Client Secret (Password) Credentials
      * Admin Consent Workflow is enabled for third party applications
   * Review all services-related detections, for instance:
      * Service Principals Found on Tenant with Certificate Credentials
      * Service Principals Found on Tenant with Client Secret (Password) Credentials

## Global checks workflow
* Follow the Microsoft recommended workflow for Azure applications compromise: https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-compromised-malicious-app
   

# 5) Data exfiltration check

## Exchange Online
* Check the "Auto forwarded message report": [MS Exchange Admin Console link](https://admin.exchange.microsoft.com/#/reports/autoforwardedmessages);
   * handle any account that is reported here.
* Check the Transport rules:
  * export the rules to an XML file: [PowerShell command for MS Exchange Online](https://learn.microsoft.com/en-us/powershell/module/exchange/export-transportrulecollection?view=exchange-ps)
  * check all the transport conditions and recipients
* Check that all shared mailboxes have sign-in disabled
* Check that there is no wildcards in "RemoteDomain" settings, with the following PS command:
> get-remotedomain *
* Check that there is no external providers storage being allowed, with the following PS command:
> Get-OwaMailboxPolicy -Identity <affected policy>
* Run a scan with [365Inspect](https://github.com/soteria-security/365Inspect):
  * Check that Outgoing Sharing Invitations are monitored
  * Check Third Party File Sharing Enabled in Microsoft Teams policy
  * Check Microsoft Teams Policies Allow Anonymous Members policy


## DNS domains checks
* Check all "custom domains names" in Entra ID:
  * TXT records;
  * MX records.



# 6) Antispam checks

* Check in the antispam policy the emails and domains that are set as Blocked or Allow Senders: are they valid and legitimate?
* Check in the anti-spoofing policy the entities allowed to Perform domain spoofing


# Protective (recommended!) measures during investigation (incident response time)

## Azure Entra ID
* Enable MFA for all VIP/VOP users.
* implement banned password list in [MS Entra ID console](https://portal.azure.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/PasswordProtection)
   * you may find a top 1000 worst passwords on Google or [here](https://gitlab.com/kalilinux/packages/seclists/-/tree/kali/master/Passwords/Common-Credentials) :)
* Enable protective Conditional access policies in [Entra ID console](https://portal.azure.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Overview):
  * require a password change for high risk users, see [MS documentation](https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-risk-user)
  * require MFA when sign-in risk has been identified, see [MS documentation](https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-risk)
  * risky sign-in location:
    * if the investigated organisation is located within a designated country, and its employees are not supposed to travel the world: implement a conditional access that will deny sign-ins from countries different from one where the organisation is located (you may need to define your trusted locations in ["named locations"](https://portal.azure.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/NamedLocations), and use it then in your policy).
    * else, implement a conditional access that will force MFA for sign-ins that occur outside the main country where the organisation is located.
  * enforce MFA for all admin access (you may want to use the template "Require multifactor authentication for admins");
  * enforce MFA for Azure management (you may want to use the template "Require multifactor authentication for Azure management");
  * block persistent browser sessions (you may want to use the template "No persistent browser session"), with a max number of days set to 7 (or 30 if you can't do better).
   
* Password protection:
  * check "Lockout threshold" is being set to a value (something like 50)
  * check "Lockout duration in seconds" is being set to a value (something like 60)
  * check "Enforce custom list" is being set to "Yes".

## Exchange Online
* Block antispam bypass with the following PS commandline for all mailboxes
  > set-Mailbox -AntispamBypassEnabled $false
* Enable quarantine for high-confidence phishings;
  *  Check that "High confidence phishing" is being set to "Quarantine Message".
* Enable anti-phishing first contact tip;
  * in the anti-phishing policy, "Edit actions", check that "Show first contact safety tip (Recommended)" is enabled.
* Enable mailbox auditing for potentiel further investigation with the following PS command:
> Set-OrganizationConfig -AuditDisabled $false
* Block auditing bypass for admin/VIP/VOP users' mailboxes, with the following PS command:
> Set-MailboxAuditBypassAssociation -Identity "<Identity>" -AuditBypassEnabled $false
* Implement an Outbound Spam Filtering Policy, such as (you may need to adapt it to your investigation context):
  * External Recipients Per Hour: 1000
  * Internal Recipients Per Hour: 2500
  * Total Recipients Per Day: 5000
  * Restrictions Placed On Users: Restrict until the following day
  * Automatic forwarding rules: Automatic



Be aware that this analysis step may require hours if not days, and is quite non-predictable in terms of required time!


# END



   
