# Standard Operating Procedure for Microsoft 365 compromise assessment (including Azure Entra ID checks)
All main steps of the SOP may not be always required, and depending on the context, one may want to go through the end of the SOP anyhow after a detection, or not. 
Version: 0.1 as of 03/13/2024

# 1) Admin check

## List users having privileged roles (Entra ID)
* Check that there are at least 2 users having "global administrator" role for redundancy and recovery purposes
* Check that they are all legitimate (known admins, that do require such high privileges)
* Check that they all have MFA enabled

## Check sessions (Entra ID)
* Check IP addresses from which users having admin roles authenticate (over the last weeks/months)
  * If any suspicious track is found, request password reset for the associated account (and enable MFA if it was not already).

## Synced global admins (Entra ID)
* Check that there are no on-premises synced accounts for Microsoft Entra ID role assignments
  * If yes, check their authentication logs;
     * if possible, disable them or at least, reset their password and enable MFA.


# 2) Generic authentication settings/events checks

## Modern authentication
* Check that modern authentication is enabled;
  * if no, enable it with the following PS command:
    > Set-OrganizationConfig -OAuth2ClientProfileEnabled $true

## Risky sign-ins
* Review all the reported risky sign-ins [MS Entra ID console link](https://portal.azure.com/#view/Microsoft_AAD_IAM/RiskySignInsBlade);
  * if any real suspicion of a compromise, reset user password and enable MFA.



# 3) User checks

## Risk detecions
* Review all the reported risks [MS Entra ID console link](https://portal.azure.com/#view/Microsoft_AAD_IAM/RiskDetectionsBlade)



## Guests
* Check Guest user permissions is being set to: "Guest user access is restricted to properties and memberships of their own directory objects (most restrictive)"
* Check Guest invite restrictions is being set to: "Only users assigned to specific admin roles can invite guest users"
  

## Password compromise
* If there are user accounts that were identified as potentially compromised, search for password compromise for their email addresses on: [HaveIBeenPwned](https://haveibeenpwned.com/Passwords)
  * reset password for any user that was found in the results.


# 4) DNS domains checks
* Check all "custom domains names" in Entra ID:
  * TXT records;
  * MX records.



# 5) Data exfiltration check

## Exchange Online
* Check the "Auto forwarded message report": [MS Exchange Admin Console link](https://admin.exchange.microsoft.com/#/reports/autoforwardedmessages)
* check the Transport rules:
  * export the rules to an XML file: [PowerShell command for MS Exchange Online](https://learn.microsoft.com/en-us/powershell/module/exchange/export-transportrulecollection?view=exchange-ps)
  * check all the transport conditions and recipients
* Check that all shared mailboxes have sign-in disabled
* Check that there is no wildcards in "RemoteDomain" settings, with the following PS command:
> get-remotedomain *
* Check that there is no external providers storage being allowed, with the following PS command:
> Get-OwaMailboxPolicy -Identity <affected policy>



# Caution measures

## Azure Entra ID
* Enable MFA for all VIP/VOP users.

## Exchange Online
* Enable mailbox auditing for potentiel further investigation with the following PS command:
> Set-OrganizationConfig -AuditDisabled $false




Be aware that this analysis step may require hours if not days, and is quite non-predictable in terms of required time!


# END



   
