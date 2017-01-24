__Server Hardening__
====================

> John Hammond | November 23rd, 2016

-----------------------------------------------

This is my attempt at commpiling notes and bits of insight that I may have received from the [SANS] 505 Windows and Powershell course. This comes from the Day 2 section on "Server Hardening".

__The Beginning__
--------------------

To start tracking our security and hardening, we start at the [OS] layer.

We _have_ to begin with a recent, patched, and minimal operating system.

* Recent
    - The most current version of the [operating system] we need.
    - __Can we use [Windows Server 2016]?__ 
* Patched
    - Fully up-to-date with all patches and fixed.
    - __Let's use Nessus to do at least some vulnerability scanning.__
* Minimal
    - If you don't need it, get rid of it!

We start the [OS] layer and work our way up through the roles, features, and applications installed.

__Minimal__
------------

You can strip away a whole lot for the [OS] layer. Do you even need a [GUI]? 

No. Get rid of it.

* [Server Core][Server Core] ([Windows Server 2008] and later)
    - Very little local [GUI] support, mostly [Powershell].
    - Smaller hard drive footprint ( 1-3GB )
    - Nice for Windows appliances with flash drives
    - Promote and demote without OS reinstall (2012)
* [Server Nano][Server Nano] ( [Windows Server 2016] and later )
    - Only about 410MB footprint, no [GUI] whatsoever.
    - The primary way to manage [Server Nano] is by [Powershell Remoting]
    - [Server Nano] DOES NOT support [Group Policy]

So what do we do for security? Well... use [Server Nano] if you can. But without [Group Policy], you might struggle with it. So if you need [Group Policy], use [Server Core]. 

__Remove Unnecessary Roles and Features__
----------

* What are roles and features?
    - It's [Microsoft] untangling decades of [spaghetti code] by organizing the [OS] into dependency layers and managable units.

* __With [Server Manager]:__
    - (Un)install roles or features 
    - [Server Manager] runs with [Powershell] in the background.
    - Manage roles on local and remote servers:
        + Including [Server 2008].
    - Works offline with [HyperV]

Go through the Roles and Features on [Server Manager], and uncheck everything you feel like you don't need. The less code you have running, the less venues for attack and exploitation you have. You should always be reducing vulnerabilities.

__Server Manager Scripting with PowerShell__
-----------

* __Your script as a server template__
    - Install or uninstall roles and features
    - Automate changes across many servers
    - Export [XML] list to install from [Server Manager]
    - Apply to local or remote machines.
    - Apply to offline [Hyper-V] drive image files.
    - Copy installation [DVD]/[ISO] to a shared folder.
* __Remotely inventory all of your servers__:
    - Save as a [CSV], [XML], or [HTML] report.

__Disable Unnecessary Windows Services__
----------------

* [Server Manager]
    - Remove uncessary roles and features first, then disable.
*__What's necessary?__ 
    - There is no official list...
    - Use common sense, lab testing, and get SME guidance.
* __Configure Services With__:
    - [INF Security Template]
    - [Group Policy] & LGPO.exe
    - [`sc.exe`][sc.exe] and [Powershell]

Even with [Powershell], the best tool to manage [Security Templates] is [`sc.exe`][sc.exe]

Check out the __Services__. We are especially interested in the services whose startup is set to Automatic. If there are things you don't want, add them to a [Security Template] and mark them as disabled.

__Service Recovery Options__
-------------

Under __Services__ you can edit what happens after a service fails, in the __Recovery__ tab. The best way to manage this across many machines is [`sc.exe`][sc.exe]. 

__Service Account Identities__
------------

* __Principle of Least Privilege for Service Identities__
    - List of accounts in the manual from best to worst.
    - Service accounts have passwords in the registry.
    - Passwords must be reset periodically.
    - Insecure permissions on the service EXE or DLL.
    - Service accounts with explicit privileges
    - Services with write-restricted SATs (Security Access Tokens).
* __Service Special Identities__
    - (Group) Managed Service Accounts (service accounts that will automatically update its own password)
    - Virtual Service Accounts

Never let a service run as a real user account that has a password. Since the passwords are stored in the [Registry], it can be easily found by an attacker.

If you have any service that has the __DEBUG__ privilege -- that is very bad. You should get rid of that service.

__Install, Update or Remove Other Applications__
--------------

* Uninstall any other unnecessary software.
    - Resource Kits, SDKs, etc.
* Built-in [OS] tools
    - Default permissions are good.
    - Audit change and execution.
* Admin Toolkit
    - [DVD] or read-only USB drive.
    - Read-only shared folder.

In the manual is a list of the two dozen most dangerous binaries that you will find on your harddrive. Don't delete these... but make sure the NTFS permissions are good, and you have audting set up. The default permissions are good... but there is no auditing set up! Make sure there is some auditing set up in your [Security Templates].

__Desired State Configuration__
=================

__Powershell Desired State Configuration__
----------

* DSC is for continuous configuration enforcement:
    - Not just for security, but for configuration in general.
    - Better for complex, inter-dependent configurations than [GPO]s.
    - Better for mobile and non-Windows devices than [GPO]s.
    - Better for constantly changing "DevOps" environments.
    - Similar to [Puppet] and [Chef] on [Linux]

* To "enact" a configuration
    - Confirm that the current state matches a desired state.
    - Make whatever changes are necessary to get to desired state.

__DSC Requirements__
---------

* __Windows Management Framework (WMF)__
    - WMF = [Powershell] + [WMI] + [WinRM] for remoting
    - WMF 5.0 or later is highly recommended for DSC.
    - Strictly speaking, [DSC] only requires at least WMF 4.0
* [DSC] target node does _not_ require:
    - Being a member of an [Active Directory] domain
    - Being inside the [LAN], if you have "pull server".

__Run a Configuration to "Compile" it to a MOF__
-----------------

* __What is a [MOF] file?__
    - A text file, not a binary, with no [PowerShell] code.
    - Its format is defined by [DMTF] to be __vender-neutral__.
    - [MOF] defines what the end desired state should be.
    - [MOF] files do not contain any enactment code.
* __[PowerShell] is not required for [DSC]!__
    - Produce your [MOF] files with any tools you wish.
    - Conversely, you can use [PowerShell] to manage non-Windows devives that support [MOF] file configuration too, such as [Linux].

__Resource Modules do the Real Enactment Work__
-----------

* Resource Modules:
    - [MOF] defines _what_ to enact, now _how_ to do it.
    - A resource module is a script or binary that enacts what a [MOF] file wants.
    - Resource modules hide all the code complexities from us, just like an object or class contains hidden code.

__Local Configuration Manager__
-------

The LCM is the overall [DSC] manager.

```
Get-DSCLocalConfigurationManager
```


* ConfigurationMode
    - ApplyOnly
    - ApplyAndMonitor (default)
    - ApplyAndAutoCorrect
* ConfigurationModeFrequencyMins: 15 - 44640
* RebootNodeIfNeeded: True or False
* RefreshMode: Push, Pull, or Disabled

__Controlling Administrative Privileges__
===============

You will want to set up smart cards for the network and domain administrators.

__Forms of Power in Windows__
----------

* Permissions
    - For NTFS, [Active Directory], shared folders, SQL server, everywhere
* User Rights
    - Determines where and how a user can log on, locally and remotely
* Privileges
    - A capability listed in your security Access Token
* Integrity Levels
    - In a user's SAT and attached to every securable object, such as files.

The best tool for managing user privileges is `icacls.exe`

__Permissions for Almost Everything in Windows__
------

For NTFS, [Active Directory], shared folders, SQL server, and more. Almost everything has an ACL.

To manage NTFS and ReFS file permissions:

* INF templates with SECEDIT and Group Policy
* `icacls.exe`
* [Desired State Configuration] resources
* `Get-Acl` and `Set-Acl` (but they are not very useful)
* Third-Party [Powershell] modules

__Manage User Rights Through Group Policy__
------------

In a Group Policy object, the path is: `Computer Configuration->Policies->Windows Settings->Security Settings->Local Policiies->User Rights Assignments`

* Allow/Deny Log On Locally
    - Restrict who can log on interactively at a terminal, i.e, whiole sitting at a computer's keyboard
* Allow/Deny Access To Computer From the Network
    - Restrict who can remotely authenticate
    - Useful when service accounts are compromised.
* Allow/Deny Log on Remote Desktop Services
    - Restrict who can use Remote Desktop Protocol

This is the most important defenses against Pass the Hash attacks an admin login attacks.

__Other Logon Restrictions__
---------

* RADIUS policy rules:
    - Who should be allowed VPN, Ethernet or 802.11 access?
    - WIll certificate-based authentication be required?
* IPSec port permissions:
    - Group-based share permissions on TCP/UDP ports.
    - IPSec enforces network logon righ restrictions too.
* Workstation restrictions:
    - You can use a single wildcard in a hostname
* Logon hours restrictions:
    - Difficult to use for IT accounts, but OK for others.

__Manage Privileges through Group Policy__
------------

A good way to look at privilegess is with `Process Hacker`. it is like a super-enhanced Task Manager, and is even better than Process Explorer with Sysinternals.

One of the tabs if you double-click on a process is "Token". Every program has a Security Access token. It is like an identifier; it identifies your username, privileges, domain name, SID, etc.. At the bottom, it should all of the _privileges_. The status DOES NOT MATTER. It does literally nothing. You are only interested in the "Description" sections.

Unlike permissions, privileges are not related to particular objects; they are special powers you have on the entire system.

* Security Access Token:
    - Your SAT is attached to every process you launch.
    - SAT includes a list of your privileges
    - View with Process Hacker, on the Token Tab
    - View by running in [Powershell]: `whoami.exe /priv`

The manual goes much more in depth for this. 

__The Maleficent Seven__
-------------

If any of these seven privileges are on a process, they can control the whole machine. You're pwned.

1. Impersonate a Client
2. Debug Programs
3. Act as Part of the Operating System
4. Create a Token Object
5. Load and Unload Device Drivers
6. Restore Files and Directories
7. Take Ownership


__Impersonate a Client Privilege__
------------

* Primary Security Access Token (SAT)
    - The true, original underlying identity of a process.
    - `whoami.exe /all /fo list`
* Impersonation Tokens:
    - Used by network services to impersonate clients
    - Regular impersonation SAT (local resources only, on this box only)
    - Delegate impersonation SAT (local AND remote)
* Token Stealing:
    - Hijack delegation SATS for network authentications.
    - You can do this with `incognito.exe`

This is a privilege escalation attack. 

You can change this in [Group Policy], the same `User Rights Agreements`. There is a privilege called `Impersonate a client after authentication`, which is ON BY DEFAULT for Administrators. __You should change this__.

You want to get users _out of the Administrators group_ on their own machines.

__Debug Programs Privilege__
------------

This is the most dangerous privilege there is. This gives you raw read/write access to the memory of every process on the box. 

* Malware can use this to take over the box:
    - With "DLL Injection" a new thread is injected into any process, giving it control over and it and data, including `lsass.exe`
    - Plaintext passwords, hashes, encryption keys and other sensitive data can simply be read out of kernel space memory, and this doesn't even require DLL injection.

This is taken advantage of by an attacking tool called `inception`. Seriously, Google `inception hacking tool`. 


__Take Ownership of Files and Objects__
--------------

* The "owner" of an object can change its permissions, unless permissions have been assigned to the Owner Rights group.
* Objects include files, folders, printers, registry keys, and even processes and threads.
* Only Administrators have this by default, but you can take it away with Group Policy.


__Backup/Restore Files Privilege__
---------------------

Think of this as the "ignore NTFS permissions" privilege.

* Your backup agent service account will need these privileges, but very rarely will regular users need these on their own workstations.
* `robocopy.exe /B` will do this. 


__Local Administrators Group__
--------------------

One of the most important goals for securing a Windows environment is to ___get users out of the administrators group!___

* Objections?
    - Users can't install software.
    - Users can't reconfigure everything.
    - Application X for feature Y breaks if we remove them:
        + But why? Can it be fixed via Group Policy or with a shim?
        + Check out the __LUA Buglight__ tools and the __Windows Application Compatibility Toolkit__ to help identify why it's breaking.

You can have Process Monitor log and filter all of the interactions that processes have with some files and folders. 


__Mandatory Integrity Control Levels__
------------------------

We can have some files with specific Integrity labels like HIGH, (no write, no read, no execute). Any process acting with a LOWER integrity label is not able to access that file! __We should do this for the CDX tokens!__

* MIC Labels in SACLs and SATs:
    - Levels: Protected, System, High, Medium, Low, Untrusted
    - CMD Tools: `whoami.exe`, `icacls.exe`, `chml.exe`, `regil.exe`
    - GUI Tools: Process Hacker, Process Explorer
* MIC can block lower-labeled processes from reading, executing, or writing/deleting higher labeled-objects:
    - Only blocks write and delete by default.
    - This is independent of any NTFS permissions.
* To edit an MIC label you must have:
    - Change Permission, Take Ownership, SeRelabelPrivilege

`chml.exe` is the best tool available for viewing and managing the labels.

The default label is __Medium__. 


__Mitigating Token Abuse & Pass the Hash Attacks__
-----------------

Use only Windows 10 or later for admins:

* Many low-level enchancements
    - Control Flow Guard, ASLR, DEP, Heap Protections, etc.
    - Fewer credentials are cached in memory
* Credential Guard
    - Protects credentials in memory from kernel-mode malware!
    - Requires Enterprise or Education edition
    - Requires very specific hardware and firmware (in manual)
    - Requires UEFI Secure Boot
    - TPM and BitLocker not required, but not recommended

__LSASS Memory Protection__
--------------------------------

* Requires Windows 8.1 or later.
* Set RunAsPPL registry value (in manual)
    - This makes it so only digitally signed modules can be loaded into the LSASS process, which helps to defend against DLL injection attacks.
* Use UEFI Secure Boot and enforce LSASS memory protection from the firmware, not just with registry settings.

__Restrict Network Logon Rights__
---------------

* On high-value target systems, only permit network logons for those users who actually need it.
* Token abuse and pass-the-hash attacks cannot magically overcome network logon rights restrictions.
* Large-scale management through OU Design, [Group Policy], and GPO permissions for groups.

__Avoid Unnecessary Interactive Logons__
----------------------

* Is the machine already infected? We don't know!
* Practice good credentials hygiene!
* When there is a choice, use a non-admin account.
* Prefer network logons instead, which result in less-useful SATs being created in memory.

__Protecting Delegation for Accounts in Active Directory__
---------------------

In [Active Directory], you can specify in the Users settings, in a box called "Account options", a setting named: "Account is sensitive and cannot be delegated." __Check this box.__

In the properties of a computer account, in the "Delegation" tab you can select "Do not trust this computer for delegation."

__Do not Cache Credentials__
--------------

* Set to zero on servers and administrative workstations.
* Requires reliable access to a domain controller.
* Use whole disk encryption and UEFI Secure Boot.

__Add users to a Protected Users Global Group in Active Directory__
-----------

* Members of this group are __not permitted to__:
    - Log on with cached credentials
    - Use NTLM, Digest or CredSSP with authentication
    - Use anything other than AES with Kerberos
    - Delegate credentials with Kerberos to trusted servers
    - Have Kerberos TGT lifetimes of more than four hours


__To Get Powershell v5.0 on Server 2012__
------------------

```
cd C:\SANS\Tools\WMF
wusa.exe .\2012R2.msu \quiet
```

__JEA Setup Steps__
-----------------

1. Create a module folder for the JEA files.
2. Edit a role capabilities text file (`.psrc`)
3. Edit a session configuration text file (`.pssc`)
4. Register the remoting session endpoint.
5. Connect that endpoint with a non-administrative user account.

Graphical tools can be built on top of JEA remoting too, not just scripts!


__Create Module Folders for the JEA Files__
--------------------

```
cd C:\Program Files\WindowsPowerShell\Modules
mkdir JEA-Test
mkdir JEA-Test\RoleCapabilities
cd JEA-Test
```

__Creating the Role Capabilities File__
-------------

JEA blocks all commands by default.

Create a `.psrc` file with default settings:

```
New-PSRoleCapabilityFile -Path .\RoleCapabilities\ServiceAdmins.psrc
```

__Creating the Session Configuration File__
--------------------

```
New-PSSessionConfigurationFile SessionConfig.pssc
```


___To use JEA, once you create this file, you must set the `SessionType` setting to `RestrictedRemoteServer`___

And the user that you have logging in, you must specify the [Active Directory] groups that the user is a part of in the `RoleDefinitions` section. The `Role Capabilities` must be set to the name of the `.psrc` file you created earlier, but ___WITHOUT___ the `.psrc` extension.

The `RunAsVirtualAccount` set to `$True` does elevate the SAT to an admin account. 


__Registering and Creating the JEA Endpoint__
------------------

```
Register-PSSessionConfiguration -Path .\SessionConfig.pssc -Name SEC505AnA
```

__Managing Administrative Privileges in Active Directory__
===========================

```
Import-Module Active-Directory
Get-Help *AD* 
```


__Active Directory Permissions__
---------------------------

Every property of every object in [Active Directory] can have its own separate set of permissions.

To see the permissions in AD Users & Computers, right-click any OU, then select View->Advanced.

Under `Properties` of any object, you can go to the `Security` tab and then even go to `Advanced` and `Edit` and see many _many_ settings. 

__Delegate Full Control over an OU__
-------------------------

Very few Domain Admins are needed. You will probably only need 1 for CDX.

An "OU Admins" group will:

1. Have full control over the OU, with logging enabled at the domain level.
2. Be a member of the Administrators group on the computers in the OU.
3. Have a write access to the GPOs linked to the OU.
4. Be explicitly denied all logon rights on computers outside the OU.
5. Be required to use particular jump servers for OU administration.


__Auditing AD Access for Pre-Forensics__
-----------------

Every property of every object in AD can have its own separate set of audit settings too.

Add to the default AD audit settings as necessary to track administrative abuse for pre-forensics logging.

Audit Policy:

* Track pre- and post- change values on modified or deleted objects.
* Requires [Server 2008] of later domain controllers.

This is just a normal Windows audit policy, so you can manage it with a Security INF template or Group Policy, or from the command line.

```
auditpol.exe /get /category:*
```


`Directory Service Access` is the name of the audit policy in the listing. 


__Host-Based Windows Firewalls__
=========================

__Host-Based Firewalls for Defense In Depth__
---------------

Having only a perimeter firewall isn't good enough:

* Infected or remotely-controlled hosts attack from _within the LAN_.

Host firewall must be centrally manageable:

* Usually bundled with endpoint protection suites (list in the manual)
* Must support different rules for different groups of users/devices.
* Must flexibly support exception, special cases, backups, etc..
* Must be compatible with devices which roam outside the LAN, have their own mobile links, and which use VPNs for remote access.
* Preferably integrated with IPsec in the protocol stack.

__Our perimeter firewall should not allow outbound SSL. That can be taken advantage of for ANYTHING, literally anything could be tunneled out that way.__

__Firewall Tools__
--------------

* MMC Snap_in
    - Windows Firewall


* `wf` from within [Powershell] wll open it up.
* `Connectiion Security Rules` are IPsec rules.

Legacy Scripting can be done with `netsh.exe`. 


__Windows Firewall: Network Profiles__
------------------------

* Profile Types:
    - Public
        + This is the default
        + Block Inbound
        + The most strict firewall settings
    - Private
        + Home
        + Small Office
        + All outbound traffic is typically allowed
        + 
    - Domain
        + Automatic with domain controller authentication
        + Least restrictive firewall rules


You can see all the "Profiles" in the Windows Firewall management tool. 

You can filter by this, and even filter by different applications or services or functionality. 

Since the __Domain__ profile is very open, we should change it in its properties to _block all by default_ and then just allow only the things we need. 

Set up logging, as well. Log all dropped packets, log successful connections, etc.. Every dropped packet will result in a new line; but every successful connection will just result in one line. Do this absolutely on the __Domain__ profile. 


__Managing Firewall Rules__
-------------------------

If you right-click on a rule and hit Properties, you have three choices for "Action". One of them is "Allow the connection if it is secure"... this means IPsec!

If we use the IPsec option, the port will look closed on a port scan, unless they are authenticating with IPsec. IF we choose that option, we can specify what users are doing this with the "Remote Users" tab. Same for "Remote Computers". __DO THIS.__ 

This option does not configure IPSec for us, however. When we choose this role, it ONLY allows IPsec connection -- but we still have to configure IPsec to work with it.

The __Scope__ tab allows you to determine what IP addresses can be allowed for the connection, and more. 

The __Programs and Services__ tab lets us set up a rule to block a specific program or a specific service. We can push out a rule like this for many machines with Group Policy.

__IPSec__
==================

IPSec benefits:

* Mutual Authentication
* Port Permissions
* Encryption (optional)
* Integrity Checking
* Compatible with NAT
* Transparent to Users
* Hardware Acceleration

__Example IPSec Scenarios and Uses__
---------------

* Dangerous protocols and ports on endpoints:
    - Wireless traffic, SMB, RPC, FTP, DNS, RDP, VNC, etc.
    - What global groups should be allowed to access these ports?
* Prefer IPsec on high-value endpoints:
    - Allow plaintext whenever necessary, but IPsec is preferred
* _Require_ IPsec to make an encrypted VLAN:
    - Different inbound vs. outbound rules, easily make exceptions.
* Secure servers in the cloud or in your DMZ:
    - Permit secure remote administration only to necessary groups.
    - Combine with firewall ruls for host-based segmentation.


__Null Encapsulation__
---------------------

Typically IDS and IPS sensors don't know what to do with IPsec. If they see an IPsec header, they just assume it is encrypted (even if it is not) and ignores it. So, that really sucks.

But, we can still work with this. We can turn on __null encapsulation__.

With null encapsulation, after the IKE negotiations (handshake), no further packets are encrypted or authenticated at all. _But_ the Windows Firewall still knows who you are and can enforce the TCP/UDP port permissions.

This is a debatable thing, if you really wanted encrypted packets... but if you have encrypted packets, your IDS and IPS can't examine them. 

__IPSec Settings__
----------- 

The default settings for IPSec are pretty good. But we can customize them if we want.

Get to the properties in the Windows Firewall tool (right click the "Windows Firewall" drop down in the very top-left) There is an IPsec Settings tab. You can click "Customize".

Start with main mode. Go "advanced" and "customize". 

If you want a new "contract", hit "Add". We can amp up to the _best_ hashing algorithms, but this requires the latest Windows products (which you should have anyway).

So, we can roll with "SHA-384" hashing, AES-256 bit encryption, and even elliptic curve diffie-helman key exchange. 

Move that up to the top of the listing, so it is the most preferred. 

The main settings for the key lifetimes are fine. But if you're paranoid (like for CDX), you can crank this down.

And for CDX, you can check the box for Key Exchange options, to turn on Diffie-Helman for enhanced security.


Next, move onto the Quick Mode settings.

The left side is for packets that are no encrypted; the right side is for packets that ARE.

There is a checkbox on the top that determines whether or not you want to ALWAYS use encryption. You'll see if you check it, the left side greys out.

For the left side, if you add a new integrity algorithm, there you can specify the __null encapsulation__ if you want it. Don't bother with AH.. it is incompatible with NAT. ESP is the default.

You can crank up the hashing algorithm to the best.

And again, if you want to lower the key lifetimes you can, but the default is fine.

On the right side, you can add another algorithm, and the recommended ESP option is fine. Crank up the encryption and integrity algorithms. And the key lifetime again, if you want it. 

In the listings on the left and right, try and have just one "offer" (on option in the listing).

Now back on the main settings page we can customize the advanced settings for the Authentication method. 

The left hand side is the authenticating COMPUTER, while the right hand side is the authenticating USER. 

For the left hand side additons: Kerberos is faster and more secure than NTLM. The certificate authority is the best and most secure option, but you would need PKI to set that up. And the signing algorithm can be cranked up to the ECDSA, which is better than RSA. You can "browse" and select your CA and PKI. 

The checkbox "Enable certificate to account mapping" is not necessary for CDX.

__The preshared key option is not recommended, do not use it.__

For the right hand side, you can again set up the CA and PKI work. Smart card authentication wins again.

__Connection Security Rules = IPsec Rules__
-------------------

These rules are kind of like Snort or Bro rules. They are under `Connection Security Rules` in the Windows Firewall tool.

These rules define which traffic types trigger IPsec

* You can exempt certain IP addresses, such as for DNS and DHCP servers, from the need to use IPsec at all.
* Require high security for important servers or subnets.

If you add a new rule, choose "Custom" so you can specify all the fields.

Endpoint 1 and Endpoint 2 are really just source and destination IP addresses. You can put in IP ranges and specific subnets like `10.40.1.0/16`, or any IPv6 range too. If you're not familiar with CIDR ranges you can specify a range with the "From" and "To" fields as well.

We can further narrow down the IPsec criteria, hit "Next". When you "request authentication" you make IPsec optional, you prefer it. When you "require authentication", you make IPsec required. After some testing youc an use "require".

That last option, "Do not authenticate" should really say "Do not use IPsec at all". This is for defining exceptions.

In Authentication Method you can use the default, which you set up earlier .. or you can usee Advanced/Customized to specify unique settings for this one single rule.

For protocol and ports, it is rather self explanatory.

For the profile, make sure it is "Domain" only, because that is when you are connected to the domain. 

You can specify whatever name you would like. Preferably something that really explains what it is.  





__Security Zone IP Addressing Scheme__
-----------------------

Security Zones => IP Address Ranges:

* Security
* DMZ
* Servers
* Clients

Zones simply the deployment of firewall and IPsec rules. Often used with VLANS or internal segmentation. Customize the zones to fit the needs of your organization.

__Clients do not need to talk to each other.__This would do wonders for the infrastructure security. 

__Group Policy Management__
-----------------------

You can use Group Policy to manage:

* Windows Firewall Rules
* IPsec Policies

So what you can do is right-click on the Firewall snap-in and export all of your settings as a file (some that you may have set up in a testing environment, in the lab). You can then import them into the Windows Firewall object in Group Policy! Group Policy will push out those rules and IPsecc settings.


Start small and work your way up after doing some testing. 

__No client should be LISTENING on port 80__. That is typically how malware beacons out with backdoors. 


__Powershell Scripts and Remoting__
------------------------


__IPsec Cmdlets:__

```
Get-Help *Net*IPSec*
Get-NetIPSecRule | Format-Table DisplayName, Enabled
```


__Firewall Cmdlets:__

```
Get-Help *Net*Firewall*
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
```

Remember that you can get a _group_ and a whole set of firewall rules. That's what we do in the example above.


You should create a "build library" of scripts and utilities to harden and do things on your network.


__Deployment Automation Options__
------------------------

__Group Policy__

* Best for hosts inside the LAN or with VPNs
* Easiest agility with OUs, GPO permissions, WMI, etc..

__Powershell Remoting__

* Not as scalable ase GPOS and not good for roaming endpoints.

__Desired State Configuration__

* Scalable, roaming-compatible, but complex HTTPS setup.

__Scheduled Scripts__

* Do anything you want! Management can get more complex.

__Anti-Exploit Techniques__
==========================

__User Endpints should be more like Appliances__
-------------

Principle of _Least Endpoint_:

* If the user doesn't need it, get rid of it!
* Applies to which applications users may launch, outbound firewall rules, Control Panel applets, the All Settings app, browser extensions, Powershell, where they may save files, etc..
* __Manual has a long list of GPO options for creating a minimal user desktop__
* This is a theme we will see many times this week.


You can change the default "desktop" to be any program you want; it doesn't have to be `explorer.exe`. That way you can't really do anything. Maybe launch just straight up `calc.exe` and let the computer do nothing! __Can we do this for CDX?__

There is an AWESOME list on this on page 104 and onwards. You can really strip down the default Windows box. 


__Application Whitelisting__
--------------------------

If AV is failing, perhaps it's better to block all processes by default and only permit known-good programs?

Application Whitelisting =  Enforcing rules to allow or block processes based on your chosen criteria:

* Folder path, network path, hash, digital singature, etc..
* Does not depend on virus signatures or heuristics.

The industry trend is to combine anti-virus with application whitelisting and endpoint monitoring.


__AppLocker Overview__
-----------------

AppLocker is only available on Enterprise and Education editions of Windows.

AppLocker Policy Rules:

* Apply to many EXEs, DLLs, scripts, MSI, and APPX packages.
* Different rules for different groups (RBAC for applications)
* An "audit only" mode for testing through Group Policy,


__AppLocker Event Log Messages__
---------------------

* Event ID numbers are in the manual for what is blocked, allowed, or would have been blocked if not in audit-only mode.

This is all managable in group policy. `Computer Configuration -> Policies - > Windows Settings - > Security Settings -> Application Control Policies -> AppLocker`.

Right clock on the AppLocker container and go to properties. In the Advanced tab you can check the box to enable DLL rule collection.

On the first tab, you can see each category of rules. You can run "Automatically Generate Rules" and AppLocker will look through your machine and create ALLOW rules for all the applications currently on there -- so, you will want to do this for like a new and complete clean machine. If there are any malware or hacking tools on there, AppLocker will allow it if you do this -- so make sure it is a clean machine!

Keep in mind, that if you create ONE AppLocker role to ALLOW, AppLocker changes modes to "BLOCK" everything by default. 

And of course, if you wanted to, you can block specific groups from Active Directory. 

__AppLocker Rules__
----------------- 


* Start with the default rules, then use the wizard.
* `Get-AppLockerFileInformation`:
    - Create rules by Scanning Windows event logs for AppLocker events
    - Create large numbers of hash rules from reecursive folder listing.
* __Everything is blocked by default once there is an allow rule!__
* Use wildcards in certificate code-signing rules.
* Import/export rule sets as XML files for [PowerShell] and GPOs.

__Make sure to block programs running from the Recycle Bin or from the temp folder!__ This is described in the manual.

__Powershell Language Mode and AppLocker__
------------------------------

Powershell Langauge Mode:

* NoLanguage 
    - You can only run commands. You cannot sue flow control, create variables, etc..
* RestrictedLanguage
    - Older langauge mode, very very similar to 
* _ConstrainedLanguage_
    - __This is what we want__. It fights against Powersploit and empire. This tries to lock against the most commonly exploited [Powershell] cmdlets. You can still access variables, but you can't do things like PInvoke or access Windows API stuff.
* FullLanguage (the default)

AppLocker sets ConstrainedLanguage mode automatically with PowerShell 5.0 or later.

With JEA, use the most restrictive mode you can. You can set the LanguageMode in the configuration files.

The full description of these are on page 124. The variable `$ExecutionContext.SessionState.LanguageMode` will show you what

__AutoPlay and AutoRun__
--------------------------


`AutoRun.inf` file in the root of the volume.

AutoPlay displays GUI of choices and can also process `AutoRun.inf`

__You can disable this through Group Policy__.


__EMET: Microsoft Benevolent Rootkit__
---------------------

* Enforces process security protections:
    - System-wide: DEP, ASLR, and SEHOP
    - Per-process: Define exceptions for compatibility.

* Deploy hands-free as an MSI package.
* Manageable through Group Policy.
* Command-line scripting support for Powershell
* Import/export settings as XML files.
* Free and supported by Microsoft!


EMET is mandatory for the DOD. It is enforced in the STIGs.

There is a lab on usage of EMET in the manual page 141.




__Assume Breach with Pre-Forensics__
======================

* Harden first, then assume breach:
    - Prepare for the inevitable incident response crisis.
    - It's too late to enable logging _after_ the fact.
* Generate the raw SIEM (Security Information Event Management) input data:
    - SIEM performs real-time IDS analysis of log data.
    - But audit policies must be enabled to feed the SIEM.
* Help your Hunt Team be successful:
    - Don't passively wait for an IDS alert, go hunting!
    - But the Hunt Team needs help, they need baselines.


__Windows Audit Policy__
---------------

Open up the GPO and go into `Security Settings -> Event Log -> Local Policies -> Audit Policies`. Ignore these. We have _newer_ audit policies, called the "Advanced Audit Policies Configuration."

You can manage these with `auditpol.exe`


```
auditpol.exe /get /category:*
```

You can of course also _set_ advanced audit policies. And you can do this with Group Policy, too.

* Windows Audit Policies
    - Determines what types of data are logged.
    - Legacy versuses Advanced Audit Policies (Vista+)
* How to Manage
    - INF Security Templates, GPO, and `auditpol.exe`
    - INF cannot manage the Advanced Audit Policies!

But what to log? Use the Microsoft Security Compliance Manager. 


__Log Consolidation for SIEM Analysis__
----------------

Logs from all sources, not just Windows, mustr be centralized:

* Protects from malicious deleting or editing.
* Allows cross-platform correlation and analysis.
* Allows-real-time IDS alerting.
* Unrealistic to do IDS scanning by hand anymore.

Long list of SIEM products in manual:

* Some totally free, some are "freemium" in SMEs. (Splunk!)
* Can't cover SIEM management here, not enough time.


__Schedule System Snapshots for the Hunt Team__
-------------------

A snapshot is a set of text files baselining for current "normal" state of the machine for the sake of future forensics and incident response:

* It includes listening ports, processes, drivers, security policies, hidden files, file system hashes, autoruns, time stamps, registry values, etc..
* Before-and-after baseline files can be easily compared because they are just text files.


There is a seriously awesome listing of what to get as data for the snapshot on page 151 of the manual.

__Pre-Forensics Miscellaneous Settings__
--------------------

* Enterprise-wide time synchronization
* Audit new process creation and termination
* Enable DNS logging (or passive sniffing)
* Windows Firewall successful connection logging
* Enable NTFS "last access" timestamps
    - Even LISTING the directory contents will update this field
* Enable Prefetch and SuperFetch on workstations
* Memory dump on system crash.
* Do not disable System Restore on workstations.
* Enable System Protection (shadow copies)
* Internet Explorer History and InPrivate browsing.
    - Don't allow users to clear the history or use settings like incognito modes or private browsing


__Powershell Automation Tips__
--------------------


* `Get-WinEvent` to search live or exported logs with XPath
* Powershell DSC resource modules for auditing
* `secedit.exe` to apply INF templates
* `auditpol.exe` to manage audit policies
* `lgpo.exe` to apply an exported GPO
* `Write-EventLog` to log new events
* `SendTo-SysLog.ps1` to send custom syslog packets
* Powershell projects: Kansa, Uproot, PowerForensics
    - These are awesome defensive and blue team projects that you should totally take a look at


__WMI for the Blue Team__
========================
    
1. WMI: Windows Managment Instrumentation.
2. Hardening Exploitable Protocols and Services:

* DNS Name Resolution
* Protocol Binding and IPv6
* Kerberos and NTLMv2
* SSL/TLS Cipher Suites
* Remote Desktop Protocol (RDP)
* Server Message Block (SMB)

 
__Windows Management Instrumentation__
-----------------

WMI is Microsoft's implementation of the DMTF's WBEM/CIM standards for remote management.

__WMI Query Language__
------------------

Typical WQL Format: `SELECT <...> FROM <...> WHERE <...> = <...>`

To see all the WMI namespaces: `Get-WMIObject -Query "SELECT * FROM __namespace" -namespace "root" | Format-Table Name`


To see all the classes in CIMv2: `Get-WMIObject -Query "SELECT * FROM meta_class" -namespace "root\cimv2"`


__WMI Querying Remote Computers__
--------------------

WMI uses DCOM RPC (TCP/135)

Integrated Windows authentication by default, but explicit credentials work too with `Get-Credential`.

Computer can be name, IP or FQDN.

```
Get-WMIObject -query "SELECT * FROM Win32_BIOS" -Computer "Server47"
```


You can connect with HTTP and HTTPS though, if you want, which would be great for CDX. 


__WMI Event Logs__
-----------------------


Very importantly, the event log enetries are selected AT THR SERVER, not locally.

```

function Get-LogonFailures ( $computer = "." ){

    $query = "SELECT * FROM Win32_NTLogEvent 
    WHERE logfile = 'Security'
    AND ( EventCode = '529' OR EventCode = '4625' )"

    Get-WMIObject -Query $query -Computer $computer
}
```


You don't need [Powershell] remoting for any of this; it is the WMI service all on its own.

__Logging WMI Activity__
------------

There are some options for auditing and monitoring WMI usage in Group Policy and in `mmc.exe`.

__WMI Processes and Device Drivers__
-------------

To query a list of processes or drivers:

```
Get-WMIObject -Query "SELECT * FROM Win32_Process"
Get-WMIObject -Query "SELECT * FROM Win32_SystemDriver"
```

To terminate a process by its PID:

```
$process = Get-WMIObject -Query "SELECT * FROM Win32_Process WHERE ProcessID = '5298'"

$process.Terminate()
```

WMI can remotely make changes. 

__WMI Remote Command Execution__
-------------------

```
function Remote-Execute ( $computer, $commandline ){

    $ProcessClass = Get-WMIObject -Computer $computer 
      -query "SEKLECT * FROM Meta_Class WHERE __Class = 'Win32_Process'"

    $ProcessClass.Create( $commandline )
}


Remote-Execute -Computer server47 -Command "ping 8.8.8.8"
```


Hackers and malware use WMI _constantly_. They don't need [Powershell] or anything -- but they can still do WMI remote command execution. All they need are credentials.


__WMI Command Execution versus Powershell Remoting__
-------------

* WMI Execution
    - Installed everywhere
    - Enabled by default
    - Target does not need Powershell installed
    - No interactive session
    - No return of output
    - Lack of management
    - Not being developed
    - Not the standard
* Powershell Remoting
    - Powershell not installed everywhere.
    - Remoting not enabled by default on clients
    - Source and target both require Powershell
    - Interactive sessions possible
    - Output returned over the network
    - Rich management, e.g., JEA, logging, etc..
    - Being actively developed, e.g., `ssh` support
    - The Microsoft standard for remoting.


__WMI Shutdown, Reboot, or Logoff__
----------------

```
function  RebootShutdownLogoff-Computer ( $computer, $action ){

    Switch -regex ( $action ){
        "logoff" { $action = 0 }
        "shutdown" { $action = 1 }
        "reboot" { $action = 2 }
    }

    Get-WMIObject -Query "SELECT * FROM Win32_OperatingSystem WHERE primary  = 'True'" -Computername $computer | Foreach-Object { $results = $_.Win32Shutdown($action) }

    if ( $results.ReturnValue -eq 0 ){ $true } else { $false }
}

```


See, the WMI service can all functions in the Windows API. You are basically talking directly to the kernel. 

Remember, you can really only interact with the WMI objects if you are in the Administrators group. 

NSA TAO video on how to defend against people like the NSA TAO: [https://www.youtube.com/watch?v=bDJb8WOJYdA&app=desktop](https://www.youtube.com/watch?v=bDJb8WOJYdA&app=desktop)


__WMI taking Inventory of your Network__
-----------------

```
cd C:\SANS\Day6-Servers\WMI

.\Inventory-Applications.ps1 -FilePath inventory.csv

Import-CSV -Path .\Inventory.csv 
```


__WMI for Group Policy__
--------------------

`WMI Explorer` is an interesting tool to see all the WMI things in a GUI rather than with Powershell.

In the flash drive files there are a ton of examples for WMI queries.

* Item-level targeting for preferences
    - Use one or more WMI queries in the targeting
    - Affects just atht one GPO preference setting
* WMI filter for an entire GPO
    - WMI query to decide apply/ignore the entire GPO
    - See the WMI filters container in the GPMC


`WMI_Sample_GPO_Filters.ps1`


__Hardening Exploitable Protocols and Services__
=======================================

__Disable NetBIOS and LLMNR__
------------

* NetBIOS
    - Disable with DHCP scope option.
    - Drop all UDP 137 and 138 packets
    - Drop all TCP 139 packets, use TCP 445 instead.
* Link-Layer Multicast Name Resolution
    - Plaintext, unauthenticated and multicast = Bad.
    - Cannot traverse routers by default.
    - Disable by Group Policy setting
    - Drop all UDP 5355 packets on each host.

__DNS Tools__
------------------

* The DNS Snap-In
* Powershell (100+ cmdlets)
    - `Get-DNSServer`
    - `Resolve-DNSName`
* Event Viewer DNS log
* Legacy Tools:
    - `ipconfig.exe`
    - `nslookup.exe`
    - `dnscmd.exe`


__Active Directory Absorbs DNS__
-------------------

* DNS records are just more AD objects
    - No more zone files.
    - No more zone transfers.
    - No more primary-secondary distinction.
    - All DNS servers must be domain controllers to do this.
* Advantages and Disadvantages
    - No separate DNS replication topology to maintain, no single point of failure, permissions onf DNS records for secure dynamic updates, more efficient replication.


If you go into the DNS snap-in, you can select the Properties for your domain. In the General tab there is an option to Change Zone Type. There is a checkbox to "Store the zone in Active Directory (available only if DNS server is a domain controller)".


__DNSSEC__
---------

* DNS is a horribly insecure protocol.
* DNSSEC digitally signs DNS records.
* DNSSEC does not encrypt queries or responses.
* DNSSEC secures DNS-to-DNS server traffic.
* _IPSec_ secures client-to-DNS server traffic.

Imagine your domain controllers are DNS servers. They are configured with IPsec to sign all of their DNS responses. All the clients are configured to sign their queries. 

If you want to add privacy, you can use IPsec to _encrypt_ the queries... but at a minimum, you should at least uses DNSSEC. 

__How to manage DNSSEC__
---------------

There is a section in the manual for this. In the lab, too, it walks you through this.

DNSSEC starts with a key, which signs other keys, which signs other keys, etc.. It is the chain of signing keys which is the backbone for the system.

1. Add root zone trust anchor (the real-world correct root zone).
2. Enable validation of remote responses.
3. Sign your DNS zone with the wizard.
4. Enable automatic anchor distribution. (only automatically synced with domain controllers)
5. Select what will require DNSSEC:

> For #5, maybe GPO will manage the Name Resolution Policy Table. Select FQDNs, domain suffixes/prefixes, IP subnets. You can define exceptions based on matching priorities.

After you have added the root zone trust anchor (#1), for #2, you can right-click the DNS server on the left-hand tree menu, go into Properties->Advanced, and there should be an option at the very end of the list for "Server Options" to "Enable DNSSEC validation for remote responses." You can check this box. 

Step #3 is to sign your own DNS zone. The DOD has been trying to deploy DNSSEC for years. But it was a headache. So, they went to Microsoft and asked them to make it _easier to manage._ So, in Server 2012 and beyond, it isn't so bad.

In your "Foward Lookup Zones," right click your domain, go to "DNSSEC" and select "Sign the zone." In the wizard, you can "Use default settings to sign the zone." Next, Next, and finish. That's it! If you press the __Refresh__ button, you can see all the new keys that were created. __Make sure you do this, to ensure that it worked.__

Ideally, you would have your DNS server Active Directory-integrated. If you right click on your domain, go back into "DNSSEC", and go to "Properties," you can go to the "Trust Anchor Tab." Click on "Enable the distribution". This way, the changes to the DNSSEC keys (that are updated and refreshed), they are automatically updated to other DNS servers in the LAN (IF YOU HAVE MULTIPLE DNS SERVERS. IDEALLY THEY WOULD BE INTEGRATED WITH ACTIVE DIRECTORY). Your internal DNS server must be a domain controller. 

The "KSK" stands for Key Signing Key in the properties Window. You can change the cipher and key size (but th defaults are just fine). ZSK is the same thing. 

__For the Next Secure tab, MAKE SURE THAT NSEC3 IS THE ONE CHECKED.__

In the "Advanced Tab", move up to the "DNS record generation algorithm" to SHA-384 if you would like (to avoid SHA1).

Remember, all of this is to protect our servers and workstation. The thing that we are trying to protect from is some machine making a query and receiving a _spoofed response_. As it stands right now, none of your _workstations_ care whether or not these responses are signed. DNS servers are set with DNSSEC, but we need to ensure that #5 will make your other machines and workstations _ACTUALLY CARE_ whether or not their responses are signed or not.

For Step #5... `nslookup` does not know or care about DNSSEC. Every Windows machine has what it called is a Name Resolution Policy Table (NRPT). All Windows machines have a Primary DNS Server and a Secondary DNS server, which is typically your "default gateway" like for DNS. By default, all your DNS queries go to those DNS servers. _But you don't have to._ You can actually send DNS requests to _different_ DNS servers, depending on the query. By default, this NRPT is _empty_... there are no settings to query other DNS servers other than your primaries.

You can look at these with Powershell commands like `Get-DNSClientNRPTPolicy`. There are fields like "DNSSECIPSecCARestriction" and "DNSSECQueryIPSecEncryption" and "DNSSECQueryIPSecRequired". The BIG important one we want set to `True` is "DNSSECValidationRequired." That _makes sure_ that the domain you query will actually be validated by DNSSEC. So, when you really use something like `Resolve-DNSName -Name ` (rather than `nslookup.exe`) it will use DNSSEC. So if something is not validated, it will look like it fails, and says "Unsecured DNS packet."

So for #5, you can set this in your clients by Group Policy. We have to configure them to care which DNS responses are signed or not. Go to your Group Policy object, "Edit GPO", "Computer Configuration", "Policies", "Windows Settings", and "Name Resolution Policy." On the right hand side, scroll down to the bottom. The bottom table sets up additional rules to add to the NPRT on all the machines that the GPO applies to. By default, the table is blank. If you scroll up to the top, you can create rules by FQDN or suffix or anything. You can check the box for "Enable DNSSEC in this rule" and the "REQUIRE DNS clients to check and validate." __And check the other box for IPsec.__ When you are done with your rule, hit the "Create Rule" button. It will be added to the table at the bottom. Then hit "Apply" when you are done.


__DNS Sinkhole: Block Unwanted Name Resolutions__
--------

__Malware often needs to resolve FQDNs__.

Import these FQDNs into your DNS.

* Or into the HOSTS file on roaming computers. `Sinhole-DNS.ps1` and `Update-HostsFile.ps1`.

Resolve to `0.0.0.0` to block access. __Or, resolve to an internal server with verbose logging enabled.__ This is even better, so you can monitor and see everything infected. 

___Free and regularly-updated sources of bad domains and FQDNS are available!___

`Update-HostsFile.ps1` will download and update your HOSTS file with a free list available online at `malwaredomains.com`. That is managed by Google. 

In the manual is a list of the free and regularly-updated sources.


__DNS Security Best Practices__
-----------


* Use a split DNS Architecture
* Require secure dynamic updates from everyone.
* Disable zone transfers.
    - Right click on your DNS domains, go into properties, "Zone transfers," and uncheck "Allow". 
* Secure against cache poisoning attacks.
    - The best defense is good patch management. 
* Use DNSSEC and IPSec.
* Sinkhole bad names.
* Harden ACLS on critical DNS records, including SACLs.
    - You can change Audit settings for DNS records, if they are integrated with Active Directory.

There are other recommendations in the manual

__Eliminate Unnecessary Networking Compenents__
-----------------

* Server Manager:
    - Remove unnecessary roles and features to eliminate many of the unneeded components.
* NIC Interface Bindings:
    - These are the checkboxes.
    - Configured per-interface, including VM virtual interfaces.
    - You will want to ___uninstall___ pieces of the protocol stack that you don't need. You can always install the pieces again if things break. For the things you can't uninstall, you can uncheck the bindings.
* PowerShell:
    - `Get-Command -Module NetAdapter`

You can use the PowerShell commands for your hardening script.



__Disable IPv6 (Until You Need It)__
----------------

* IPv6 is inevitable, but ...
    - IPv6 is complex, powerful, and requires planning.
    - We want to shrink our attack surface.
    - The tunneling features can be separately disabled.
* To disable IPv6 (or just IPv6 tunneling)
    - For the entire system, it's just a registry value. (this is documented in the manual and it is in the USB for `Day6-Servers/IPv6`)
    - For a single NIC, uncheck its binding checkbox.
    - Drop IPv6, tunneled IPv6, and Teredo packets.

If you don't want to get rid of IPv6 entirely, you can change the registry value in a special way, to keep IPv6, but _just remove the tunneling feature_.

__You should at least remove tunneling for CDX__.


__Harden TLS and Disable SSL__
---------------

___Disable all versions of SSL and only use TLS___.

TLS 1.0 is almost universally supported today. Enable TLS 1.1 and 1.2 on older operating systems.

* Optimize the TLS cipher suites using Group Policy:
    - Prefer 256-bit AES in GCM mode for TLS 1.2
    - Prefer ECDHE for perfect forward secrecy (PFS).
    - `Get-Command -Module TLS` (for Server 2016 and later)

Use of SSL is a bunch of Registry settings. You can do this with the `Day6-Servers/SSL-TLS` folder in the USB. Also in this folder is the `CipherSuiteOrder.txt` which has the most secure order for cipher suites, which you should definitely utilize for CDX. You copy the string to the clipboard, open up a GPO, and chaneg the cipher suites. This is "Computer Configuration", "Policies", "Administrative Templates", "Network", "SSL Configuration Settings".


In the manual are really cool websites that can give you more information on your own configuration settings.


__Kerberos Overview__
---------------------

Kerberos is the default authentication protocol on domain-joined Windows devices.

* Kerberos benefits:
    - More secure than LM, NTLMv1 or NTLMv2
    - Faster and more scalable than NTLM
    - Mutual authentication by default (client _and_ server)
    - Can be combined with smart cards (PKINT)
    - Solves the "delegation of identity" problem

There is a glossary of Kerberos terms in the manual.

__Hardening Kerberos__
--------------------

* Require a smart card whenever possible
    - Still have a hidden, random, long password
* Enforce a good passphrase Policy
    - The longer and more complex the better
* Requires AES, block DES and RC4
    - Use only Windows 7, Server 2008 R2, or a later OS
* If necessary, fine-tune other settings
    - TTL values, permissible clock skew, etc..

In your manual there are other things and settings to keep in mind.

__Kerberos Armoring__
---------------------

__Kerberos is vulnerable to MITM and brute-force decryption attacks!__

* Armoring encrypts the __user's__ authentication with a key derived from the __computer's__ boot-up authentication sequence.
* Computer passwords are random and reset every 30 days.
* Requires server 2012, Windows 8 or later, but can coexists with older systems when armoring is set to optional.

__Kerberos Post-Exploitation__
-----------------------

* The `krbtgt` global user account:
    - Its password hash is the KDC master key!

* __Golden Ticket Attack__
    - Stolen `krbtgt` password hash can be used to spoof a domain controller to create _any_ Kerberos ticket!
    - Microsoft reset script: `New-CtmADKrbtgtKeys.ps1`

* __Silver Ticket Attack__
    - Stolen Kerberos TGT key for a computer or service.
    - Computer password auto-reset every 30 days.

There are free tools on the Internet to implement these attacks (like Mimikatz!). It will be worthwhile for you to look up mitigation processes.

__NTLMv2 Authentication__
-----------------

* LAN Manager is _totally_ obsolete!
    - In the Security Options of Local Policies of Security Settings of Windows Settings in GPO, there is an option to remove LANMAN. Make sure it is enabled. Do the same for the NTLMv1. Select For the LAN Manager authentication level, use the bottom option "Send NTLMv2 response only. Refuse LM and NTLMv1".
* NTLMv1 still uses LANMAN!
* NTLMv2 can be secure enough to use....
    - ___IF___ you have a good, long passphrase!
    - Require NTLMv2 through group policy
    - Improves RPC session encryption too.

__Block NTLM Authentication Entirely (if you can)__
---------------


__NTLM is slower and less secure than Kerberos.__

NTLM audit-only mode records what _would have been blocked_ by disabling NTLM, but doesn't block it.

Different restrictions for incoming and/or outgoing NLTM.

__Remote Desktop Protocol__
----------------

* Many RDP uses:
    - Remote administration
    - Remote assistance
    - Virtual Desktops (VDI)
    - Virtual Apps
* Vulnerabilities
    - MITM Attacks
    - Weak Encryption
    - Credentials Exposure
    - Zero-Day exploits

__RDP Security Best Practices__
--------------

For admins, RDP should _always_ be used as __last resort__. Because when you RDP, you give your identity to that computer and it creates a security access token in memory, that might be stolen.

* RDP logons are considered __interactive__ logons.
* Beware of exposing your credentials and SAT!
* `mstsc.exe /RestrictedAdmin`... but this is just for Win8 or greater or Server2012 or greater.
* Prefer using a __local__ administrative account at the target, but only if passwords are different on every machine.
* As a first resort, try to use PowerShell JEA remoting and other networking logon tools instead to manage machines.

Avoid remoting into a machine with any __global__ account; _especially_ avoid remoting into a machine with any global account __that is a member of any groups (like domain admins!)__. 

To prevent MITM (USE IPSEC):

* Use either certificate authentication or IPsec (OR BOTH!)
* Use PKI auto-enrollment with a custom template.
    - Do this in a GPO, and navigate down to `Remote Desktop Services`, and evertually `Remote Desktop Session Host`, and `Security`. Set the name of the authentication certificate template. You can create a new template, like `RDP PKI` and use it here. We _have to avoid_ a self-signed certificate!
    - Require that it is using `SSL (TLS 1.0)`. 
    - Set client encryption level to "High"
    - For individual machines there are Registry keys to do this (all available in `Day6-Server/RDP`)
    - ___(there are better guides on how to to do this in the manual)___
* Do not allow users to ignore authentication warnings.
* Prefer smart card authentication when possible. (or just require IPsec for all RDP traffic within the LAN)
* Require Network Level Authentication (NLA), but also have an out-of-band password reset method.
    - You can manage this in Group Policy.


To prevent against attacks on weak encryption:

* Wrap RDP with IPsec (it is still the best)
    - Works on both endpoints and servers
    - Inside the LAN and over the Internet
    - Mutual authentication to block MITM attacks
    - Port permissions for role-based access control
* Have a VPN gateway and/or RDP proxy gateway
    - Best for roaming users and admins
    - Not practical for all RDP use inside the LAN
* __Set minimum encryption level to "High" with TLS.__
    - __TLS session key must be at least 128-bit.__


Miscellaneous tips:

* On endpoints, disable Remote Desktops and Remote Assistance if you aren't using these features, or restrict with host-based firewall and IPsec rules.
* __TLS 1.0 with RSA, 3DES and SHA-1 is hard-coded! All of these bad. Do not use TLS 1.0!__
* Upgrade to the latest version of thin client application.
* Set cached credentials to one or zero, depending.
* Changing the default RDP port won't help much.


__SMBv3 Encryption and Downgrade Detection__
------------------------

___Ensure you are using SMBv3!___ There is a script for this in the `Day6-Server/SMB` folder.

* SMB 3.0 supports native 128-bit AES:
    - Requires Server 2012, Windows 8 or later
    - Configure per-share or as a server default
    - Encryption can be required or merely preferred
    - Require SMB message signing too (you can make this mandatory with Group Policy)

* Older SMB versions are more exploitable:
    - Downgrade attacks can be detected and blocked.
    - ___Disable SMB 1.0 when your XP/2003 boxes are upgraded.___



[SANS]: https://sans.org
[Powershell]: https://en.wikipedia.org/wiki/PowerShell
[Server Nano]: https://technet.microsoft.com/en-us/windows-server-docs/get-started/getting-started-with-nano-server
[Windows Server 2016]: https://en.wikipedia.org/wiki/Windows_Server_2016
[Server 2016]: https://en.wikipedia.org/wiki/Windows_Server_2016
[GUI]: https://en.wikipedia.org/wiki/Graphical_user_interface
[Powershell Remoting]: https://msdn.microsoft.com/en-us/powershell/scripting/core-powershell/running-remote-commands#windows-powershell-remoting
[Group Policy]: https://en.wikipedia.org/wiki/Group_Policy
[OS]: https://en.wikipedia.org/wiki/Operating_system
[operating system]: https://en.wikipedia.org/wiki/Operating_system
[Windows Server 2008]: https://en.wikipedia.org/wiki/Windows_Server_2008
[Server 2008]: https://en.wikipedia.org/wiki/Windows_Server_2008
[Server Core]: https://en.wikipedia.org/wiki/Server_Core
[spaghetti code]: https://en.wikipedia.org/wiki/Spaghetti_code
[microsoft]: https://www.microsoft.com/en-us/
[Server Manager]: https://technet.microsoft.com/en-us/library/cc732455(v=ws.11).aspx
[HyperV]: https://en.wikipedia.org/wiki/Hyper-V
[Hyper-V]: https://en.wikipedia.org/wiki/Hyper-V
[CSV]: https://en.wikipedia.org/wiki/Comma-separated_values
[XML]: https://en.wikipedia.org/wiki/XML
[HTML]: https://en.wikipedia.org/wiki/HTML
[ISO]: https://en.wikipedia.org/wiki/ISO_image
[DVD]: https://en.wikipedia.org/wiki/DVD
[Security Templates]: https://technet.microsoft.com/en-us/library/cc960645.aspx
[Security Template]: https://technet.microsoft.com/en-us/library/cc960645.aspx
[INF Security Template]: https://technet.microsoft.com/en-us/library/cc960645.aspx
[sc.exe]: https://technet.microsoft.com/en-us/library/bb490995.aspx
[Windows Registry]: https://en.wikipedia.org/wiki/Windows_Registry
[Registry]: https://en.wikipedia.org/wiki/Windows_Registry
[Linux]: https://en.wikipedia.org/wiki/Linux
[Chef]: https://www.chef.io/chef/
[Puppet]: https://puppet.com/
[WMI]: https://en.wikipedia.org/wiki/Windows_Management_Instrumentation
[WiNRM]: https://msdn.microsoft.com/en-us/library/aa384426(v=vs.85).aspx
[DSC]: https://www.simple-talk.com/sysadmin/powershell/powershell-desired-state-configuration-the-basics/
[Desired State Configuration]: https://www.simple-talk.com/sysadmin/powershell/powershell-desired-state-configuration-the-basics/
[Active Directory]: https://en.wikipedia.org/wiki/Active_Directory
[LAN]: https://en.wikipedia.org/wiki/Local_area_network
[DMTF]: https://en.wikipedia.org/wiki/Distributed_Management_Task_Force
[MOF]: https://en.wikipedia.org/wiki/Common_Information_Model_(computing)