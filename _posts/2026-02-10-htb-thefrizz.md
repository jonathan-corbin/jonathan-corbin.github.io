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

TheFrizz is a retired Windows Server 2022 Active Directory box that chains a vulnerable Gibbon-LMS file upload (CVE-2023-45878) to gain a web shell, harvest database credentials, pivot into AD with Kerberos authentication, and abuse GPO permissions to escalate from a low-privileged user to Domain Administrator.

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
After the Nmap scan revealed the domain frizz.htb, I added it to /etc/hosts to enable proper name resolution. When the web page on port 80 failed to load correctly, I observed it was redirecting to frizzdc.frizz.htb, so I added this hostname as well.

![](assets/img/htb/thefrizz/thefrizz3.png)
`echo '10.129.18.74 thefrizz.htb' | sudo tee -a /etc/hosts`
![](assets/img/htb/thefrizz/thefrizz4.png)
`echo '10.129.232.168 frizzdc.frizz.htb' | sudo tee -a /etc/hosts`

---

## SMB 445, 139
Checked smb via `nxc`. No creds so unable to proceed further here.
`nxc smb 10.129.232.168`
![](assets/img/htb/thefrizz/thefrizz9.png)

---

## Web Enumeration (Port 80)
### Initial Access to the Web App
Browising to port 80 presents a public “Walker­ville Elementary School” site with a Staff Login link, which led to a Gibbon-LMS instance.
![](assets/img/htb/thefrizz/thefrizz6.png)
![](assets/img/htb/thefrizz/thefrizz7.png)

---

### Directory Brute Force
Ran `gobuster` against the Gibbon-LMS application for anything interesting.
![](assets/img/htb/thefrizz/thefrizz8.png)

---

## Initial Access (Web → Shell)
### CVE-2023-45878

