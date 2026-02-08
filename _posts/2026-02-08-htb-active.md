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
## Recon
### Nmap Scan
I began with a full Nmap scan to enumerate all open TCP ports and identify the services running on the target host.
`sudo nmap -p- -T4 10.129.17.166 -oN scans/all_ports.txt -Pn`
![](/assets/img/htb/Active/active2.png)
I parsed the results to store all open ports in a variable for the next scan.
`ports=$(awk '/\/tcp/ && /open/ { split($1,a,"/"); p = (p ? p "," a[1] : a[1]) } END{ print p }' scans/all_ports.txt)`
