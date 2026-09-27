<img src="./assets/banner.png" style="max-width: 100%; height: auto;" align=left />

# <center>Last Light Writeup</center>

-----------

2026-09-10

Prepared by: canopus

Sherlock Author(s): canopus

Difficulty: <font color="red">Hard</font>

## Description

```

```

## Artifacts Provided

- `NTDS.dit` - *3db205e572d2733b94ecfa168d8ff0b392f53bbbc971f0c64929a0b3e122557b* (SHA256)
- `SYSTEM` - *12b4fbc0b069081e2d8c306af3994b1ef8bc1ae0d7460a1cc77e7662263ea680*
- `SECURITY` - *cbcd19d2c35e97ed169331590475d5727efb2626c630ccdc96d21a9feee2ff67*
- `Security.evtx` - *0c46391a3928b98fde8308a415f8cb6c1a9c28e5fd23655a5105f736b79ca2a4*
- `Sysmon-Operational.evtx` - *b3f44a7c023e8dfa822ce1a3068cfd80a03ab0220860d081f797ce31429f3495*
- Memory Snapshot of DC02 - *145a572936fb70ea9704fe15bbf75f5067c22555fcff4deb4d967e2d171c9ca2*

## Skills Learnt

- Kerberos ticket memory extraction
- Golden ticket extra SID detection
- Token object impersonation analysis
- Impersonation thread identification
- RBCD backdoor detection
- Security event log analysis

## Initial Analysis

Since we have the `NTDS.dit` along with the `SYSTEM` hive, let's just go ahead and dump all the secrets using `secretsdump.py` from Impacket:

```bash
$ secretsdump.py -system ntdsutil/registry/SYSTEM -ntds ntdsutil/Active\ Directory/ntds.dit LOCAL
Impacket v0.14.0.dev0+20260904.150037.0b1a949a - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0x16b22ad9c4c7577dca3d4c5d51f21633
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 2e4a96eb1fa9bb0524e530776ab1058b
[*] Reading and decrypting hashes from ntdsutil/Active Directory/ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:f08da8c7577eb519ddaa8f7a1c2f07e1:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
vagrant:1000:aad3b435b51404eeaad3b435b51404ee:e02bc503339d51f71d913c245d35b50b:::
DC02$:1001:aad3b435b51404eeaad3b435b51404ee:5029c33b93e18f92c3adb58aaff3a0c4:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:e812d14a9c390f7400549593fc98a2c2:::
DIOGENES$:1104:aad3b435b51404eeaad3b435b51404ee:2105be67ea65d2c579ec4fec4c202904:::
WS02$:1105:aad3b435b51404eeaad3b435b51404ee:174fc629336fe7bf2e694eb08c9ae6a7:::
jreed:1123:aad3b435b51404eeaad3b435b51404ee:59500660aaf0ba7f470e8c43271df92d:::
ncole:1124:aad3b435b51404eeaad3b435b51404ee:050578d4eb5da4053131dbb9229b64ee:::
afenwick:1125:aad3b435b51404eeaad3b435b51404ee:b38845d8a6e5c42035e4cc4746d155f8:::
[...]
[*] Kerberos keys from ntdsutil/Active Directory/ntds.dit
Administrator:aes256-cts-hmac-sha1-96:19d38bbc3ab41997ab6bdefd48311a97bbade010e07ce1dbe36ad1b16d194eb8
Administrator:aes128-cts-hmac-sha1-96:ea9d3207c214f292361c931e5dc7451d
[...]
```

## Questions

----------
1. **What is the SHA256 of the service agent**

  Last Sherlock's (8 - Borrowed Name) question had us identify the new beacon that was executed as a SYSTEM service on the (child) DC. This question builds on that by asking the actual hash of the service agent that was executed.

  In order to find the hash we can use the Sysmon logs which record the hash of executables!

  We first use `evtx_dump` to parse the Sysmon logs into a json file and then we use `jq` to filter:
  - EventID == 1 (Process Create)
  - Image Name == `svc_bkup` (Already known from Borrowed Name)

  ```bash
  evtx_dump -o jsonl "C/Windows/System32/winevt/logs/Microsoft-Windows-Sysmon%4Operational.evtx" \
    | jq -r 'select(.Event.System.EventID==1) | .Event.EventData | select(.Image? | test("svc_bkup"))'
  {
    "RuleName": "-",
    "UtcTime": "2026-09-09 20:49:57.400",
    "ProcessGuid": "4608B267-C675-6AA1-AF00-000000001200",
    "ProcessId": 3376,
    "Image": "\\\\dc02\\ADMIN$\\svc_bkup",
    "FileVersion": "-",
    "Description": "-",
    "Product": "-",
    "Company": "-",
    "OriginalFileName": "-",
    "CommandLine": "\\\\dc02\\ADMIN$\\svc_bkup",
    "CurrentDirectory": "C:\\Windows\\system32\\",
    "User": "NT AUTHORITY\\SYSTEM",
    "LogonGuid": "4608B267-235D-6AA2-E703-000000000000",
    "LogonId": "0x3e7",
    "TerminalSessionId": 0,
    "IntegrityLevel": "System",
    "Hashes": "MD5=AE74305B36C450B8850E34599426D28A,SHA256=1E44C63950DD4FE1FFCC955C08D509132BCADDF87BBB08F5EA622D0533625274,IMPHASH=74F4CAFB93287C883ECA7117A3FA3FD0",
    "ParentProcessGuid": "00000000-0000-0000-0000-000000000000",
    "ParentProcessId": 596,
    "ParentImage": "-",
    "ParentCommandLine": "-",
    "ParentUser": "-"
  }
  ```

  **Answer:** <span style="color: #9FEF00;">`1E44C63950DD4FE1FFCC955C08D509132BCADDF87BBB08F5EA622D0533625274` </span>

2. **Napoleon forged golden tickets and injected them into DC02. Without dumping LSASS what is the md5sum (ccache format) and memory address of the ticket which contains the extra SID? (0xaddress:md5sum)**

  There are two ways to go about this. We can either dump LSASS and then look for the tickets there, or we can interactively examine the memory snapshot for tickets. This can easily be done with a Volatility plugin made by Airbus-CERT ([PR#1933](https://github.com/volatilityfoundation/volatility3/pull/1933))

  ```bash
  $ python vol.py -f /home/canopus/dev/holmes_ctf/release/part2/memory.elf windows.kerberos.Tickets
  
  Volatility 3 Framework 2.28.1
  Progress:  100.00               PDB scanning finished
  Address Client  Server  KerbTicket Encryption Type      Ticket Flags    Start Time      End Time        Renew Time      Session Key Type        Kdc Called
  
  0x227470d3a80   DC02$ @ CORE.DIOGENES.HTB       ldap/dc02.core.diogenes.htb @ CORE.DIOGENES.HTB AES_256_CTS_HMAC_SHA_196        0x840a50000     2026-09-09 20:27:06.000000 UTC  2026-09-10 06:27:06.000000 UTC  1601-01-03 17:46:11.000000 UTC  AES_256_CTS_HMAC_SHA_196
  0x227470cd1c0   dc02$ @ CORE.DIOGENES.HTB       DNS/dc02.core.diogenes.htb @ CORE.DIOGENES.HTB  AES_256_CTS_HMAC_SHA_196        0x0     2026-09-09 20:27:19.000000 UTC  2026-09-10 06:27:11.000000 UTC  2026-09-16 20:27:11.000000 UTC  AES_256_CTS_HMAC_SHA_196        DC02
  [...]
  0x227473721b0   Administrator @ CORE.DIOGENES.HTB       krbtgt/CORE.DIOGENES.HTB @ CORE.DIOGENES.HTB    RC4_HMAC        0x150e00000     2026-09-09 22:17:41.000000 UTC  2036-09-06 22:17:41.000000 UTC  2036-09-06 22:17:41.000000 UTC  RC4_HMAC
  ```

  The question clearly states that golden tickets were injected. A golden ticket is forged offline signed by `krbtgt`. We have a couple of tickets signed by the `krbtgt` account, but the one that sticks out is `0x227473721b0` since it's for Administrator and also valid for 10 years.

  We can dump that ticket by adding the `--dump` argument. This will dump all of the tickets. After renaming we have to convert it into a ccache format:

  ```bash
  $ mv 0x227473721b0.kirbi admin_gold.kirbi 
  $ ticketConverter.py admin_gold.kirbi admin_gold.ccache                                         [00:13:33]
  Impacket v0.14.0.dev0+20260904.150037.0b1a949a - Copyright Fortra, LLC and its affiliated companies
  
  [*] converting kirbi to ccache...
  [+] done

  $ md5sum admin_gold.ccache
  dcf56965eee82fff4d381c6127834d72  admin_gold.ccache
  ```

  **Answer:** <span style="color: #9FEF00;">`0x227473721b0:dcf56965eee82fff4d381c6127834d72` </span>

3. **From the same ticket, provide the KDCChecksum Signature hash**

  To also confirm the extra `SID` in the ticket, we have to parse it. We can use `describeTicket.py` by Impacket. We also need the NT Hash of the `krbtgt` account which we got from our initial analysis:

  ```bash
  describeTicket.py admin_gold.ccache --rc4 e812d14a9c390f7400549593fc98a2c2                    [00:17:05]
  Impacket v0.14.0.dev0+20260904.150037.0b1a949a - Copyright Fortra, LLC and its affiliated companies
  
  [*] Number of credentials in cache: 1
  [*] Parsing credential[0]:
  [*] Ticket Session Key            : dcbdf2e6c20bde38aca1305c89bb7aab
  [*] User Name                     : Administrator
  [*] User Realm                    : CORE.DIOGENES.HTB
  [*] Service Name                  : krbtgt/CORE.DIOGENES.HTB
  [*] Service Realm                 : CORE.DIOGENES.HTB
  [*] Start Time                    : 10/09/2026 01:17:41 AM
  [*] End Time                      : 07/09/2036 01:17:41 AM
  [*] RenewTill                     : 07/09/2036 01:17:41 AM
  [*] Flags                         : (0xa8700000) reserved, forwarded, proxy, initial, pre_authent, hw_authent
  [*] KeyType                       : rc4_hmac
  [*] Base64(key)                   : 3L3y5sIL3jisoTBcibt6qw==
  [*] Decoding unencrypted data in credential[0]['ticket']:
  [*]   Service Name                : krbtgt/CORE.DIOGENES.HTB
  [*]   Service Realm               : CORE.DIOGENES.HTB
  [*]   Encryption type             : rc4_hmac (etype 23)
  [*] Decoding credential[0]['ticket']['enc-part']:
  [*]   LoginInfo
  [*]     Logon Time                : 09/09/2026 22:17:41 PM
  [*]     Logoff Time               : Infinity (absolute time)
  [*]     Kickoff Time              : Infinity (absolute time)
  [*]     Password Last Set         : 09/09/2026 22:17:41 PM
  [*]     Password Can Change       : Infinity (absolute time)
  [*]     Password Must Change      : Infinity (absolute time)
  [*]     LastSuccessfulILogon      : Infinity (absolute time)
  [*]     LastFailedILogon          : Infinity (absolute time)
  [*]     FailedILogonCount         : 0
  [*]     Account Name              : Administrator
  [*]     Full Name                 :
  [*]     Logon Script              :
  [*]     Profile Path              :
  [*]     Home Dir                  :
  [*]     Dir Drive                 :
  [*]     Logon Count               : 500
  [*]     Bad Password Count        : 0
  [*]     User RID                  : 500
  [*]     Group RID                 : 513
  [*]     Group Count               : 5
  [*]     Groups                    : 513, 512, 520, 518, 519
  [*]     Groups (decoded)          : (513) Domain Users
  [*]                                 (512) Domain Admins
  [*]                                 (520) Group Policy Creator Owners
  [*]                                 (518) Schema Admins
  [*]                                 (519) Enterprise Admins
  [*]     User Flags                : (32) LOGON_EXTRA_SIDS
  [*]     User Session Key          : 00000000000000000000000000000000
  [*]     Logon Server              :
  [*]     Logon Domain Name         : CORE.DIOGENES.HTB
  [*]     Logon Domain SID          : S-1-5-21-2253468260-689643353-167204612
  [*]     User Account Control      : (528) USER_NORMAL_ACCOUNT, USER_DONT_EXPIRE_PASSWORD
  [*]     Extra SID Count           : 1
  [*]     Extra SIDs                : S-1-5-21-3066635835-107521988-671693545-519 Enterprise Admins (SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED)
  [*]     Resource Group Domain SID :
  [*]     Resource Group Count      : 0
  [*]     Resource Group Ids        :
  [*]     LMKey                     : 0000000000000000
  [*]     SubAuthStatus             : 0
  [*]     Reserved3                 : 0
  [*]   ClientName
  [*]     Client Id                 : 09/09/2026 22:17:41 PM
  [*]     Client Name               : Administrator
  [*]   Requestor Info
  [*]     UserSid                   : S-1-5-21-2253468260-689643353-167204612-500
  [*]   ServerChecksum
  [*]     Signature Type            : hmac_md5
  [*]     Signature                 : 5cc2da157cb1c50b8f555401bea362af
  [*]   KDCChecksum
  [*]     Signature Type            : hmac_md5
  [*]     Signature                 : b63742148ab83e91d38dd632b5b1fb99
  ```

  The extra `SID` is the Enterprise Admins group. Since this is a child domain, this ticket was used for a [raisechild](https://www.netexec.wiki/ldap-protocol/raisechild) attack.
  
  **Answer:** <span style="color: #9FEF00;">`b63742148ab83e91d38dd632b5b1fb99` </span>

4. **After the token steal, what is the address of the stolen Token (Address of _TOKEN object)**

  Listing all Token handles from the beacon:

  ```bash
  $ vol -f memory.elf --filter "Type,Token" windows.handles --pid 3376
  
  Volatility 3 Framework 2.28.2
  Progress:  100.00		PDB scanning finished
  PID	Process	Offset	HandleValue	Type	GrantedAccess	Name
  
  3376	svc_bkup	0xca8ddb257060	0xd8	Token	0x48	-
  3376	svc_bkup	0xca8ddc130060	0x3a8	Token	0xf01ff	-
  3376	svc_bkup	0xca8ddc130830	0x3ac	Token	0xe	-
  3376	svc_bkup	0xca8ddc130830	0x410	Token	0x8	-
  3376	svc_bkup	0xca8ddc130830	0x460	Token	0x8	-
  3376	svc_bkup	0xca8ddc130830	0x464	Token	0x8	-
  ```

  There are many candidates but we can disambiguate them pretty easily. We fire up `volshell` with `-f memory.elf` and `-w` to open a windows shell. We have to instantiate the kernel module (`ntoskrnl`) first. Then we instantiate each of the token objects:
 
  ```python
  $ volshell -f memory.elf -w
  
  Volshell (Volatility 3 Framework) 2.28.2
  Python 3.14.7 (main, Aug 13 2026, 07:40:04) [GCC 16.2.1 20260810]
  Type 'copyright', 'credits' or 'license' for more information
  IPython 9.17.1 -- An enhanced Interactive Python. Type '?' for help.
  
  
  Call help() to see available functions
  
  Volshell mode        : Windows
  Current Layer        : layer_name
  Current Symbol Table : symbol_table_name1
  Current Kernel Name  : kernel
  
  [layer_name]> ntoskrnl = self.context.modules[self.config['kernel']]
  
  [layer_name]> token = ntoskrnl.object(object_type="_TOKEN", offset=0xca8ddc130830, absolute=True)
  ```

  The attribute `TokenType` is of type [`_TOKEN_TYPE`](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_type). If the value is `1`, then the token is the original, if the value is something else, then the token object is impersonated:

  ```python
  [layer_name]> token.TokenType
  Out[4]: 2
  ```

  The other two tokens:

  ```python
  [layer_name]> token = ntoskrnl.object(object_type="_TOKEN", offset=0xca8ddb257060, absolute=True)
  [layer_name]> token.TokenType
  Out[6]: 1
  
  [layer_name]> token = ntoskrnl.object(object_type="_TOKEN", offset=0xca8ddc130060, absolute=True)
  [layer_name]> token.TokenType
  Out[8]: 1
  ```

  **Answer:** <span style="color: #9FEF00;">`0xca8ddc130830` </span>

5. **What is the ImpersonationLevel:LogonID of the stolen Token**

  Continuing our analysis of the identified `_TOKEN` object, we can find the impersonation level from the `.ImpersonationLevel` attribute:

  ```python
  [layer_name]> token.ImpersonationLevel
  Out[11]: 2
  ```

  And the logon session from:

  ```python
  [layer_name]> hex(token.LogonSession.LogonId.LowPart)
  Out[10]: '0xa616a'
  ```

  **Answer:** <span style="color: #9FEF00;">`2:0xa616a` </span>

6. **Which ThreadId runs with the stolen Token**

  To find the thread which runs with the stolen token, we have to iterate over all of the process' active threads:

  ```python
  [layer_name]> proc = gp(pid=3376)
  
  [layer_name]> thread_list = list(
           ...:             proc.ThreadListHead.to_list(
           ...:                 f"{ntoskrnl.symbol_table_name}!_ETHREAD", "ThreadListEntry"
           ...:             )
           ...:      )
  ```

  `_ETHREAD` contains `ClientSecurity`:

  ```python
  [layer_name]> for t in thread_list:
           ...:     dt(t.ClientSecurity)
           ...:
  symbol_table_name1!_PS_CLIENT_SECURITY_CONTEXT (8 bytes) @ 0xda87576616e8:
    0x0 :   EffectiveOnly          symbol_table_name1!bitfield               offset: 0xda87576616e8
    0x0 :   ImpersonationData      symbol_table_name1!unsigned long long     0
    0x0 :   ImpersonationLevel     symbol_table_name1!bitfield               offset: 0xda87576616e8
    0x0 :   ImpersonationToken     *symbol_table_name1!void                  0x0 (null pointer)
  symbol_table_name1!_PS_CLIENT_SECURITY_CONTEXT (8 bytes) @ 0xda87561356e8:
    0x0 :   EffectiveOnly          symbol_table_name1!bitfield               offset: 0xda87561356e8
    0x0 :   ImpersonationData      symbol_table_name1!unsigned long long     18446685309364275250
    0x0 :   ImpersonationLevel     symbol_table_name1!bitfield               offset: 0xda87561356e8
    0x0 :   ImpersonationToken     *symbol_table_name1!void                  0xca8ddc130832
  symbol_table_name1!_PS_CLIENT_SECURITY_CONTEXT (8 bytes) @ 0xda87585816e8:
    0x0 :   EffectiveOnly          symbol_table_name1!bitfield               offset: 0xda87585816e8
    0x0 :   ImpersonationData      symbol_table_name1!unsigned long long     0
    0x0 :   ImpersonationLevel     symbol_table_name1!bitfield               offset: 0xda87585816e8
    0x0 :   ImpersonationToken     *symbol_table_name1!void                  0x0 (null pointer)
  symbol_table_name1!_PS_CLIENT_SECURITY_CONTEXT (8 bytes) @ 0xda874f8ad6e8:
    0x0 :   EffectiveOnly          symbol_table_name1!bitfield               offset: 0xda874f8ad6e8
    0x0 :   ImpersonationData      symbol_table_name1!unsigned long long     0
    0x0 :   ImpersonationLevel     symbol_table_name1!bitfield               offset: 0xda874f8ad6e8
    0x0 :   ImpersonationToken     *symbol_table_name1!void                  0x0 (null pointer)
  ```

  There's only 1 thread that has `.ImpersonationToken` populated: 
  ```
  0x0 :   ImpersonationToken     *symbol_table_name1!void                  0xca8ddc130832
  ```

  If we unmask the pointer (`&~ 0xf`), the resulting address points exactly to the `_TOKEN` object we found above:

  ```python
  [layer_name]> token.vol.offset
  Out[8]: 222710631434288
  
  [layer_name]> 0xca8ddc130832 &~ 0xf
  Out[9]: 222710631434288
  ```

  We can filter based on that and print the `ThreadID`:

  ```python
  [layer_name]> for t in thread_list:
           ...:     if t.ClientSecurity.ImpersonationToken != 0:
           ...:         dt(t.Cid)
           ...:
  symbol_table_name1!_CLIENT_ID (16 bytes) @ 0xda87561356b8:
    0x0 :   UniqueProcess     *symbol_table_name1!void     0xd30 (unreadable pointer)
    0x8 :   UniqueThread      *symbol_table_name1!void     0x1368 (unreadable pointer)
  
  [layer_name]> 0x1368
  Out[11]: 4968
  ```
  
  **Answer:** <span style="color: #9FEF00;">`4968` </span>
  

7. **APT Napoleon used RBCD to backdoor DC02, what is the machine account name and SID that can impersonate users on DC02 (SAM Name:SID)**

  We can use [ntdissector](https://github.com/synacktiv/ntdissector) to parse the entire `NTDS.dit` as a database:

  ```bash
  ntdissector -ntds ntdsutil/Active\ Directory/ntds.dit -system ntdsutil/registry/SYSTEM -outputdir ./ntds_out -ts -f all                                                                                              [01:06:42]
  [2026-09-17 01:07:15] [*] PEK # 0 found and decrypted: 2e4a96eb1fa9bb0524e530776ab1058b
  [2026-09-17 01:07:15] [*] Filtering records with this list of object classes :  ['all']
  [2026-09-17 01:07:15] [*] Ignoring records marked as deleted
  100%|█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 4079/4079 [00:00<00:00, 10048.12rec./s]
  [2026-09-17 01:07:16] [*] Finished, matched 4022 records out of 4079
  [2026-09-17 01:07:16] [*] Processing 4022 serialization tasks
  100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 4022/4022 [00:09<00:00, 268.62rec./s]
  ```

  A Resource-Based Constrained Delegation modifies the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on the targeted Computer. We can use `jq` to easily explore the `json` files.

  ```bash
  $ jq -CS --arg a "msDS-AllowedToActOnBehalfOfOtherIdentity" 'select(has($a))' *.json
  
  {
    "accountExpires": 9223372036854775807,
    "badPasswordTime": "1601-01-01T00:00:00+00:00",
    "badPwdCount": 0,
    "cn": "DC02",
    "codePage": 0,
    "countryCode": 0,
    "dNSHostName": "dc02.core.diogenes.htb",
    "dSCorePropagationData": [
      "1601-01-01T00:00:01+00:00",
      "2026-09-08T21:25:38+00:00"
    ],
    "distinguishedName": "CN=DC02,OU=Domain Controllers,DC=core,DC=diogenes,DC=htb",
    "instanceType": 4,
    "isCriticalSystemObject": 1,
    "lastLogoff": "1601-01-01T00:00:00+00:00",
    "lastLogon": "2026-09-11T12:56:23.671484+00:00",
    "lastLogonTimestamp": "2026-09-08T21:26:24.405418+00:00",
    "localPolicyFlags": 0,
    "logonCount": 32,
    "msDFSR-ComputerReferenceBL": [
      "CN=DC02,CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,DC=core,DC=diogenes,DC=htb"
    ],
    "msDS-AllowedToActOnBehalfOfOtherIdentity": [
      "S-1-5-21-2253468260-689643353-167204612-1140"
    ],
  ```

  The `dNSHostName` of `dc02.core.diogenes.htb` means this computer (i.e. the DC) has been configured to accept _any_ identity that's coming from `S-1-5-21-2253468260-689643353-167204612-1140`. 

  In the same manner as above, let's search for that `SID`:

  ```bash
  $ jq --arg sid "S-1-5-21-2253468260-689643353-167204612-1140" 'select(.objectSid == $sid)' *.json
  
  {
    "dSCorePropagationData": "1601-01-01T00:00:00+00:00",
    "userAccountControl": "WORKSTATION_TRUST_ACCOUNT",
    "objectSid": "S-1-5-21-2253468260-689643353-167204612-1140",
    "isCriticalSystemObject": 0,
    "codePage": 0,
    "localPolicyFlags": 0,
    "supplementalCredentials": {
      "Primary:Kerberos-Newer-Keys": [
        "aes256-cts-hmac-sha1-96:f7b1f96af642e076639eb8e2ebf1e3c4dfa8c6be2e14a1e98f8ac3c6ad66d43c",
        "aes128-cts-hmac-sha1-96:8a8027c3d9145b988907cdb09e5a9a4d",
        "des-cbc-md5:b6c1978361404083"
      ],
      [...]
    "badPasswordTime": "1601-01-01T00:00:00+00:00",
    "lastLogonTimestamp": "2026-09-09T22:39:43.469685+00:00",
    "distinguishedName": "CN=svc_bkup,CN=Computers,DC=core,DC=diogenes,DC=htb",
    "sAMAccountName": "svc_bkup$",
    "sAMAccountType": "SAM_GROUP_OBJECT | SAM_NON_SECURITY_GROUP_OBJECT | SAM_ALIAS_OBJECT | SAM_NON_SECURITY_ALIAS_OBJECT | SAM_USER_OBJECT | SAM_NORMAL_USER_ACCOUNT | SAM_MACHINE_ACCOUNT | SAM_TRUST_ACCOUNT | SAM_APP_QUERY_GROUP | SAM_ACCOUNT_TYPE_MAX",
    "objectClass": [
      "computer",
      "user",
      "organizationalPerson",
      "person",
      "top"
    ],
    [...]
  ```

  The `SID` belongs to a Machine Account with the `SAM` Name of `svc_bkup$`.

  This can be done purely by examining the `Security.evtx` and looking for events `4741` (A computer account was created) and `4624` (An account was successfully logged on)

  **Answer:** <span style="color: #9FEF00;">`svc_bkup$:S-1-5-21-2253468260-689643353-167204612-1140` </span>
  

8. **What is the _ROOT_ domain SID?**

  ```bash
  jq -c 'select(.objectClass | index("domainDNS")) | select(has("objectSid"))                              [01:33:51]
              | {name, dn: .distinguishedName, sid: .objectSid, whenCreated}' *.json
  {"name":"core","dn":"DC=core,DC=diogenes,DC=htb","sid":"S-1-5-21-2253468260-689643353-167204612","whenCreated":"2026-09-08T21:22:25+00:00"}
  {"name":"diogenes","dn":"DC=diogenes,DC=htb","sid":"S-1-5-21-3066635835-107521988-671693545","whenCreated":"2026-09-08T21:08:10+00:00"}
  ```

  **Answer:** <span style="color: #9FEF00;">`S-1-5-21-3066635835-107521988-671693545` </span>

9. **The RBCD appears in exactly one event in DC02, What is the SubjectLogonId:LogonType of the session that performed the RBCD backdoor**

  We use `evtx_dump` to parse `Security.evtx` to a `json` file:

 ```bash
 $ evtx_dump -o jsonl C/Windows/System32/winevt/logs/Security.evtx > Security.jsonl

 jq -CS 'select(tostring | test("msDS-AllowedToActOnBehalfOfOtherIdentity"))' Security.jsonl
 {
   "Event": {
     "#attributes": {
       "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
     },
     "EventData": {
       "AppCorrelationID": "-",
       "AttributeLDAPDisplayName": "msDS-AllowedToActOnBehalfOfOtherIdentity",
       "AttributeSyntaxOID": "2.5.5.15",
       "AttributeValue": "Malformed Security Descriptor",
       "DSName": "core.diogenes.htb",
       "DSType": "%%14676",
       "ObjectClass": "computer",
       "ObjectDN": "CN=DC02,OU=Domain Controllers,DC=core,DC=diogenes,DC=htb",
       "ObjectGUID": "41EA452D-795E-403B-853F-2860CFC5D319",
       "OpCorrelationID": "1B68B066-7F30-4857-8BFC-04612BE86BB9",
       "OperationType": "%%14674",
       "SubjectDomainName": "DIOCORE",
       "SubjectLogonId": "0x3f213b",
       "SubjectUserName": "jreed",
       "SubjectUserSid": "S-1-5-21-2253468260-689643353-167204612-1123"
     }
   }
 }
 ```

 The LogonID is `0x3f213b`, now we have to find its `LogonType`:

 ```bash
 jq -r 'select(.Event.System.EventID==4624) | .Event.EventData | select(.TargetLogonId=="0x3f213b")' Security.jsonl
 
 {
   "SubjectUserSid": "S-1-0-0",
   "SubjectUserName": "-",
   "SubjectDomainName": "-",
   "SubjectLogonId": "0x0",
   "TargetUserSid": "S-1-5-21-2253468260-689643353-167204612-1123",
   "TargetUserName": "jreed",
   "TargetDomainName": "DIOCORE",
   "TargetLogonId": "0x3f213b",
   "LogonType": 3,
   "LogonProcessName": "NtLmSsp ",
   "AuthenticationPackageName": "NTLM",
   "WorkstationName": "-",
   "LogonGuid": "00000000-0000-0000-0000-000000000000",
   "TransmittedServices": "-",
   "LmPackageName": "NTLM V2",
   "KeyLength": 128,
   "ProcessId": "0x0",
   "ProcessName": "-",
   "IpAddress": "192.168.56.1",
   "IpPort": "35442",
   "ImpersonationLevel": "%%1833",
   "RestrictedAdminMode": "-",
   "TargetOutboundUserName": "-",
   "TargetOutboundDomainName": "-",
   "VirtualAccount": "%%1843",
   "TargetLinkedLogonId": "0x0",
   "ElevatedToken": "%%1842"
 }
 ```

  **Answer:** <span style="color: #9FEF00;">`0x3f213b:3` </span>

10. **The password attack involved two SubjectLogonIds that were neither the account owner, nor the administrator. One preparing, one resetting. Submit these LogonIDs (prepare:reset)**

  Since we know it was `jreed`'s password that was reset, let's look for event IDs of `4723` (An attempt was made to change an account's password)

  ```bash
  jq -r 'select(.Event.System.EventID==4723 and .Event.EventData.TargetUserName=="jreed")
         | [.Event.System.EventRecordID, .Event.EventData.SubjectUserName, .Event.EventData.SubjectLogonId]| @tsv' Security.jsonl
  37543	afenwick	0x17c569
  ```

  User `afenwick` tries to change the password on behalf of `jreed` <- This is our "reset" part

  Similarly, if we look for event IDs of `4738` (A user account was changed) we can clearly see the UPN modification from `afenwick` -> `jreed` and then the clear:

  ```bash
  jq -r 'select(.Event.System.EventID==4738 and .Event.EventData.TargetUserName=="afenwick"
                       and .Event.EventData.UserPrincipalName!="-")
         | [.Event.System.EventRecordID, .Event.EventData.SubjectLogonId, .Event.EventData.UserPrincipalName] | @tsv' Security.jsonl
  37539	0x17c514	jreed
  37541	0x17c514	%%1793
  ```

  `0x17c514` <- This is the prepare part
  
  We can also confirm this further by searching for logons (EID 4624) for LogonID `0x17c569`:

  ```bash
  jq -c 'select(.Event.System.EventID==4624 and .Event.EventData.TargetLogonId=="0x17c569")' Security.jsonl
  ```
  
  **Answer:** <span style="color: #9FEF00;">`0x17c514:0x17c569` </span>
