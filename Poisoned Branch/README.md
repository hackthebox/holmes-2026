<img src="./assets/banner.png" style="max-width: 100%; height: auto;" align=left />

# <center>Poisoned Branch</center>

-----------

<p align="center">
<img src="./assets/CosmicCorruption.png" style="max-width: 49%;"/>
</p>
2026-09-04

Prepared by: VivisGhost

Sherlock Author: VivisGhost

Difficulty: <font color="orange">Medium</font>

## Description

```
In this Sherlock, players will analyze a Linux UAC collection obtained from a compromised DIOGENES workstation. The investigation involves identifying a malicious Git repository, tracing attacker-delivered tooling, uncovering persistence, and determining what data the attacker targeted.

Careful analysis of local artifacts will also reveal links to attacker infrastructure, allowing players to build a clearer picture of the intrusion and its potential next steps.
```

## Scenario

```
Tom Ainsworth, an external contractor for DIOGENES, was assigned a routine maintenance task involving an internal application. 

While searching for a solution, he discovered a development repository that appeared to contain the code and documentation he needed. What should have been a routine clone quickly became something else.

Suspicious activity was later identified on Tom’s workstation, including unauthorized downloads, unusual scheduled activity, and potential access to sensitive files. 
Lead Command has authorized defensive action against the identified attacker infrastructure. Analyze the forensic evidence to determine how the compromise occurred and identify the attacker-controlled URL, credentials, and other relevant details. 

Once identified, use the attacker IP address provided with the spawnable VM and the malicious URL recovered during the investigation to access the attacker’s system and retrieve any information relevant to the operation.
```

## Artifacts Provided

* 361aea11a0cdd70e99def33c6ff28decfc5cb9c5642fdcb92570f26deebcfe1c PoisonedBranch.zip

## Skills Learnt

* Analyzing malicious repositories
* Reversing encrypted payloads
* Trace C2 communication
* Auditd to detect malicious commands
* Perform recon on attackers
* ZipCryto weaknesses

## Initial Analysis

----------

To begin the analysis, the password-protected ZIP file was unlocked using the password `hacktheblue`.

We see we have a uac collection and `Tom.zip`

![Screenshot 2026-09-13 at 8.34.15 AM](/Users/vivisghost/Desktop/Work/Walkthroughs/Poisoned_Branch_Official/assets/Screenshot 2026-09-13 at 8.34.15 AM.png)

We unzip `Tom.zip` and see the contents of the users home directory. It looks like we have to find a malicious repo, so the Projects folder might be a good place to start the search.

![Screenshot 2026-09-13 at 8.37.57 AM](/Users/vivisghost/Desktop/Work/Walkthroughs/Poisoned_Branch_Official/assets/Screenshot 2026-09-13 at 8.37.57 AM.png)




## Questions

----------
1. **What was the name of the malicious repository?**

	
	
	From the scenario and introduction analysis we are confident the protocol inside the UDP data is CFDP. 
	
	
	
	
	![Screenshot 2026-09-13 at 8.43.13 AM](/Users/vivisghost/Desktop/Work/Walkthroughs/Poisoned_Branch_Official/assets/Screenshot 2026-09-13 at 8.43.13 AM.png)
	
	
	
	![Screenshot 2026-09-13 at 8.58.52 AM](/Users/vivisghost/Desktop/Work/Walkthroughs/Poisoned_Branch_Official/assets/Screenshot 2026-09-13 at 8.58.52 AM.png)
	
	
	
	Looking around more we see the `validate_environment()` function from `telemetry.py`.
	
	
	
	![Screenshot 2026-09-13 at 9.00.34 AM](/Users/vivisghost/Desktop/Work/Walkthroughs/Poisoned_Branch_Official/assets/Screenshot 2026-09-13 at 9.00.34 AM.png)
	
	Looking at that file we immediately see a suspicious base64 string. We can take it to **CyberChef** and see the string changes the execution of a file then runs the file.
	
	
	
	![Screenshot 2026-09-13 at 9.08.32 AM](/Users/vivisghost/Desktop/Work/Walkthroughs/Poisoned_Branch_Official/assets/Screenshot 2026-09-13 at 9.08.32 AM.png)
	
	
	
	Back in the python script, we can see the file `reconstructed` is written from output of the `repeating` function with 2 inputs.
	
	![Screenshot 2026-09-13 at 9.01.40 AM](/Users/vivisghost/Desktop/Work/Walkthroughs/Poisoned_Branch_Official/assets/Screenshot 2026-09-13 at 9.01.40 AM.png)
	
	
	
	Moving to the `repeating` function we see it is basically a XOR function.
	
	![Screenshot 2026-09-13 at 9.02.07 AM](/Users/vivisghost/Desktop/Work/Walkthroughs/Poisoned_Branch_Official/assets/Screenshot 2026-09-13 at 9.02.07 AM.png)
	
	
	
	
	
	**Answer:** <span style="color: #9FEF00;">`diogenes-ticket-parser`</span>


2. **What is the email address listed for the author of the repo?**

	

	We look in the git logs to see if the attacker left any information behind in them. Here we can see a name and email address. 
	
	
	
	![Screenshot 2026-09-13 at 8.45.59 AM](./assets/Screenshot 2026-09-13 at 8.45.59 AM.png)
	
	
	
	**Answer:** <span style="color: #9FEF00;">`cbass.Moran@blackpearl2026.htb`</span>


3. **What file holds the encrypted payload?**

	

	From question 1 we began to get an idea of how the backdoor works, XORing 2 files; `Diogenes.jpg` and `calibration.bin`. We can bring `calibration.bin` into **CyberChef** and see it is encrypted. 
	
	
	
	![Screenshot 2026-09-13 at 9.05.32 AM](/Users/vivisghost/Desktop/Work/Walkthroughs/Poisoned_Branch_Official/assets/Screenshot 2026-09-13 at 9.05.32 AM.png)
	
	
	
	We can take the image, and cast it to HEX to use as the key.
	
	
	![Screenshot 2026-09-13 at 9.06.12 AM](/Users/vivisghost/Desktop/Work/Walkthroughs/Poisoned_Branch_Official/assets/Screenshot 2026-09-13 at 9.06.12 AM.png)
	
	
	
	Doing so we see the output begins with `ELF` which are the magic bytes for linux binaries. 
	
	
	
	
	![Screenshot 2026-09-13 at 9.05.51 AM](/Users/vivisghost/Desktop/Work/Walkthroughs/Poisoned_Branch_Official/assets/Screenshot 2026-09-13 at 9.05.51 AM.png)
	
	**Answer:** <span style="color: #9FEF00;">`calibration.bin`</span>


4. **What is the full path of the c2 implant?**

	
	
	We found the path in the previous answers. Now running strings on the file, we see it has a familiar string often seen in `meterpreter`.
	
	
	
	![Screenshot 2026-09-13 at 8.39.54 AM](/Users/vivisghost/Desktop/Work/Walkthroughs/Poisoned_Branch_Official/assets/Screenshot 2026-09-13 at 8.39.54 AM.png)
	
	
	
	
	**Answer:** <span style="color: #9FEF00;">`/home/Tom/.cache/.ticket-parser/.integrity`</span>


5. **What port did the implant connect back to?**

	
	
	To answer this question we can now turn to the uac output. UAC takes some recordings of the current state of the machine. In `live_response/network` we can view the `ss` output to get networking information. Below we can see the `.integrity` file established a connection to port `31337`.
	
	
	
	![Screenshot 2026-09-15 at 11.26.34 AM](/Users/vivisghost/Desktop/Work/Walkthroughs/Poisoned_Branch_Official/assets/Screenshot 2026-09-15 at 11.26.34 AM.png)
	
	
	
	**Answer:** <span style="color: #9FEF00;">`31337`</span>


6. **What is the pid of the implant?**

	
	
	We saw this answer in the previous question, we can also get more information about processes in `process`.
	
	
	
	![Screenshot 2026-09-15 at 11.23.43 AM](/Users/vivisghost/Desktop/Work/Walkthroughs/Poisoned_Branch_Official/assets/Screenshot 2026-09-15 at 11.23.43 AM.png)
	
	
	
	
	**Answer:** <span style="color: #9FEF00;">`1514`</span>


7. **The attacker tried to use URL:PORT before using IP:PORT to download a file to Tom's machine. What was the URL:PORT combo? (set the spawned vm IP to this URL in your /etc/hosts to complete the challenge)**

	
	
	
	
	To answer the next couple questions we can look at the **auditd** logs in `[root]/var/log/audi/auditd.log`.
	
	
	
	![Screenshot 2026-09-15 at 11.41.56 AM](/Users/vivisghost/Desktop/Work/Walkthroughs/Poisoned_Branch_Official/assets/Screenshot 2026-09-15 at 11.41.56 AM.png)
	
	
	
	`auditd` often contains the parameters in hex. We can take the value of a5 to **CyberChef** and see the attacker downloaded a public key to the victim.
	
	![Screenshot 2026-09-15 at 11.41.07 AM](/Users/vivisghost/Desktop/Work/Walkthroughs/Poisoned_Branch_Official/assets/Screenshot 2026-09-15 at 11.41.07 AM.png)
	
	
	
	We can see the same command ran again, this time with an IP being used instead of a PORT.
	
	![Screenshot 2026-09-15 at 11.38.16 AM](/Users/vivisghost/Desktop/Work/Walkthroughs/Poisoned_Branch_Official/assets/Screenshot 2026-09-15 at 11.38.16 AM.png)
	
	
	
	**Answer:** <span style="color: #9FEF00;">`BlackPearl2026.htb:9999`</span>
	
7. **What is the name of the Cookie/Token for the attackers web server?**

	
	
	a2 holds the information regarding the header and cookie. We can see the token in the **CyberChef** output below. Connection to the server is rejected if the token is not present.
	
	 
	
	![Screenshot 2026-09-15 at 11.46.45 AM](/Users/vivisghost/Desktop/Work/Walkthroughs/Poisoned_Branch_Official/assets/Screenshot 2026-09-15 at 11.46.45 AM.png)
	
	
	![Screenshot 2026-09-15 at 11.46.24 AM](/Users/vivisghost/Desktop/Work/Walkthroughs/Poisoned_Branch_Official/assets/Screenshot 2026-09-15 at 11.46.24 AM.png)
	
	
	
	
	
	**Answer:** <span style="color: #9FEF00;">`X-Operator-Auth=napoleon_moran_1894`</span>
	
7. **The attacker deleted a file before leaving. What command did they run?**

	
	
	Going back to `auditd` we can see the attacker ran `rm` to delete a `.pdf`.
	
	
	![Screenshot 2026-09-15 at 11.48.57 AM](/Users/vivisghost/Desktop/Work/Walkthroughs/Poisoned_Branch_Official/assets/Screenshot 2026-09-15 at 11.48.57 AM.png)
	
	
	
	
	
	**Answer:** <span style="color: #9FEF00;">`rm Gov_HR_Continuity_Emergency_Callout_Roster.pdf`</span>
	
7. **What was the ppid of the command from the previous question?**

	
	
	We can find the answer for this question from the previous screenshot, the paid is 1549. Now we know that, we can look now look at the parent process of `1549` and see in the image below, it is 1514, `.integrity`.
	
	
	
	![Screenshot 2026-09-15 at 11.52.02 AM](/Users/vivisghost/Desktop/Work/Walkthroughs/Poisoned_Branch_Official/assets/Screenshot 2026-09-15 at 11.52.02 AM.png)
	
	
	
	**Answer:** <span style="color: #9FEF00;">`1549`</span>
	
7. **While preparing the listener the attacker declared the architecture of the implant. What command did they use?**

	
	
	To answer this question we must get access to the attackers machine. First, we try the command they ran and see we also get a key back. This means the file server is still open!
	
	
	
	![Screenshot 2026-09-16 at 8.07.28 AM](./assets/Screenshot 2026-09-16 at 8.07.28 AM.png)
	
	
	
	We can try to get the attackers private key. This works too!
	
	![Screenshot 2026-09-16 at 8.09.13 AM](./assets/Screenshot 2026-09-16 at 8.09.13 AM.png)
	
	
	
	Now we can ssh in to the attackers machine. Let's enumerate.
	
	
	
	![Screenshot 2026-09-16 at 8.17.55 AM](./assets/Screenshot 2026-09-16 at 8.17.55 AM.png)
	
	
	
	The `.msf` directory holds the **Metasploit** database and some interesting log files:`history` and `meterpreter_history`. Looking into history we can see the commands the attacker ran after opening up **msfconsole**.
	
	
	
	![Screenshot 2026-09-16 at 8.18.31 AM](./assets/Screenshot 2026-09-16 at 8.18.31 AM.png)
	
	
	
	**Answer:** <span style="color: #9FEF00;">`set payload linux/x64/meterpreter_reverse_tcp`</span>
	
7. **The attacker attempted to locate a specific directory and file combo. What command did they run?**

	
	
	In `meterpreter_history` we can see the commands they ran in **meterpreter** after receiving the connection back.
	
	![Screenshot 2026-09-16 at 8.19.41 AM](./assets/Screenshot 2026-09-16 at 8.19.41 AM.png)
	
	
	
	
	
	**Answer:** <span style="color: #9FEF00;">`search -d ONBOARDING -f *.pdf`</span>
	
7. **What is the name of the file the attacker is keeping the exfiltrated documents in?**

	
	
	The attacker's home directory contains `Exfiltrated_Loot`. Looking in there we see a LOOT.zip, and in that zip is the file the attacker deleted from the victim, Tom's workstation.
	
	
	
	![Screenshot 2026-09-16 at 8.20.50 AM](./assets/Screenshot 2026-09-16 at 8.20.50 AM.png)
	
	
	
	**Answer:** <span style="color: #9FEF00;">`LOOT.zip`</span>
	
7. **What is the name of the person that has their position redacted?**

	
	
	The pdf has been deleted, we can search for the password the attacker used, try to brute force it, or see if we can open the zip with `bkcrack`. `bkcrack` is a tool that exploits `ZipCrypto` encryption. When files are put in a zip they can be compressed with store or deflate. 
	
	
	
	
	
	
	
	![Screenshot 2026-09-16 at 8.50.50 AM](./assets/Screenshot 2026-09-16 at 8.50.50 AM.png)
	
	
	
	The attack works because we have access to a plaintext file that is inside the encrypted zip, README.txt. First we run `bkcrack` and confirm the encryption type is `ZipCrypto`. In order to run the attack we will need to create a zip file with README.txt in it.
	
	
	
	![Screenshot 2026-09-16 at 9.37.56 AM](./assets/Screenshot 2026-09-16 at 9.37.56 AM.png)
	
	Once we have those 4 parts (the encrypted zip, the encrypted file, our new plaintext zip, the plaintext file) we can run bkcrack. 
	
	
	
	![Screenshot 2026-09-16 at 9.37.37 AM](./assets/Screenshot 2026-09-16 at 9.37.37 AM.png)
	
	
	
	It cracked, we can see the keys in the bottom of the previous screenshot. Now that we have the keys we can replicate the zip, with a password of our choosing, and open it.
	
	
	
	Lets look at some of the flags used for the next command. -C is again the encrypted zip, -U is the replicated zip with my password, ViviG is the password and -k are the keys from the previous screenshot.
	
	
	
	After we create the new zip, we unzip it and run file on the `.pdf` showing we can now open it. 
	
	
	
	![Screenshot 2026-09-16 at 9.50.52 AM](./assets/Screenshot 2026-09-16 at 9.50.52 AM.png)
	
	
	
	Once we open the zip file we find the pdf. There is one user with redacted information `Sarah Kemp`.
	
	
	
	![Screenshot 2026-09-15 at 11.57.10 AM](/Users/vivisghost/Desktop/Work/Walkthroughs/Poisoned_Branch_Official/assets/Screenshot 2026-09-15 at 11.57.10 AM.png)
	
	
	**Answer:** <span style="color: #9FEF00;">`Sarah Kemp`</span>
	
7. **What is the address of the previously identified person?**

	
	We can also see their address in the previous screenshot.
	
	
	
	**Answer:** <span style="color: #9FEF00;">`Flat 6, Ashdown House, Palace Court, London W2 4LS`</span>
	
	

