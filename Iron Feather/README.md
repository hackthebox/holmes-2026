<img src="./assets/banner.png" style="max-width: 100%; height: auto;" align=left />

# <center>Iron Feather Writeup</center>

-----------

2026-09-10

Prepared by: felamos, gordic

Sherlock Author(s): felamos, gordic

Difficulty: <font color="red">Hard</font>

## Description

```
Recover a drone's encrypted mission and flight log to investigate suspected command injection. Reconstruct the flight from takeoff and payload release to the crash and subsequent disarming.
```

## Artifacts Provided

`Iron_Feather.zip` contains the following evidence files:

- px4 - *1deea3e30984f30ed15d49800bba09b4c01bb85596937f979b9a5c85c9a3603b* (SHA-256)
- dataman.encrypted - *d302aa119f9d54389afc50a1b09961bfdbbcd47bbf3a435cad7e01eb8a63d7de* (SHA-256)
- flight.ulg.encrypted - *0439ba6421015a41ee277ff880a99b847f09d089100720f006eb32e08e90f4ca* (SHA-256)

## Skills Learnt

* Triage of unknown binary formats
* Reverse engineering stripped ELF binaries with radare2
* Finding code through string cross-references
* Reading optimized x86-64 calling conventions
* Reconstructing table-driven 32-bit mixing logic
* PBKDF2-HMAC-SHA256 and AES-256-GCM
* PX4 dataman and `mission_item_s` parsing
* QGroundControl waypoint reconstruction
* PX4 ULog triage and timeline correlation
* Comparing planned waypoints with recorded flight positions

## Initial Analysis

----------

Extract `Iron_Feather.zip` into a working directory. The archive contains three files and does not require a password. Run the subsequent commands from the extracted evidence directory:

```bash
unzip Iron_Feather.zip -d evidence
cd evidence
```

### Evidence Triage

PX4 is the aircraft's autopilot software. It reads sensors, follows navigation instructions, controls the motors, and communicates with a ground station. MAVLink is the protocol used for many of those messages. QGroundControl is a ground-station application that can upload missions to PX4.

This case uses PX4 SITL, meaning Software In The Loop. The autopilot runs as a Linux program connected to a simulator. The supplied `px4` executable is stripped: many function and variable names have been removed, so we must infer their roles from instructions, data, and references that remain.

The evidence files answer different parts of the investigation:

| Artifact | What it contains | What we can learn from it |
|---|---|---|
| `px4` | The autopilot executable | How this build derives its key and reads stored missions |
| `dataman.encrypted` | An encrypted copy of PX4's persistent datastore | Which mission was stored, including its waypoints and actions |
| `flight.ulg.encrypted` | An encrypted flight log | Recorded commands, positions, impact, and disarming after decryption |

`dataman` is the storage PX4 uses to retain information across restarts. It holds mission items, geographic boundaries, safe locations, and records describing which stored data is active. A mission item can be a waypoint or an action, such as changing speed or setting an actuator.

After decryption, `flight.ulg.encrypted` contains a ULog: timestamped measurements, commands, and status updates. We will correlate those records to reconstruct the flight and compare its outcome with the stored plan.

The investigation follows four steps:

1. Use `file`, `ls`, and a hex viewer to identify each artifact and its role.
2. Examine the firmware to learn how PX4 opens this modified dataman image.
3. Decrypt the datastore and parse its records to recover the planned mission.
4. Decrypt the ULog, reconstruct the flight timeline, and locate the crash site.

```bash
file px4 dataman.encrypted flight.ulg.encrypted
ls -lh px4 dataman.encrypted flight.ulg.encrypted
rabin2 -I px4
sha256sum px4 dataman.encrypted flight.ulg.encrypted
```

Compare the SHA-256 values with the artifact list above. On macOS, use `shasum -a 256` in place of `sha256sum`.

The executable is built for 64-bit x86 Linux and uses little-endian numbers, with the least significant byte stored first. The encrypted datastore is 1,208,588 bytes long. We begin with its header, then use what we find to locate the decryption code in the executable.

## Questions

----------
1. **What eight-byte ASCII magic identifies the encrypted datastore format? (string)**

	A file signature, also called a magic value, is a recognizable sequence of bytes that identifies a file format. Checking it tells us what kind of data we are handling and may give us a useful search term for the firmware.

	`xxd` shows the raw bytes on the left and their printable characters on the right. Read the first 60 bytes of `dataman.encrypted`:

	```bash
	xxd -g1 -l 60 dataman.encrypted
	```

	```text
	00000000: 50 58 34 44 4d 45 4e 43 01 00 00 00 d0 70 12 00  PX4DMENC.....p..
	00000010: 60 c2 00 30 9e 3f 46 4c 11 d1 46 45 a3 55 bf e8  `..0.?FL..FE.U..
	00000020: b9 2d e8 19 80 6c 6f 05 bb a4 4e b5 97 f3 d8 8e  .-...lo...N.....
	00000030: dd 1a 27 29 13 6d 2a b7 c0 17 e0 ad              ..').m*.....
	```

	The first eight bytes spell `PX4DMENC`. The remaining header contains the format version and encryption metadata. With the format identified, we can trace how the firmware decrypts it.

	**Answer:** <span style="color: #9FEF00;">`PX4DMENC`</span>

2. **Which authenticated encryption algorithm protects the datastore? (string)**

	To recover the stored mission, we need to reproduce the firmware's decryption process. Authenticated encryption checks the integrity of the data as well as decrypting it, so a successful result can also help verify our recovered key.

	The executable includes a large amount of OpenSSL code. A search for `AES` would find many routines that may have nothing to do with this datastore. A more useful starting point is an error message specific to loading the file:

	```bash
	rabin2 -zz px4 | grep -F 'invalid encrypted image header'
	```

	```text
	0x006edf00 ... invalid encrypted image header
	```

	Next, find the code that uses this error message. A cross-reference is a link from an instruction to the data or code it accesses. In radare2, `axt` lists the references to an address:

	```text
	$ r2 -AA px4
	[0x00000000]> axt @ 0x006edf00
	fcn.0016fe10 0x16ff4c [DATA:r--] movdqa xmm0, ...
	```

	The reference leads to the loader at `0x16fe10`. It opens the datastore, reads its 60-byte header, checks the signature and version, and prepares to decrypt the contents.

	```text
	[0x00000000]> s 0x16fe10
	[0x0016fe10]> pdf
	```

	After identifying the library routines, the relevant instructions can be annotated as follows. `EVP_aes_256_gcm` selects AES with a 256-bit key in GCM mode:

	```text
	0x0016ff1e  movabs rax, 0x434e454d44345850  ; "PX4DMENC"
	0x0016ff32  cmp dword [header+8], 1
	0x001700e0  call EVP_aes_256_gcm
	0x001700f2  call EVP_DecryptInit_ex
	0x001702ef  call EVP_DecryptUpdate
	0x00170333  call EVP_CIPHER_CTX_ctrl        ; set authentication tag
	0x00170351  call EVP_DecryptFinal_ex         ; verify the tag
	```

	The loader supplies four pieces of data to the decryption routine:

	| Data | Where it comes from | Purpose |
	|---|---|---|
	| Key | A custom function examined in Q3 | The 32 secret bytes needed to decrypt the image |
	| Nonce | 12 bytes at offset `0x20` | A value that must be unique for each encryption under the same key |
	| Authentication tag | 16 bytes at offset `0x2c` | Checks whether the key and authenticated data agree |
	| Ciphertext | Bytes from offset `0x3c` onward | The encrypted dataman contents |

	The first 44 header bytes are also authenticated as additional data. They stay readable, but changes to them cause authentication to fail.

	`EVP_DecryptFinal_ex` performs the final authentication check. We will use that check in Q6: a valid tag provides much stronger evidence of correct decryption than plaintext that merely looks plausible.

	**Answer:** <span style="color: #9FEF00;">`AES-256-GCM`</span>

3. **What is the virtual address of the custom key-derivation function? (hex number)**

	The loader needs a 32-byte AES key. A key-derivation function, or KDF, computes that key from other input. Our next task is to find where the loader obtains it.

	Start at `EVP_DecryptInit_ex` and trace the key buffer backward. The instructions show an earlier call that fills the buffer:

	```text
	0x0017008e  lea rax, [key_buffer]
	0x001700a6  mov rsi, rax
	0x001700c6  call 0x170af0
	0x001700cb  test al, al
	```

	That call takes two useful arguments:

	- A pointer to the 16-byte salt stored in the encrypted file's header.
	- A pointer to the 32-byte buffer that will receive the AES key.

	The loader checks whether the call succeeded before continuing with decryption. These inputs, output size, and later use of the output identify `0x170af0` as the key-derivation function.

	The answer is the function's address in the ELF image as displayed by the disassembler. It is not a byte offset in the file. Because this executable is position-independent, its address in a running process may include a different load base.

	```text
	[0x0016fe10]> s 0x170af0
	[0x00170af0]> afi
	size: 725
	num-instrs: 176
	```

	**Answer:** <span style="color: #9FEF00;">`0x170af0`</span>

4. **How many rounds are performed by the custom 32-bit mixing loop? (number)**

	The function starts with eight 32-bit integers and repeatedly changes their values using table lookups, addition, XOR, and bit rotations. One pass through these operations is a round. Reproducing the key requires performing exactly the same number of rounds as the firmware.

	We can establish the count before understanding every operation. Follow the round counter to the comparison that decides whether the loop runs again:

	```text
	0x00170c43  lea r14d, [rdx + 1]
	...
	0x00170c8b  cmp edx, 0x17f
	0x00170c91  jne 0x170ba0
	```

	`0x17f` is 383 in decimal. The first round has counter value 0, and the round with counter value 383 also runs. Therefore the total is `383 - 0 + 1 = 384`. Stopping after 383 rounds would produce a different key.

	The two lookup tables and the byte sequence that selects operations are stored in the executable. Dump them so the same values can be used in a recovery script:

	```text
	[0x00170af0]> pxw 128 @ 0x6f0b00  # first 32-word table
	[0x00170af0]> pxw 128 @ 0x6f0a80  # second 32-word table
	[0x00170af0]> px 48 @ 0x6f0a40    # routing program
	```

	The first words are:

	```text
	0x006f0b00  0xd7591353 0x3eb4a9f8 0x746b27a1 0x9c18fd42
	0x006f0a80  0x8a1e640b 0x57c39df2 0xe6102a7c 0x34b8f591
	```

	After establishing the loop count and locating its lookup data, follow how the function uses the mixed state to build the key-derivation input.

	**Answer:** <span style="color: #9FEF00;">`384`</span>

5. **Which standard KDF produces the AES key? (string)**

	The custom mixing loop produces intermediate material. The firmware then uses PBKDF2, a standard key-derivation algorithm, to turn that material and the file's salt into the final AES key.

	PBKDF2's result depends on its input bytes, salt, hash function, iteration count, and requested key length. All five must match the firmware. Here, the input is assembled from three parts:

	```text
	32 bytes  expanded state
	24 bytes  device record
	48 bytes  routing program
	---------
	104 bytes total
	```

	The 24-byte device record and the first 40 bytes of the routing sequence are stored together at `0x6edfa0`. The final eight routing bytes appear directly inside an instruction. Such a value is called an immediate:

	```text
	[0x00170af0]> px 64 @ 0x6edfa0
	[0x00170af0]> pd 20 @ 0x170d04
	
	0x00170d0c  movabs rax, 0x6fb14a9923de7508
	```

	The processor stores this number with its least significant byte first (little-endian). Its bytes are therefore `08 75 de 23 99 4a b1 6f`. Append those eight bytes to complete the 104-byte input.

	The call immediately afterward reveals the standard KDF and its parameters:

	```text
	0x00170d50  call EVP_sha256
	0x00170d57  mov r8d, 0x2000              ; iteration count
	0x00170d5d  mov rdi, r15                 ; 104-byte input
	0x00170d62  mov rdx, [salt_pointer]
	0x00170d6a  mov ecx, 0x10                ; 16-byte salt
	0x00170d6f  mov esi, 0x68                ; 104-byte input
	0x00170d74  call PKCS5_PBKDF2_HMAC
	```

	`EVP_sha256` selects SHA-256 for the HMAC operation used by PBKDF2. The call arguments specify:

	- Input length: `0x68`, or 104 bytes.
	- Salt length: `0x10`, or 16 bytes.
	- Iterations: `0x2000`, or 8,192.
	- Output length: 32 bytes, matching an AES-256 key.

	The KDF is PBKDF2-HMAC-SHA256. These parameters give us the final derivation step needed to reproduce the key.

	**Answer:** <span style="color: #9FEF00;">`PBKDF2-HMAC-SHA256`</span>

6. **What AES-256 key is derived for the supplied encrypted image? (64 lowercase hexadecimal characters)**

	We can now reproduce the key using the constants in `px4` and the salt in `dataman.encrypted`. The salt is an input to the derivation, so changing it would change the resulting key even if the firmware stayed the same.

	The main implementation trap is integer arithmetic. The firmware uses 32-bit values, so overflow discards bits above bit 31. Python integers keep growing unless we explicitly mask them with `0xffffffff`. Bit rotations must also operate on 32 bits. The loop below follows those rules:

	```python
	for round_number in range(384):
	    lane = round_number & 7
	    a = alpha[(round_number * 5 + state[(lane + 3) & 7]) & 31]
	    b = beta[(round_number * 11 + (state[(lane + 5) & 7] >> 27)) & 31]
	    opcode = routing[(round_number + (a >> 24)) % 48]
	    mixed = rol32(a ^ b ^ (0x9e3779b9 * (round_number + 1)),
	                  (opcode & 15) + 3)
	    state[lane] = rol32(state[lane] + mixed + opcode,
	                        ((b >> 27) & 15) + 5)
	    state[(lane + 2) & 7] ^= rol32(state[lane],
	                                   (round_number % 19) + 1)
	    state[(lane + 6) & 7] = (
	        state[(lane + 6) & 7]
	        + (state[(lane + 2) & 7] ^ (opcode * 0x01010101))
	    ) & 0xffffffff
	```

	The companion script, [solve_mission_vault.py](solve_mission_vault.py), implements the full recovery. It reads the constants from the supplied ELF, applies the final masks and PBKDF2 call, authenticates the datastore, and exports the mission. From the extracted `evidence` directory, run:

	```bash
	python3 -m venv .venv
	. .venv/bin/activate
	python3 -m pip install cryptography
	python3 ../solve_mission_vault.py dataman.encrypted --firmware px4 \
	    --plaintext dataman.decrypted -o mission.recovered.waypoints --show-key
	```

	```text
	GCM authentication: valid
	Mission items: 24
	Recovered route: mission.recovered.waypoints
	AES-256 key: a40ba87b8a0e21d4ead98b917c4bf0f60cc65b25c614b93f107e5ed1e483d6ce
	```

	Successful GCM authentication verifies that the derived key and authenticated image agree. The script saves the plaintext as `dataman.decrypted` and exports 24 mission items. We can now examine which bank is active and how its records describe the mission.

	**Answer:** <span style="color: #9FEF00;">`a40ba87b8a0e21d4ead98b917c4bf0f60cc65b25c614b93f107e5ed1e483d6ce`</span>

7. **Which of PX4's two mission banks is active? (number)**

	PX4 stores uploaded missions in one of two banks:

	- `DM_KEY_WAYPOINTS_OFFBOARD_0` is Bank 0.
	- `DM_KEY_WAYPOINTS_OFFBOARD_1` is Bank 1.

	When a new mission is uploaded over MAVLink, PX4 writes it to the inactive bank. Only after the upload finishes successfully does PX4 make that bank active. If the transfer is interrupted, the current mission remains untouched. This behaviour is implemented in PX4's [mission upload code](https://github.com/PX4/PX4-Autopilot/blob/main/src/modules/mavlink/mavlink_mission.cpp).

	In this context, **offboard** means that the mission came from an external system. It should not be confused with **Offboard flight mode**, where an external controller sends live setpoints to the vehicle.

	The mission-state record, stored under `DM_KEY_MISSION_STATE`, tells us which bank is active. Its `mission_dataman_id` field is authoritative; inspecting the banks for plausible coordinates is not, because the inactive bank may still contain an older mission.

	The numeric IDs assigned to the two banks depend on the PX4 version:

	| Layout | Bank 0 ID | Bank 1 ID |
	|---|---:|---:|
	| Supplied executable | 6 | 7 |
	| PX4 v1.14.0 | 2 | 3 |

	The difference is visible by comparing the enum definitions on PX4's [main branch](https://github.com/PX4/PX4-Autopilot/blob/main/src/modules/dataman/dataman.h) with those in [PX4 v1.14.0](https://github.com/PX4/PX4-Autopilot/blob/v1.14.0/src/modules/dataman/dataman.h). For this investigation, the values in the supplied executable are the ones that matter.

	On a running vehicle, `listener mission` would display `mission_dataman_id`. Here, we need to read it from the recovered datastore. The sections appear consecutively in `dataman.decrypted`:

	| Dataman section | Offset | Record size | Count |
	|---|---:|---:|---:|
	| Safe points 0 | 0 | 60 | 32 |
	| Safe points 1 | 1,920 | 60 | 32 |
	| Safe-point state | 3,840 | 12 | 1 |
	| Fence points 0 | 3,852 | 36 | 64 |
	| Fence points 1 | 6,156 | 36 | 64 |
	| Fence state | 8,460 | 12 | 1 |
	| Mission bank 0 | 8,472 | 60 | 10,000 |
	| Mission bank 1 | 608,472 | 60 | 10,000 |
	| Mission state | 1,208,472 | 44 | 1 |
	| Compatibility | 1,208,516 | 12 | 1 |

	Every dataman record begins with a four-byte storage header. The first byte contains the payload length. At offset `1,208,472`, it is 40 bytes, which matches the mission-state structure used by this build.

	Within the payload, `mission_dataman_id` is at offset `0x22`. Its absolute file offset is:

	`1,208,472 + 4 + 0x22 = 1,208,510`

	Read that byte directly:

	```bash
	xxd -g1 -s 1208510 -l 1 dataman.decrypted
	```

	```text
	001270be: 06                                               .
	```

	The value is `6`, which this executable maps to `DM_KEY_WAYPOINTS_OFFBOARD_0`. Therefore, **Bank 0 is active**, and its mission records begin at offset `8,472`.

	**Answer:** <span style="color: #9FEF00;">`0`</span>

8. **How many mission items are stored in the active bank? (number)**

	Now that we know where the active bank begins, we need its mission length.

	Each bank can hold 10,000 items, but that capacity does not tell us how many items are currently valid. Records from an older, longer mission may remain after a shorter mission is uploaded, so counting nonempty records can produce the wrong result.

	Instead, use the `count` field in the mission-state record. In this build, it is a little-endian 16-bit integer at payload offset `0x20`:

	```python
	import struct
	from pathlib import Path

	data = Path('dataman.decrypted').read_bytes()
	state_offset = 1_208_472
	mission_state = data[state_offset + 4:state_offset + 44]
	count = struct.unpack_from('<H', mission_state, 0x20)[0]
	print(count)
	```

	```text
	24
	```

	The active mission contains 24 items, numbered 0 through 23. We now have both values needed to parse it: Bank 0 starts at offset `8,472`, and only its first 24 records belong to the current mission.

	**Answer:** <span style="color: #9FEF00;">`24`</span>

9. **Which mission item triggers payload release? (number)**

	Each bank record has a four-byte storage header followed by a 56-byte `mission_item_s` payload. Mission items are numbered from 0 and may contain either navigation targets or actions:

	| Item offset | Type | Meaning |
	|---|---|---|
	| `0x00` | `double` | latitude |
	| `0x08` | `double` | longitude |
	| `0x10` | `float[7]` | command parameters/altitude union |
	| `0x2c` | `uint16` | MAVLink command ID |
	| `0x2e` | `int16` | jump target |
	| `0x30` | `uint16` | jump repeat count |
	| `0x32` | `uint16` | jump count or land precision |
	| `0x34` | `uint16` | packed frame and flags |

	The command ID tells PX4 what to do. The lowest four bits of the flags contain the MAVLink frame. In this mission, frame 2 marks action commands whose fields should be read as parameters, not plotted as coordinates.

	The relevant part of the mission contains two command 187 (`DO_SET_ACTUATOR`) records with a delay between them:

	| Sequence | Instruction | Relevant parameters |
	|---:|---|---|
	| 10 | Set the payload actuator | `p1=1`, `p7=0` |
	| 11 | Wait two seconds, `NAV_DELAY (93)` | `p1=2` |
	| 12 | Reset the payload actuator | `p1=0`, `p7=0` |

	Item 10 sets actuator 1, item 11 waits for two seconds, and item 12 resets the actuator. The first command is the release action. We can identify it by checking the command, frame, and parameters together:

	```python
	bank_offset = 8_472
	record_size = 60

	for sequence in range(count):
	    payload_offset = bank_offset + sequence * record_size + 4
	    item = data[payload_offset:payload_offset + 56]
	    params = struct.unpack_from('<7f', item, 0x10)
	    command = struct.unpack_from('<H', item, 0x2c)[0]
	    frame = struct.unpack_from('<H', item, 0x34)[0] & 0x0f

	    if command == 187 and frame == 2 and params[0] == 1 and params[6] == 0:
	        print(sequence)
	```

	```text
	10
	```

	The MAVLink command ID (`187`) identifies the type of instruction; `10` is its position in the mission. We will use the same command and parameter values when searching the flight log.

	**Answer:** <span style="color: #9FEF00;">`10`</span>

10. **Where was the drone supposed to land? (latitude,longitude; 5 decimal places)**

	The last mission item, sequence 23, is command 21 (`NAV_LAND`). It uses frame 3, so its latitude and longitude are global coordinates and its altitude is relative to the home position. Reading the coordinates and rounding both values to five decimal places gives `51.49970,-0.16080`.

	This is the planned landing point. The recovered mission, including its action commands, is shown below:

	| Seq | Command | Frame | Latitude | Longitude | Alt/P7 |
	|---:|---|---:|---:|---:|---:|
	| 0 | `NAV_TAKEOFF (22)` | 3 | 51.4997 | -0.1608 | 15 |
	| 1 | `DO_CHANGE_SPEED (178)` | 2 | 0 | 0 | 0 |
	| 2 | `NAV_WAYPOINT (16)` | 3 | 51.50005 | -0.1602 | 24 |
	| 3 | `NAV_WAYPOINT (16)` | 3 | 51.50085 | -0.15955 | 34 |
	| 4 | `NAV_WAYPOINT (16)` | 3 | 51.50185 | -0.1593999 | 38 |
	| 5 | `NAV_WAYPOINT (16)` | 3 | 51.50275 | -0.1597 | 36 |
	| 6 | `NAV_WAYPOINT (16)` | 3 | 51.50335 | -0.16005 | 26 |
	| 7 | `DO_CHANGE_SPEED (178)` | 2 | 0 | 0 | 0 |
	| 8 | `NAV_WAYPOINT (16)` | 3 | 51.50355 | -0.16045 | 12 |
	| 9 | `NAV_WAYPOINT (16)` | 3 | 51.5035598 | -0.1608362 | 2 |
	| 10 | `DO_SET_ACTUATOR (187)` | 2 | 0 | 0 | 0 |
	| 11 | `NAV_DELAY (93)` | 2 | 0 | 0 | 0 |
	| 12 | `DO_SET_ACTUATOR (187)` | 2 | 0 | 0 | 0 |
	| 13 | `DO_CHANGE_SPEED (178)` | 2 | 0 | 0 | 0 |
	| 14 | `NAV_WAYPOINT (16)` | 3 | 51.5036 | -0.1611 | 18 |
	| 15 | `NAV_WAYPOINT (16)` | 3 | 51.50358 | -0.16145 | 28 |
	| 16 | `NAV_WAYPOINT (16)` | 3 | 51.5032 | -0.1621 | 36 |
	| 17 | `NAV_WAYPOINT (16)` | 3 | 51.50235 | -0.16225 | 38 |
	| 18 | `NAV_WAYPOINT (16)` | 3 | 51.50145 | -0.16205 | 36 |
	| 19 | `NAV_WAYPOINT (16)` | 3 | 51.5007499 | -0.1616499 | 30 |
	| 20 | `NAV_WAYPOINT (16)` | 3 | 51.50035 | -0.1612 | 20 |
	| 21 | `DO_CHANGE_SPEED (178)` | 2 | 0 | 0 | 0 |
	| 22 | `NAV_WAYPOINT (16)` | 3 | 51.5001 | -0.16086 | 6 |
	| 23 | `NAV_LAND (21)` | 3 | 51.4997 | -0.1608 | 0 |

	The companion solver also exports these records in QGC WPL 110 format, which can be opened directly in QGroundControl. With the planned route reconstructed, we can turn to the flight log and see what actually happened.

	**Answer:** <span style="color: #9FEF00;">`51.49970,-0.16080`</span>

### Black-box investigation

The recovered mission tells us what the drone was supposed to do. To reconstruct the actual flight, we need the second encrypted artifact: `flight.ulg.encrypted`. Its header has the same layout as the datastore wrapper:

```bash
xxd -g1 -l 60 flight.ulg.encrypted
```

```text
00000000: 50 58 34 55 4c 45 4e 43 01 00 00 00 9b 3b 1a 04  PX4ULENC.....;..
00000010: 60 c2 00 30 9e 3f 46 4c 11 d1 46 45 a3 55 bf e8  `..0.?FL..FE.U..
00000020: aa d9 f2 86 e8 10 cb 84 90 b9 59 38 50 3c 3a 14  ..........Y8P<:.
00000030: bd 6d 28 9e c6 9d 8e 71 a5 3b 48 cd              .m(....q.;H.
```

The signature has changed to `PX4ULENC`, but the version, length, salt, nonce, tag, and ciphertext remain at the same offsets:

| Offset | Length | Field |
|---|---:|---|
| `0x00` | 8 bytes | Magic, `PX4ULENC` |
| `0x08` | 4 bytes | Version, little-endian |
| `0x0c` | 4 bytes | Plaintext size, little-endian |
| `0x10` | 16 bytes | KDF salt |
| `0x20` | 12 bytes | AES-GCM nonce |
| `0x2c` | 16 bytes | Authentication tag |
| `0x3c` | Remaining bytes | Ciphertext |

Both encrypted files use the salt `60c200309e3f464c11d14645a355bfe8`. Because the firmware constants and salt are unchanged, the derivation produces the same AES key. The nonce is different, as it should be for a separate AES-GCM message. A valid authentication tag will confirm that the key and header interpretation are correct.

With the virtual environment from Q6 still active, decrypt both artifacts in one run:

```bash
python3 ../solve_mission_vault.py dataman.encrypted --firmware px4 \
    --plaintext dataman.decrypted -o mission.recovered.waypoints --show-key \
    --ulog flight.ulg.encrypted --ulog-output flight.recovered.ulg
```

The solver authenticates the first 44 bytes of the header, decrypts the ciphertext, and writes the ULog only if tag verification succeeds. The recovered file is 68,828,059 bytes and has SHA-256 `2a4aa7193d325a36b327a97316c29a37596fa88b261f8b9ebdf650f364ec05ca`.

Install `pyulog`, inspect the log, and export the topics used in the remaining questions:

```bash
python3 -m pip install pyulog
ulog_info flight.recovered.ulg
ulog_messages flight.recovered.ulg
ulog2csv -m vehicle_status,vehicle_command,vehicle_command_ack,vehicle_global_position,vehicle_acceleration,vehicle_local_position,control_allocator_status \
    -o flight_csv flight.recovered.ulg
```

The recording covers 292.708 seconds and reports no dropouts. ULog timestamps are measured in microseconds after PX4 booted, not from the beginning of the recording. Divide a timestamp by 1,000,000 when an answer requires seconds after boot.

Each exported topic contributes a different part of the timeline:

| Topic | Evidence |
|---|---|
| `vehicle_status` | Takeoff time and the armed/disarmed state |
| `vehicle_command` | Payload actions and the injected motor failure |
| `vehicle_command_ack` | Whether PX4 accepted a command |
| `vehicle_global_position` | Estimated latitude and longitude |
| `vehicle_acceleration` | The impact spike |
| `vehicle_local_position` | Descent speed and ground distance |
| `control_allocator_status` | Motor-stop state after the failure |

The snippets below build on the following setup. Run them in the same Python session or place them, in order, in one script:

```python
from bisect import bisect_right
import numpy as np
from pyulog import ULog

log = ULog('flight.recovered.ulg', [
    'vehicle_status', 'vehicle_command', 'vehicle_command_ack',
    'vehicle_global_position', 'vehicle_acceleration', 'vehicle_local_position',
    'control_allocator_status'
])
global_position = log.get_dataset('vehicle_global_position').data

def sample_at_or_before(dataset, timestamp):
    index = bisect_right(dataset['timestamp'], timestamp) - 1
    if index < 0:
        raise ValueError('No sample exists before this event')
    return index

def coordinates_at(timestamp):
    index = sample_at_or_before(global_position, timestamp)
    latitude = global_position['lat'][index]
    longitude = global_position['lon'][index]
    return f"{latitude:.7f},{longitude:.7f}"
```

`vehicle_global_position` contains PX4's estimated position rather than an exact physical measurement. Seven decimal places are required for the answers, but they should not be mistaken for seven-decimal-place accuracy. For consistency, `coordinates_at()` always uses the final position sample at or before an event.

11. **Where did the drone take off? (latitude,longitude; 7 decimal places)**

	The `takeoff_time` field in `vehicle_status` records when PX4 detected takeoff. Extract the nonzero value and use the helper above to find the latest position available at that time:

	```python
	status = log.get_dataset('vehicle_status').data
	takeoff_times = np.unique(status['takeoff_time'][status['takeoff_time'] > 0])
	assert len(takeoff_times) == 1
	takeoff_time = int(takeoff_times[0])
	print(coordinates_at(takeoff_time))
	```

	PX4 detected takeoff at `287084000`. The nearest preceding position sample was recorded four milliseconds earlier, at `287080000`, and places the drone at `51.4996987,-0.1607999`. This is the recorded takeoff location, independent of the first waypoint in the mission plan.

	**Answer:** <span style="color: #9FEF00;">`51.4996987,-0.1607999`</span>

12. **Where was the drone when payload release was triggered? (latitude,longitude; 7 decimal places)**

	From Q9, the release action is command 187 with `param1=1` and `param7=0`. The later actuator reset uses the same command ID, so the parameters are needed to distinguish the two events:

	```python
	commands = log.get_dataset('vehicle_command').data
	release_rows = np.flatnonzero(
	    (commands['command'] == 187)
	    & (commands['param1'] == 1)
	    & (commands['param7'] == 0)
	)
	assert len(release_rows) == 1
	release_time = int(commands['timestamp'][release_rows[0]])
	print(coordinates_at(release_time))
	```

	The release command was recorded at `446656000`, with a position sample at the same timestamp. The drone was at `51.5035602,-0.1608417`. The reset command follows at `448672000`, roughly two seconds later, matching the delay in the mission.

	This gives the location where PX4 issued the release command. The log does not prove that a physical payload detached; that would require evidence from a release sensor, camera, or another external source.

	**Answer:** <span style="color: #9FEF00;">`51.5035602,-0.1608417`</span>

13. **Which MAVLink command was injected to bring down the drone? (string)**

	After the payload action, the drone begins following its return route. Shortly before it falls, the log records three related messages:

	```text
	520764000  [failure] inject failure unit: motor (101), type: off (1), instance: 0
	520764000  [failure_injection_manager] Injected: motor off, all instances
	520772000  [control_allocator] Stopping motors (4095)
	```

	At the same timestamp, `vehicle_command` records command ID 420. Its parameters describe the target and the injected failure:

	| Field | Value | Meaning |
	|---|---:|---|
	| `command` | 420 | `MAV_CMD_INJECT_FAILURE` |
	| `param1` | 101 | Motors |
	| `param2` | 1 | Off |
	| `param3` | 0 | All instances |

	According to the [MAVLink command definition](https://mavlink.io/en/messages/common.html#MAV_CMD_INJECT_FAILURE), these values request that all motor instances be switched off. Confirm the command and verify that PX4 accepted it:

	```python
	failure_rows = np.flatnonzero(
	    (commands['command'] == 420)
	    & (commands['param1'] == 101)
	    & (commands['param2'] == 1)
	    & (commands['param3'] == 0)
	)
	assert len(failure_rows) == 1
	failure_time = int(commands['timestamp'][failure_rows[0]])
	acks = log.get_dataset('vehicle_command_ack').data
	accepted = (
	    (acks['command'] == 420)
	    & (acks['timestamp'] == failure_time)
	    & (acks['result'] == 0)
	)
	assert np.any(accepted)
	print('MAV_CMD_INJECT_FAILURE')
	```

	PX4 returned an accepted acknowledgement. The command is not part of the recovered mission, and `control_allocator_status` subsequently reports `motor_stop_mask=4095`, meaning every motor output was stopped. Together, these records link `MAV_CMD_INJECT_FAILURE` to the loss of thrust and the fall. The available evidence does not identify who sent the command or how the link was intercepted.

	**Answer:** <span style="color: #9FEF00;">`MAV_CMD_INJECT_FAILURE`</span>

14. **How far did the drone travel between payload release and command injection? (horizontal metres, nearest whole number)**

	The release and failure commands give us the start and end timestamps. To measure the route flown between them, use the local-position coordinates, which are already expressed in metres.

	Select the last `vehicle_local_position` sample at or before each event, then add the horizontal distance between each consecutive pair of samples. Before doing so, confirm that the positions are valid and that PX4 did not reset the local coordinate frame during the interval:

	```python
	local = log.get_dataset('vehicle_local_position').data
	start = sample_at_or_before(local, release_time)
	end = sample_at_or_before(local, failure_time)
	assert 0 <= start < end

	window = slice(start, end + 1)
	assert np.all(local['xy_valid'][window])
	assert len(np.unique(local['xy_reset_counter'][window])) == 1

	x = local['x'][window].astype(float)
	y = local['y'][window].astype(float)
	segment_lengths = np.hypot(np.diff(x), np.diff(y))
	distance_travelled = segment_lengths.sum()
	print(f'{distance_travelled:.0f}')
	```

	The selected interval contains 9,264 samples, beginning at `446656000` and ending at `520760000`, four milliseconds before the failure command. Every sample is valid, and `xy_reset_counter` stays at 5, so all coordinates use the same local frame.

	The segments add up to approximately `276.711` metres, which rounds to **277 metres**. By comparison, the straight-line distance between the two endpoints is about `224.031` metres. The larger result is expected because the drone followed the mission route rather than flying directly between those points.

	Therefore, the drone travelled 277 horizontal metres after the release command and before the injected failure command.

	**Answer:** <span style="color: #9FEF00;">`277`</span>

15. **Where did the drone crash? (latitude,longitude; 7 decimal places)**

	The motor shutdown marks the beginning of the fall, not the impact itself. To locate the crash, follow the descent in `vehicle_local_position` and look for a sharp acceleration spike when the drone hits the ground.

	The [acceleration topic](https://docs.px4.io/main/en/msg_docs/VehicleAcceleration) stores three axes in metres per second squared. Calculate the vector magnitude for each sample, then find the largest value after the failure command:

	```python
	acceleration = log.get_dataset('vehicle_acceleration').data
	ax = acceleration['xyz[0]'].astype(float)
	ay = acceleration['xyz[1]'].astype(float)
	az = acceleration['xyz[2]'].astype(float)
	magnitude = np.sqrt(ax**2 + ay**2 + az**2)

	after_failure = np.flatnonzero(acceleration['timestamp'] > failure_time)
	assert len(after_failure) > 0
	peak = int(after_failure[np.argmax(magnitude[after_failure])])
	impact_time = int(acceleration['timestamp'][peak])
	print(coordinates_at(impact_time))
	```

	There is a single clear peak of approximately `562.442 m/s²` at `525860000`. The samples around it support treating this as the moment of impact:

	| Timestamp | Observation |
	|---:|---|
	| `525496000` | Downward velocity is about `9.738 m/s` |
	| `525860000` | Acceleration magnitude spikes to about `562.442 m/s²` |
	| `526000000` | Downward velocity is about `0.009 m/s`; valid ground distance is zero |

	The latest position before the spike was recorded four milliseconds earlier, at `525856000`. It places the drone at `51.5016938,-0.1620929`, well short of the planned landing point at `51.49970,-0.16080`.

	PX4's land detector does not return to the landed state until much later, after disarming. That delayed status change is not a reliable impact marker; the acceleration spike, halted descent, and zero ground distance all point to `525860000`.

	**Answer:** <span style="color: #9FEF00;">`51.5016938,-0.1620929`</span>

16. **When was the drone disarmed after the crash? (seconds after boot; 3 decimal places)**

	The drone remains armed after impact. Search the later `vehicle_status` records for the first transition from armed (`arming_state=2`) to disarmed (`arming_state=1`):

	```python
	disarm_rows = [
	    i for i in range(1, len(status['timestamp']))
	    if status['timestamp'][i] > impact_time
	    and status['arming_state'][i - 1] == 2
	    and status['arming_state'][i] == 1
	]
	assert len(disarm_rows) == 1
	disarm_time = int(status['timestamp'][disarm_rows[0]])
	print(f'{disarm_time / 1_000_000:.3f}')
	```

	The state changes at `576968000` microseconds, or `576.968` seconds after boot. The message `Disarmed by internal command` appears at the same timestamp. A force-disarm request was recorded 12 milliseconds earlier, at `576956000`, but the confirmed state transition is the correct event to report.

	Disarming is not the same as powering off. The log continues until `577968000`, one second after the state change, and an earlier `System does not support shutdown` message indicates that no shutdown time can be established from this log.

	**Answer:** <span style="color: #9FEF00;">`576.968`</span>

17. **Which road is closest to the crash site? (string)**

	Finally, plot the crash coordinates from Q15 (`51.5016938,-0.1620929`) on [OpenStreetMap](https://www.openstreetmap.org/?mlat=51.5016938&mlon=-0.1620929#map=19/51.5016938/-0.1620929).

	The nearest road is **Knightsbridge**. The adjacent [OpenStreetMap segment, way 744663874](https://www.openstreetmap.org/way/744663874), is tagged `name=Knightsbridge` and `ref=A315`. The question asks for the road name rather than its route number.

	This was verified on 2026-09-10 using both the reverse-geocoding result and the road geometry. Unlike the preceding answers, the road name comes from map data rather than the ULog itself.

	**Answer:** <span style="color: #9FEF00;">`Knightsbridge`</span>
