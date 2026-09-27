# Silent Passenger — organizer-only screenshot plan

This file is an organizer capture checklist, not analyst evidence. Do not place it
in the downloadable case artifact. Capture the images only after repeating the
published solution from a clean analyst working directory containing the one
firmware ZIP and the spawned target IP.

The smallest sensible set is ten real screenshots. Each image below must be a
screen capture of the named terminal/source view produced during that clean
solve. Do not render a mock terminal, paste expected output over an image, or
fabricate packet rows. Cropping and removal of unrelated desktop chrome are
fine; altering evidence text is not.

## Capture rules

1. Never install, launch, or dynamically load an APK, JAR, DEX, or `.io` file.
   Python snippets in the solution operate on inert bytes only.
2. Never resolve or contact an evidence-derived or historical hostname. In the
   screenshots, MQTT must use the spawned numeric IP directly. Every HTTP
   request must visibly include both `--noproxy '*'` and
   `--resolve "<host>:80:$LAB_IP"`.
3. Replace the value below with the actual dotted-decimal address shown by the
   spawned instance. Run the validation and print it in every screenshot that
   contains a network interaction:

   ```sh
   export LAB_IP='<replace with the spawned numeric IPv4>'
   test "$(python3 -c 'import ipaddress,sys; print(ipaddress.IPv4Address(sys.argv[1]))' "$LAB_IP")" = "$LAB_IP"
   printf 'Spawned numeric IP: %s\n' "$LAB_IP"
   ```

4. Use `set -x` immediately around a network command so the captured terminal
   shows the expanded numeric IP; use `set +x` immediately afterward. Do not
   show shell history from unrelated work.
5. Any packet capture must use a kernel capture filter beginning with
   `host $LAB_IP`. A Wireshark GUI display filter must contain the literal
   spawned IP, not a historical hostname.
6. Use the paths created by the public writeup (`twcore-jadx`,
   `jarservice-jadx`, `loader-jadx`, `stage3-jadx`, and `sh66-jadx`). Do not
   expose organizer audit paths, internal fixtures, source repositories, or
   unrelated samples.
7. Save the real PNGs beneath `assets/screenshots/` with the exact filenames
   below. A split terminal/editor layout is still one screenshot when all panes
   are simultaneously visible and legible.

## Coverage map

| Questions | Screenshot |
| --- | --- |
| Q1 | `01-firmware-twcore.png` |
| Q2–Q4 | `02-twcore-mqtt-static.png` |
| Q5 | `03-retained-command-jarservice.png` |
| Q6–Q8 | `04-jarservice-loader-recovery.png` |
| Q9–Q10 | `05-loader-token-response.png` |
| Q11–Q12 | `06-stage3-wrapper-target.png` |
| Q13–Q14 | `07-registration-task.png` |
| Q15–Q16 | `08-dispatcher-sh66.png` |
| Q17–Q19 | `09-sh66-abi-roles-auth.png` |
| Q20 | `10-sh66-relay-location.png` |

Every question appears exactly once in this primary mapping. A screenshot may
show prerequisite evidence for an adjacent question, but its caption should
retain the mapping above.

## 01 — firmware and privileged implant

**Filename:** `assets/screenshots/01-firmware-twcore.png`  
**Covers:** Q1  
**Layout:** one terminal, with the archive identity at the top and the extracted
APK identity at the bottom.

From the clean analyst directory, run the writeup's concatenation and truncation
steps first, then capture this compact verification view:

```sh
export FIRMWARE='firmware.zip'
sha256sum "$FIRMWARE"
unzip -l "$FIRMWARE"
file system.img
debugfs -R 'ls -l /priv-app/TWCore' system.img
debugfs -R 'dump /priv-app/TWCore/TWCore.apk TWCore.apk' system.img
stat -c '%s bytes  %n' TWCore.apk
md5sum TWCore.apk
sha256sum TWCore.apk
apkanalyzer manifest application-id TWCore.apk
apkanalyzer manifest version-name TWCore.apk
apkanalyzer manifest version-code TWCore.apk
```

Keep the `debugfs` filesystem path and the SHA-256 visible in the same frame.

**Caption:** “Q1 — Static extraction from the split ext4 system image identifies
`/system/priv-app/TWCore/TWCore.apk` and verifies its exact SHA-256; no firmware
or APK was booted.”

## 02 — TWCore branch, MQTT identity, and subscription

**Filename:** `assets/screenshots/02-twcore-mqtt-static.png`  
**Covers:** Q2, Q3, Q4  
**Layout:** three tiled source/terminal panes: predicate, connection identity,
and subscription construction.

Use the real JADX output and show line numbers plus surrounding control flow:

```sh
rg -n -C 8 'gh\(|zh_CN|ro\.com\.google\.gmsversion' \
  twcore-jadx/sources/com/tw/core/b/e.java \
  twcore-jadx/sources/com/tw/core/utils/I.java

rg -n -C 8 'mqtt\.car\.cardoor\.cn|tcp://|1883' \
  twcore-jadx/sources/com/tw/core/d/a.java
rg -n -C 8 'dofun|dofun666666|setUserName|setPassword' \
  twcore-jadx/sources/com/tw/core/h/b.java

rg -n -C 8 'dofun/car/config|dofun/car/private|subscribe' \
  twcore-jadx/sources/com/tw/core/app/a.java \
  twcore-jadx/sources/com/tw/core/model/MainService.java
```

If a JADX identifier differs slightly, open those same files in the JADX GUI at
the predicate, `MqttConnectOptions`, and `subscribe` call sites. Do not replace
the code view with a handwritten summary.

**Caption:** “Q2–Q4 — TWCore's static mainland predicate, production MQTT broker
and credentials, and the device-independent `dofun/car/config/#` subscription
are recovered from the APK.”

## 03 — retained `0500` command and JarService identity

**Filename:** `assets/screenshots/03-retained-command-jarservice.png`  
**Covers:** Q5  
**Layout:** two terminals. The left pane shows the numeric-IP MQTT retrieval and
decoded fixed-width record. The right pane shows the hostname-pinned APK fetch
and its identity.

Left pane:

```sh
printf 'Spawned numeric IP: %s\n' "$LAB_IP"
set -x
mosquitto_sub \
  -h "$LAB_IP" -p 1883 -V mqttv311 \
  -u dofun -P dofun666666 \
  -t 'dofun/car/config/#' -C 1 > retained-command.txt
set +x
python3 decode_0500.py
jq . command.json
```

Right pane:

```sh
OTA_URL="$(jq -r '.path' command.json)"
OTA_HOST="$(python3 -c 'import sys,urllib.parse; print(urllib.parse.urlsplit(sys.argv[1]).hostname)' "$OTA_URL")"
printf 'Spawned numeric IP: %s\n' "$LAB_IP"
set -x
curl --fail --silent --show-error --noproxy '*' \
  --resolve "$OTA_HOST:80:$LAB_IP" \
  "$OTA_URL" -o JarService.apk
set +x
stat -c '%s bytes  %n' JarService.apk
md5sum JarService.apk
sha256sum JarService.apk
apkanalyzer manifest application-id JarService.apk
apkanalyzer manifest version-code JarService.apk
```

The expanded numeric `-h` value and expanded numeric `--resolve` mapping must
both be visible. The decoded package, flag, and key must be readable.

**Caption:** “Q5 — One retained MQTT value from the spawned numeric IP decodes
as the `0500` application-update record, and the pinned lab download verifies
JarService as `com.tw.jar1`, flag/version code 12, with the matching MD5.”

## 04 — JarService reflection and exact loader recovery

**Filename:** `assets/screenshots/04-jarservice-loader-recovery.png`  
**Covers:** Q6, Q7, Q8  
**Layout:** three panes: outer reflection/channel source, reconstruction output,
and loader fallback-version source/decoding.

Pane 1, use actual JarService code views:

```sh
rg -n -C 10 'beed72|80|85|86|93|2039' \
  jarservice-jadx/sources/com/p000x/zg/ifz.java
rg -n -C 10 'Class\.forName|getDeclaredMethod|invoke|com\.c\.j\.qbh|wa' \
  jarservice-jadx/sources/com/p000x/zg/RunnableC0002b.java
```

Pane 2, reconstruct from apktool's declared arrays and display the real result:

```sh
python3 recover_loader.py
unzip -t loader-v1.7.jar
```

The pane must visibly include the 25-byte header, entry point, output size, and
SHA-256 printed by `recover_loader.py`.

Pane 3, retain the loader call site and decode the static literal without
loading the JAR:

```sh
rg -n -C 10 '\.ver|readLine|:7@|dexVersion' \
  loader-jadx/sources/com/p000c/p001j/C0012m.java
python3 - <<'PY'
print('loader fallback =', ''.join(chr(ord(c) - 9) for c in ':7@'))
PY
```

**Caption:** “Q6–Q8 — JarService reconstructs
`com.c.j.qbh.wa(..., "2039")`; its thirty inert byte arrays yield the exact
loader SHA-256, whose own missing-`.ver` fallback is 1.7 rather than the outer
1.2 metadata value.”

## 05 — loader token and decrypted update response

**Filename:** `assets/screenshots/05-loader-token-response.png`  
**Covers:** Q9, Q10  
**Layout:** two terminals. The left shows the static literal reversal and token
generator. The right shows the real lab POST and decrypted JSON.

Left pane:

```sh
rg -n -C 10 '0bqj0stbVqebuf|Rzc8=\^ijt788Zt\|i|5gvo\|85|m42a|m43a|m44b' \
  loader-jadx/sources/com/p000c/p001j/C0012m.java \
  loader-jadx/sources/com/p000c/p001j/C0013n.java
python3 - <<'PY'
def unshift(value, amount):
    return ''.join(chr(ord(char) - amount) for char in value)
print('inner plaintext =', unshift('0bqj0stbVqebuf', 1))
print('outer XOR key   =', unshift('Rzc8=^ijt788Zt|i', 5))
PY
TOKEN="$(python3 make_loader_token.py)"
printf 'token length = %s\n' "${#TOKEN}"
```

Right pane:

```sh
python3 rsa_blocks.py encrypt \
  loader-request-public.der loader-request.json loader-request.bin
UPDATE_HOST='a1.xshaon123.sbs'
printf 'Spawned numeric IP: %s\n' "$LAB_IP"
set -x
curl --fail --silent --show-error --noproxy '*' \
  --resolve "$UPDATE_HOST:80:$LAB_IP" \
  -H 'Content-Type:' -H 'Expect:' \
  --data-binary @loader-request.bin \
  "http://$UPDATE_HOST/apiv2/$TOKEN" \
  -o loader-response.bin
set +x
python3 rsa_blocks.py decrypt \
  loader-response-private.der loader-response.bin loader-response.json
jq . loader-response.json
```

Keep the expanded numeric `--resolve` argument, the 90-character token length,
and the decrypted `/vr34der34/dex3.68.png` path visible.

**Caption:** “Q9–Q10 — Static reversal recovers `/api/rsaUpdate`; an authentic
RSA request sent only to the spawned IP decrypts to the selected Stage-3 3.68
wrapper path.”

## 06 — Stage-3 wrapper and exact initial target

**Filename:** `assets/screenshots/06-stage3-wrapper-target.png`  
**Covers:** Q11, Q12  
**Layout:** two panes. The left shows the pinned wrapper acquisition and local
decode. The right shows the real Stage-3 string fragments and reconstruction.

Left pane:

```sh
DEX_URL="$(jq -r '.data.dexUrl' loader-response.json)"
DEX_HOST="$(python3 -c 'import sys,urllib.parse; print(urllib.parse.urlsplit(sys.argv[1]).hostname)' "$DEX_URL")"
printf 'Spawned numeric IP: %s\n' "$LAB_IP"
set -x
curl --fail --silent --show-error --noproxy '*' \
  --resolve "$DEX_HOST:80:$LAB_IP" \
  "$DEX_URL" -o stage3.wrapper
set +x
stat -c '%s bytes  %n' stage3.wrapper
sha256sum stage3.wrapper
python3 decode_stage3.py
unzip -t stage3-v3.68.jar
```

Right pane:

```sh
rg -n -C 8 '1crk1kpkvAeqphkiXgtukqp\?|50:|configVersion' \
  stage3-jadx/sources/com/a/b/a/am.java \
  stage3-jadx/sources/com/a/b/a/ap.java
rg -n -C 8 '\*vweA5\*glerripMhA|channelId' \
  stage3-jadx/sources/com/ast/sdk/a.java
python3 - <<'PY'
def unshift(value, amount):
    return ''.join(chr(ord(char) - amount) for char in value)
target = (
    unshift('1crk1kpkvAeqphkiXgtukqp?', 2)
    + unshift('50:', 2)
    + unshift('*vweA5*glerripMhA', 4)
    + '2039'
)
print(target)
PY
```

**Caption:** “Q11–Q12 — The five-byte wrapper decodes locally to the exact
Stage-3 JAR hash, while its own static string construction yields
`/api/init?configVersion=3.8&rsa=1&channelId=2039`.”

## 07 — registration UID and encrypted task

**Filename:** `assets/screenshots/07-registration-task.png`  
**Covers:** Q13, Q14  
**Layout:** two terminals. The left contains configuration plus plaintext
registration; the right contains the RSA task exchange and decrypted task.

Left pane:

```sh
CONFIG_HOST='a1.xshaon123.sbs'
CONFIG_TARGET='/api/init?configVersion=3.8&rsa=1&channelId=2039'
printf 'Spawned numeric IP: %s\n' "$LAB_IP"
set -x
curl --fail --silent --show-error --noproxy '*' \
  --resolve "$CONFIG_HOST:80:$LAB_IP" \
  "http://$CONFIG_HOST$CONFIG_TARGET" \
  -o stage3-config.bin
set +x
python3 rsa_blocks.py decrypt \
  stage3-response-private.der stage3-config.bin stage3-config.json
C2_URL="$(jq -r '.data.hosts[0]' stage3-config.json)"
C2_HOST="$(python3 -c 'import sys,urllib.parse; print(urllib.parse.urlsplit(sys.argv[1]).hostname)' "$C2_URL")"
set -x
curl --fail --silent --show-error --noproxy '*' \
  --resolve "$C2_HOST:80:$LAB_IP" \
  "http://$C2_HOST/cpc/api/proxy/origin" \
  -o registration.json
set +x
jq . registration.json
```

Right pane, after creating the inert request JSON exactly as in the writeup:

```sh
python3 rsa_blocks.py encrypt \
  stage3-request-public.der stage3-task-request.json stage3-task-request.bin
printf 'Spawned numeric IP: %s\n' "$LAB_IP"
set -x
curl --fail --silent --show-error --noproxy '*' \
  --resolve "$C2_HOST:80:$LAB_IP" \
  -H 'Content-Type: application/octet-stream' -H 'Expect:' \
  --data-binary @stage3-task-request.bin \
  "http://$C2_HOST/cpc/api/task" \
  -o stage3-task-response.bin
set +x
python3 rsa_blocks.py decrypt \
  stage3-response-private.der stage3-task-response.bin stage3-task-response.json
jq . stage3-task-response.json
```

The left output must show UID `00005bp`; the right output must show product,
task, and version fields together. Both traced curl commands must show the same
spawned numeric destination.

**Caption:** “Q13–Q14 — Hostnames recovered from the encrypted configuration
remain pinned to the spawned IP: registration returns UID `00005bp`, and the
two-block task response decrypts to the selected product/task/version tuple.”

## 08 — active dispatcher and sh66 identity

**Filename:** `assets/screenshots/08-dispatcher-sh66.png`  
**Covers:** Q15, Q16  
**Layout:** two terminals. The left shows the pinned XML-route fetch and nested
JSON parse; the right shows the active URL fetch and module hashes.

Left pane:

```sh
printf 'Spawned numeric IP: %s\n' "$LAB_IP"
set -x
curl --fail --silent --show-error --noproxy '*' \
  --resolve "$C2_HOST:80:$LAB_IP" \
  "http://$C2_HOST/cpc/api/xml?productId=4532" \
  -o stage3-xml.json
set +x
python3 parse_script.py
```

In an adjacent source tab, keep the Stage-3 dispatcher branch visible so the
`loadlib2`/`url` selection is code-backed rather than inferred only from the
fixture:

```sh
rg -n -C 10 'qtfiqng7|bn\.class' \
  stage3-jadx/sources/com/a/b/a/cf.java
rg -n -C 10 'vsm|bnVar\.i|r\.a\(bnVar\.i' \
  stage3-jadx/sources/com/a/b/a/bn.java
python3 - <<'PY'
def unshift(value, amount):
    return ''.join(chr(ord(char) - amount) for char in value)
print('dispatcher =', unshift('qtfiqng7', 5))
print('field      =', unshift('vsm', 1))
PY
```

Right pane:

```sh
MODULE_URL="$(jq -r '.url' module-script.json)"
MODULE_HOST="$(python3 -c 'import sys,urllib.parse; print(urllib.parse.urlsplit(sys.argv[1]).hostname)' "$MODULE_URL")"
printf 'Spawned numeric IP: %s\n' "$LAB_IP"
set -x
curl --fail --silent --show-error --noproxy '*' \
  --resolve "$MODULE_HOST:80:$LAB_IP" \
  "$MODULE_URL" -o sh66.io
set +x
stat -c '%s bytes  %n' sh66.io
md5sum sh66.io
sha256sum sh66.io
```

**Caption:** “Q15–Q16 — The Stage-3 dispatcher proves that `loadlib2` consumes
`url`; fetching only that URL through the spawned numeric IP produces the exact
sh66 SHA-256.”

## 09 — sh66 ABI, parameter roles, and authentication frame

**Filename:** `assets/screenshots/09-sh66-abi-roles-auth.png`  
**Covers:** Q17, Q18, Q19  
**Layout:** a 2×2 terminal/source grid: descriptor, argument flow, heartbeat/UDP
flow, and local frame construction.

Descriptor and entry-point panes:

```sh
rg -n -C 6 'com\.miyc\.transfer\.Client|start|Landroid/content/Context' \
  sh66-dexdump.txt
rg -n -C 8 'static.*start|Client|new b|9999|7777|8888|20000' \
  sh66-jadx/sources/com/miyc/transfer/Client.java \
  sh66-jadx/sources/com/miyc/transfer/b.java
jq '.params' module-script.json
```

Socket/timer pane:

```sh
rg -n -C 8 'InetSocketAddress|this\.b|this\.c|this\.d|Thread\.sleep|8888' \
  sh66-jadx/sources/com/miyc/transfer/a.java \
  sh66-jadx/sources/com/miyc/transfer/e.java \
  sh66-jadx/sources/com/miyc/transfer/f.java \
  sh66-jadx/sources/com/miyc/transfer/g.java \
  sh66-jadx/sources/com/miyc/transfer/a/m.java
```

Authentication pane:

```sh
python3 - <<'PY'
import struct
uid = b'00005bp'
frame = b'\x33' + struct.pack('>II', 66, len(uid)) + uid
print('length =', len(frame))
print('hex    =', frame.hex())
PY
```

Keep the exact DEX descriptor, all four integer values and roles, and the 16-byte output
visible. Do not run `Client.start`.

**Caption:** “Q17–Q19 — DEX metadata fixes the reflective ABI; static socket and
timer flow maps 9999/7777/8888/20000 to command/data/UDP-relay/heartbeat roles;
local serialization yields the exact primary authentication frame.”

## 10 - sh66 relay-enrollment location

**Filename:** `assets/screenshots/10-sh66-relay-location.png`  
**Covers:** Q20  
**Layout:** one terminal showing the authenticated command frame followed by
the HTTP proxy task recovered from the token-correlated data channel.

```sh
LAB_IP="$SPAWN_IP" python3 - <<'PY'
import os
import socket

def take(sock, size):
    data = b""
    while len(data) < size:
        data += sock.recv(size - len(data))
    return data

host = os.environ["LAB_IP"]
with socket.create_connection((host, 9999)) as command:
    command.sendall(bytes.fromhex("33000000420000000730303030356270"))
    frame = take(command, 17)
    print("command:", frame.hex())
    assert frame[0] == 0x30
    with socket.create_connection((host, 7777)) as data:
        data.sendall(frame[1:5])
        request = b""
        while not request.endswith(b"\r\n\r\n"):
            request += data.recv(512)
        print(request.decode())
        data.sendall(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
PY
```

Keep the `0x30` command frame, relay UID, `drone-control` role, and both
coordinate fields visible.

**Caption:** "Q20 - The authenticated sh66 data channel exposes operator
tasking that enrolls the compromised vehicle as a drone-control relay and
records its parked location."

## Final organizer check

Before attaching the images to the submitted solution, confirm all of the
following:

- there are exactly ten PNGs and every filename matches this plan;
- each screenshot is from the clean analyst path and contains real command or
  source output;
- screenshots 03, 05, 06, 07, 08, and 10 visibly show the spawned numeric IP;
- every shown HTTP request includes `--noproxy '*'` and numeric `--resolve`;
- the MQTT client uses only numeric `-h "$LAB_IP"`;
- the sole pcap was captured with `host $LAB_IP` and passes both checks above;
- no malware sample was executed and no historical hostname was resolved; and
- no organizer-only path, private terminal history, token, or unrelated host
  data appears in the crop.
