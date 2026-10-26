# Plaud Note Pro: how the app pulls recordings

Source: `PLAUD_release.apk`, package `ai.plaud.android.plaud`, version 4.0.2 (build 1278), SHA-256 `107053b8…5c32`. Analysed with rea 6.7.0 (`identify-flutter-build`, `inspect-dart-aot`, `inspect-android-package`, `search-android-classes`) and a full JADX 1.5 decompile. Class names below are the obfuscated JADX names in that build. They change between app versions.

## Summary

There are two ways to get the audio.

| Path | Works for Note Pro? | What you need | Script |
|---|---|---|---|
| Plaud cloud API | Yes, for any recording the app has uploaded | Your account bearer token | `plaud_cloud_pull.py` |
| Direct BLE | Only on firmware with the plain protocol | Your bind token (= your `user_id`) | `plaud_ble_pull.py` |

The direct BLE path has a blocker for newer firmware. When the device reports protocol version 30, the app runs an ECDH session (P-256) and encrypts every packet with AES-GCM or ChaCha20-Poly1305. The keys for reconnect come from the Plaud cloud (`/device-app/device/apply-token`, `/device-app/device/sn-sign`). I could not tell from the APK which protocol version a Note Pro ships with. The BLE script detects the ECC start packet and stops.

The app is native Android (Kotlin). Flutter is present but `libapp.so` is 1.7 MB and holds only a data migration module (`package:flutter_migration/...`).

## Direct BLE protocol (Tinnotech SDK, `com.tinnotech.penblesdk`)

### GATT

| UUID | Use |
|---|---|
| `00001910-0000-1000-8000-00805f9b34fb` | Plaud service (`ll2.a`) |
| `00002bb0-…` | Notify, device to app (`ll2.b`) |
| `00002bb1-…` | Write, app to device (`ll2.c`) |
| `0000180f-…` / `00002a19-…` | Standard battery service |

The device model is the first 3 digits of the serial number: `881` Note Pro, `888` Note, `880` NotePin, `882` NotePin S, `860` Plaud One.

### Framing

All integers are little-endian. I checked this in the ARM64 code of `libtnt_ble_utils.so` (`packInt`, `readInt`).

- App to device: `[0x01][cmd u16][params]`. Trailing zero bytes are trimmed (`nhg.b`).
- Device to app, byte 0 is the packet type (`e03.a`):
  - `1` = command response: `[0x01][cmd u16][fields]`
  - `2` = recording data
  - `4` = speed test data, `5` = device log data
- Checksum: CRC-16/CCITT, byte-wise (`tnt_get_crc` in the native library). It is used for file tail checks.

### Connect and handshake (`ih2.j`, `bxa`, `axa`, `vf2`)

1. Enable notify on `0x2BB0`.
2. Send handshake, cmd `1`: `01 01 00 | 02 00 | P | token`. `P` is present when the protocol version is 3 or more, and is `0` for the first handshake. The token is 32 ASCII chars when the protocol version is 9 or more, else 16.
3. The device answers cmd `1` (done) or cmd `2` (`GetSsnRsp`, serial check). After cmd `2`, send the handshake again with `P = 1`.
4. `HandShakeRsp` (cmd 1): `[3]` status (0 = OK), `[4..5]` protocol version, `[6]` timezone, `[7]` timezone minutes, `[8]` audio channels, `[9]` Wi-Fi support, `[10]` no NS/AGC, `[11]` Ogg audio, last 4 bytes version type and version code.

**The bind token is your Plaud `user_id`, right-padded with `0` to 32 chars** (`fa6.d.a`). In team mode it is a workspace ID instead (`igp.o`). The app has a hidden copy button: Settings > About, tap the logo 10 times. It copies `userId`, `workspaceId` and `bindToken` to the clipboard (`r0.invoke`).

### Commands for recordings

| cmd | Request params | Response |
|---|---|---|
| 26 get sessions | `now u32, start_session u32, flag u8` | cmd 26: `[7..8]` total, `[9..10]` index of first entry, entries from byte 11 |
| 28 sync file start | `session_id u32, start_offset u32, end_offset u32` | cmd 28 head: `session_id u32, status u8` (status > 0 = refused) |
| (data) | | type 2 packets, see below |
| 29 | sync stop (request) | cmd 29 tail: `session_id u32, crc u16` |
| 30 | delete file `session_id u32` | cmd 31. The script never sends this. |

Session entry size depends on the protocol version: 8 bytes for version 1 (`session_id u32, size u32`), 9 for versions 2-6 (+ scene u8), 10 for version 7 and up (+ 2 attribute bytes). The session ID is the recording start time in Unix seconds.

Data packet (type 2): `[0x02][session_id u32, only if protocol version >= 7][offset u32][len u8][len bytes of audio]`. Offset `0xFFFFFFFF` means "no more data", with a code byte after it. If the offset jumps, the app restarts the sync from the last good offset.

### Audio format

Raw Opus, 16 kHz, 20 ms frames of 80 bytes per channel (32 kbit/s CBR). `OPUS_FRAME_SIZE = channels * 80`. Two-channel devices use a multistream decoder. If the handshake sets the Ogg flag, the data is already Ogg. The script wraps mono frames in an Ogg Opus container.

### Encrypted firmware (protocol versions 20 and 30)

- Version 30: the device sends `0xFE30` first: `auth_mode u8, nonce_dev[16], sig[64], eph_dev_pub[65]`. Mode 1 is first bind, which goes through the cloud. Mode 2 is reconnect: the app checks the device signature with a stored device public key, then sends `0xFE31` = `nonce_app[16], sig2[64], eph_app_pub[65]`, signed with a stored app private key. The device answers `0xFE34`. Session keys: ECDH secret → HMAC-SHA256 with key `nonce_dev || nonce_app` → HKDF-expand with info `plaud-v2:ble-session` to 56 bytes = key[32] + nonce[12] + AAD[12]. Each packet is `seq u32 || plaintext`, AEAD-encrypted with a fixed nonce (`g03`, `e03`, `dn7`, `uo5.Z`/`uo5.V`).
- Version 20: RSA-wrapped session. **This is what my Note Pro uses (firmware 1.0.0), and it works end to end.** See below.

### Protocol 20 (tested on a real Note Pro, 2026-10-23)

The advertisement says protocol 20 in bytes 18-19 of manufacturer data `0x005D` (`14 00`). Bytes 1-2 are the model (`0x0371` = 881), bytes 9-16 the serial.

Two values come from the Plaud cloud. Both need the **user token** (`typ: UT`; on web.plaud.ai it is the `pld_ut` cookie), not the workspace token, plus the request header `X-Encrypt-Response: 1`. Use the regional host: the API answers `status -302` with the right domain (for me `https://api-apse1.plaud.ai`).
- `POST /device-app/device/sn-sign` with `{"sns": ["<serial>"]}` → `data.signature[serial]`: base64, 256 bytes.
- `POST /device-app/e2ee/gen_key` with `{}` → `data.private_key_base64` / `public_key_base64`: base64 of PEM text, RSA-2048. The app calls this only when it has no saved key. I don't know whether the server makes a new pair on each call.

Unlock flow (`ih2.t`, `zf2`, `e03`), before the normal handshake:
1. Send the signature as `[0xFE10 u16][total u8][index u8][<= 100 bytes]` chunks, raw (no `0x01` prefix).
2. If the device answers `0xFE11`, send the public key PEM text the same way with cmd `0xFE12`. My device skipped this and answered `0xFE12` directly.
3. The device sends the session secret as `0xFE12` packets: `[0xFE12][total][index][data]`. Join the data in index order and RSA-decrypt it (PKCS#1 v1.5). Result: key[32], nonce[12], AAD[12], then a ChaCha20-Poly1305 ciphertext that must decrypt to `PLAUD.AI`.
4. From now on, every packet in both directions is `ChaCha20-Poly1305(key, nonce, AAD)` over `seq u32 || packet`. The nonce is fixed for the session. The app's send counter starts at 2. Drop received packets whose seq is not higher than the last one.
5. Then the normal handshake and commands, encrypted.

Observed on my device:
- Handshake response `010100001400051e0101000156000701`: status 0, protocol 20, timezone 5:30, 1 channel, Wi-Fi supported, Ogg audio.
- Session list response `011a00 b19cdb6a 0000 0000`: the device echoes the timestamp in bytes 3-6, so the total is in bytes 7-8.
- Unrequested responses `010900005d` (cmd 9, probably battery, `0x5d` = 93) and `018d0000000000` (cmd 141).
- Download of a 34,816-byte test recording: data packets arrived in order up to the end marker (code 1), then tail `011d00 f49ddb6a ffff` (CRC field `0xFFFF`).

### Recordings are end-to-end encrypted on the device

The bytes the device sends are not Ogg. They are a `PLAUD.AI` file (`fem.a.h`, `decryptE2eeFile`). All values are little-endian:

| Offset | Field |
|---|---|
| 0 | magic `PLAUD.AI` |
| 8 | version u16 (1 = RSA; 2 = ECDH, for protocol 30) |
| 10 | header size u16 (512) |
| 12 | crc u32 |
| 16 | user id, 32 bytes (my device: the placeholder `userid_0123…`) |
| 48 / 50 / 52 | file type, channel, encrypt type (u16 each) |
| 54 | duration in seconds u32 |
| 58 | file UUID, 16 bytes |
| 128 | ChaCha20 start counter u32 |
| 132 | ChaCha20 nonce, 12 bytes |
| 144 | segment size u32 (0 on every Note Pro file seen; 80 on the original Note, see step 2) |
| 256 | key cipher, 256 bytes |

To decrypt version 1:
1. RSA-decrypt the key cipher (PKCS#1 v1.5) with the user private key from `gen_key`. This gives the 32-byte content key. The app uses the last 32 bytes if the result is longer.
2. Decrypt everything after the header with plain ChaCha20 (RFC 8439, no Poly1305), using the counter and nonce from the header. If the segment size is above 0, each segment of that many bytes is encrypted on its own, with the block counter at 0 for every segment (the official app's `yl7.a`). On the original Note (segment size 80) the result is bare Opus frames, one per segment, each starting with TOC byte `0xB8` or `0xB9` (CELT wideband, 20 ms, mono), with no Ogg pages; the app wraps them in Ogg. Reported by bitboxx in [issue #1](https://github.com/roopen219/plaude-archiver/issues/1).

The result is a normal Ogg Opus file. My 7.9 s test recording decoded with ffmpeg: Opus, mono, mean volume -17.6 dB.

Version 2 files (protocol 30) wrap the key with ECDH on P-256 instead: `keyCipher[0:65]` is an ephemeral public key, `[65:97]` the wrapped key, and HKDF info is `plaud-v2:audio-encrypt`. I did not implement that.

To support these devices, a script needs the per-device keys the app stores after binding. Two ways to get them: from the app's storage on a rooted phone, or from the device endpoints with your account token. I did not do this.

## First-time pairing (bind) flow

From the APK only, not tested on a device. For the Note and Note Pro, the app runs `fa6.bindAndConnect` (log tag `DeviceBindDomain`). Parts of it did not decompile, so the order comes from the app's own timing labels (`sf6`) and log messages. The Plaud One (ECC, protocol 30) has its own numbered flow in `mb6`.

### Cloud, then Bluetooth

1. **Scan.** The app finds the device by its advertisement: model code, serial, `bindInfo` flag (0 = free, 1 = bound) and protocol version.
2. **Your device list:** `GET /device-app/device/list` → `data_devices`. If the serial is already yours, this is a reconnect, not a new bind.
3. **Pre-connect** (`sendPreConnectData`):
   - `POST /device-app/device/sn-sign` `{"sns": [sn]}` → `signature[sn]`, cached per serial.
   - Your E2EE key pair: from the local cache, else `POST /device-app/e2ee/gen_key`.
   - The log warns that without these "handshake WILL FAIL for port>=20 devices".
4. **Ownership check:** `POST /device-app/device/check-sn-info` `{"sn", "model"}` → `is_bind`, `token_list` (bind tokens the cloud has for this serial), `email` (the current owner).
5. **Force unbind if someone else owns it** (`runForceUnbind`, new devices only): `POST /device-app/device/unbind` `{"sn", "is_force": true}`. It is skipped for "same-user offline rebind".
6. **Cloud bind:** `POST /device-app/device/bind` `{"sn", "name", "model", "version_number"}` → `email`. The cloud now lists the device under your account.
7. **Bluetooth connect and handshake** (next section). If this fails, the app undoes the cloud bind ("rolled back cloud bind after BLE failure"), so a half-paired device is never shown as bound.
8. **After connecting**, the app sends extras:
   - Time sync and settings reads.
   - Find My token (`distributeFindMyToken`), if the device supports it.
   - An HTTP/websocket token if needed (`distributeHttpTokenIfNeeded`, `POST /device-app/device/apply-token` `{"sn"}`).
   - A license (`POST /device-app/device/apply-license` `{"sn", "cid"}` → `key`, where `cid` is the flash ID from `GetFlashCidRsp`).

### Bluetooth side of a first bind (protocol 20)

1. Connect and enable notify on `0x2BB0`.
2. Send the SN signature as `0xFE10` chunks. The cloud signed the serial, so this proves the app is authorised by Plaud's servers.
3. **First bind only:** the device answers `0xFE11` ("I have no user key"). The app then sends your RSA public key PEM as `0xFE12` chunks (`zf2`), and the device stores it. My already-bound device skipped this and replied with the session secret directly.
4. The device sends the session secret, RSA-encrypted to that public key. From here the link is ChaCha20-Poly1305.
5. Handshake (cmd 1) with the bind token = your `user_id`, padded to 32 chars. An unbound device in pairing mode stores this token. Later connects must send the same token.
6. Possible handshake status values (`ConnectBleFailed`):

| Status | Meaning |
|---|---|
| 0 | OK |
| 1 | token mismatch (bound to someone else) |
| 2 | recording in progress, cannot confirm |
| 3 | rejected by the user on the device |
| 4 | SSN check failed |
| 255 | not in pairing mode |

So a new bind needs the device in pairing mode, and may need a confirmation on the device.

The same public key also encrypts every recording's content key. That is why the files on the device are only readable with the account that bound it.

### Plaud One / protocol 30 (ECC), for comparison

The device sends `0xFE30` first. Mode 1 means first bind:
1. The app calls `POST /device-app/auth/verify-device` `{"sn", "nonce_dev", "sig", "eph_dev_pub"}` → `verified`, `bind_session_id`, `dev_pub_base64`.
2. Then `POST /device-app/auth/sign-auth` `{"bind_session_id", "nonce_dev", "nonce_app", "sn", "eph_dev_pub", "eph_app_pub"}` → `sig2`, sent to the device as `0xFE31`.
3. After `0xFE34`, the app delivers the user key (`0xFE32`). The user ECC key comes from `GET /device-app/device/security/user-safe-key`.
4. The device acks with `0xFE33`. Then the app runs the handshake and calls `POST /device-app/device/bind-sn` with `bind_session_id` and `bind_sig`.

Mode 2 is a reconnect, verified locally with keys stored from the first bind.

## Does the firmware check the SN signature? (can you act as Plaud?)

Short answer from the APK: for your own device, you need nothing from Plaud ever again. For a reset device you have no signature for, you could only pair it offline if the firmware does **not** verify the signature, and the evidence says it probably does. The APK cannot settle this; only a device test can.

What the APK shows:

1. **The signature is a static RSA-2048 signature over the serial.** `sn-sign` returns 256 bytes (= 2048-bit). The request carries only the serial, no nonce, and a refetch 3 hours later returned byte-for-byte the same value. So it is a fixed certificate for the serial, not a per-session challenge. That is exactly why you can replay it offline forever for your device.

2. **The app has no "signature rejected" branch.** In the RSA pre-handshake (`ih2.t`, `zf2`, `e03`), the app sends the signature chunks (`0xFE10`) and then only ever expects `0xFE11` ("send your public key") or the encrypted secret (`0xFE12`). There is no code path for a device reply that says "bad signature". A device that rejected it would just go silent, and the app would time out as `HANDSHAKE_FAIL`. So the app tells us nothing about whether the check happens; the check, if any, is firmware-side.

3. **The sibling ECC devices definitely verify Plaud's signature in firmware.** On the Plaud One (protocol 30), the cloud `verify-device` checks the device, `sign-auth` returns `sig2`, the app forwards `sig2` to the device, and the device accepts the session only if `sig2` verifies. The app side even verifies the device's own signature with `SHA256withECDSA` (`fn7.d`). This whole challenge/sign/verify design only exists because these devices are built to trust a Plaud signature, not any app that shows up. The 256-byte RSA blob on protocol 20 is the older version of the same idea.

Putting it together:

- **Your Note Pro, offline, forever:** yes. You hold its static signature, its RSA key pair, and a token of your choice. Nothing above needs Plaud again. The only caveat is a fresh bind needs the device reset and in pairing mode, which this doc has not traced.
- **Impersonating Plaud to an arbitrary reset device (no signature for it):** only works if the firmware skips the signature check. Given points 1-3, assume it does verify and you cannot forge a signature (that needs Plaud's RSA private key). This is the one thing worth a device test: on a reset device, send a garbage 256-byte blob as `0xFE10` and see whether it still answers `0xFE11`. If it does, the firmware does not verify and you can fully act as Plaud. If it goes silent, it verifies.
- **No Plaud signing key is in the APK.** The device holds the Plaud public key (baked in at the factory), not the app, so the APK cannot reveal the key or a way around the check.

One more consequence worth noting: because the RSA signature step has no nonce, there is no freshness in the authorisation itself. All the session freshness comes from the RSA key exchange (the device encrypts a fresh secret to whatever public key it is handed). The signature only answers "is this serial Plaud-issued", not "is this a live, authorised app".

## Wi-Fi fast transfer

The SDK also has a Wi-Fi agent (`IWifiAgent`, `n5p`) with `GetFileListRsp`, `FileSyncContentRsp` and `FileDeleteRsp`. BLE turns it on (`openWiFi`, `getWifiSyncStart`). I did not trace that protocol.

## Cloud API (`https://api.plaud.ai`)

- Auth: `Authorization: Bearer <token>`. The app stores `user_token` and `user_refresh_token`. A simple way to get the token: sign in at `web.plaud.ai`, open DevTools > Network, and copy the `Authorization` header of any `api.plaud.ai` request.
- If a response has `x-encrypt-response: 1`, the body is a Fernet token. The key is built into the app as 7 joined parts (`wng.b`): `8rRmMCskL3NaUiGr-UsmEEeI8NKH-ZfeGbpRGqSLpuI=`.
- List: `GET /file-app/v4/app/sync/version/file?cursor=&limit=50` → `data.files[]` with `meta` (`file_id`, `start_time`, `duration`, `size_bytes`, `serial_number`, …) and `objects[]` (`object_type`, `content_id`, `download_url`, `mime_type`, …), plus `data.has_more` and `data.next_cursor`.
- Audio objects: `object_type` is `audio` (original) or `audio_transcoded`.
- Download URL: `POST /file-app/v4/files/content/url` with `{"content_ids": [...]}` → `data.url_map`.
- Region: the app can switch the base URL per account (`baseUrlOverride`). If you get an error about region, pass `--base` with the host the web app uses.

## What I checked and what I did not

Checked:
- Little-endian packing and the CRC, from the native ARM64 code.
- Handshake bytes: the second handshake the script builds (`01 01 00 02 00 01 + token`) matches the bytes the app's ECC path sends (`{1,1,0,2,1,1} + token`).
- Ogg Opus writer: 251 real 80-byte Opus frames (16 kHz, 20 ms, 32 kbit/s CBR) → ffmpeg decodes 5.02 s.
- The Fernet key decodes to 32 bytes and works with Python `cryptography`.

Tested end to end on a real Note Pro (firmware 1.0.0, protocol 20): scan, protocol-20 unlock, encrypted handshake, session list, download of one 7.9 s recording, and decryption to a playable Ogg Opus file. Not tested: long recordings, multiple files in one run, files with a segment size other than 0, and the cloud script.

Earlier note: before the device test, The cloud response shapes come from the app's JSON field names. The BLE byte offsets come from the decompiled parsers, but the script has not talked to hardware.
