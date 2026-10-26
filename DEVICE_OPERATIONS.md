# What the Plaud app can do to the device

Every operation the Android app (Tinnotech `penblesdk`) can run over BLE, grouped by what it does. Method names are from `IBleAgent` / `IWifiAgent`. Command numbers (the BLE opcode) are given where confirmed from the decompile. This is the menu of things the app *could* do. The table below says what a Note Pro actually answers.

## What a Plaud Note Pro answers (tested 2026-10-24)

Tested on a Note Pro (serial prefix 881, protocol 20) with the app's hidden modes `--probe-settings`, `--probe-features` and `--test-recording`.

| Feature | Cmd | Result |
|---|---|---|
| Set the clock | 4: `[unix u32][tz hours i8][tz minutes i8]` | works |
| Common settings, read | 8: `[1][setting u16]`, reply `[setting u16][value u32]`, `0xFFFFFFFF` = not on this device | 12 of 34 settings: 4, 15, 18, 19, 20, 23, 24, 25, 26, 27, 32, 49 |
| Common settings, write | 8: `[2][setting u16][value u32]` | accepted: 23 auto power off (0, 4, 5 tried; 1 = "shut down" not tried), 25 auto record (it did not start a recording within about 1 s; what it does is not known), 26 auto sync (see below), 32 battery mode (0, 1, 2 tried), 49 iBeacon wake-up. Kept at 0 whatever is written: 15 voice detection, 24 save raw audio |
| Recording state | 3: `[code u32 @3][privacy @7][key @8][scene @10][session u32 @11]` | code 4099 while recording, 1 when idle. Pause does not change it |
| Start / pause / resume / stop | 20 `[1][0]`, 21 / 22 `[session u32][0]`, 23 `[1][0]` | all work. A 4 s + 2 s paused + 3 s test gave 7.6 s of audio |
| Device name, read / write | 108 / 107 (32 bytes, reply 108) | works |
| Device status, firmware update info | 141, 151 | answer; no update was pending |
| Resume a download | 28 with a start offset | works: a download started at byte 17,408 matched a full copy |
| Stop a download | 29, reply 30 | a cancel 150 ms into a download stopped it, and the link answered the next command |
| Download checksum | tail packet `[session u32][crc u16]` | no usable checksum: the test transfers ended with the `0xFFFFFFFF` end marker, and an earlier capture shows a tail with CRC `0xFFFF`. The app checks the decrypted audio's Ogg page CRCs instead |
| Device events | 19 (device to app) | none arrived during a recording |
| Bookmarks / tags | 35, 38 | no reply |
| LED | 24 / 25 | replies, but the state never changes |
| No reply at all | 2, 15, 54, 106, 122, 131, 147, 149, 150, 152 | includes the Wi-Fi reads (15, 122). That does not prove the Note Pro has no Wi-Fi: its handshake reply flags Wi-Fi support, and the reads may need Wi-Fi turned on first (`openWiFi`, cmd 16), which was not tried |

**Auto sync (26) uploads to Plaud's cloud.** The Plaud app writes it from `setSyncInIdleState`, in a command group that also saves, tests and deletes Wi-Fi networks on the device. The app's own text for the NotePin: "auto-uploads recordings to your cloud when charging and connected to saved Wi-Fi". The archiver does not offer this setting.

**Auto record (25) has no description in the app.** Every "auto record" text in the app is for Plaud One earbuds ("Automatically records every call or meeting through your earbuds"), and that screen writes auto *call* record (37), not 25.

Two corrections to older notes in this repo: stop recording is cmd 23 (145 stops a device-log transfer), and the recording state above replaces the old reading of byte 7 as "recording" (byte 7 is the privacy flag).

## 📥 Recording transfer (what we already do)

| Method | Cmd | Does |
|---|---|---|
| `getRecSessions` | 26 | List recordings (session id = start time, size, attributes) |
| `syncFileStart` | 28 | Start streaming one recording to the app |
| `syncFileStop` | 30 | Stop the current transfer |
| `fileDataCheck` | — | Verify a transferred chunk |
| `getRecTags` / `getRecMarkings` | — | In-recording tags / bookmarks the user set |

## 🗑️ Deleting and storage (the part you want)

| Method | Cmd | Does |
|---|---|---|
| **`syncFileDel(sessionId)`** | **31** | **Delete one recording.** The app wraps this as `deleteFile` and calls it right after a successful cloud backup. This is the hook for "delete after download". |
| `clearRecordFile` | 104 | Delete **all** recordings at once |
| `getStorage` | 6 | Free / used space on the device |
| `setAutoDeleteRecordFile` / `getAutoDeleteRecordFile` | setting 4 | Device-side auto-delete (tell the device to drop files itself after a retention window) |
| `setAutoSync` / `getAutoSync` | — | Device's own auto-upload toggle |

## 🎙️ Recording control

`startRecord` (20), `startImmediateRecord`, `startSyncRecord`, `stopRecord` (23), `stopImmediateRecord`, `recordPause` (21), `recordResume` (22). Plus modes: `getRecMode`/`setRecMode`, `getRecScene`/`setRecScene`, `getPreRecord`/`setPreRecord`, `getSaveRAWFile`/`setSaveRAWFile`, `getAutoRecord`/`setAutoRecord`, `setAutoStopRecord`, `setAutoCallRecord`, `setAlarmRec`.

## 📊 Device status & identity

`getState`, `getDeviceStatus`, `getStorage` (6), `getBattStatus`, `getBatteryMode`, `getSsn` (serial), `getBleDeviceName`/`setBleDeviceName`, `getSDFlashCID`, `appGetThirdVersion`, `getSigmaLteStatus`, `syncTime` (set the clock).

## ⚙️ Settings (audio, power, UI)

Audio: `setMICGain`, `setVpuGain`, `setVpuCLK`, `setVadSensitivity`, `openVAD`, `getANC`/`setANC`, `setLDAC`, `setSoundEffect`, `setSoundPlusToken`.
Power/UI: `setAutoPowerOff`, `setBackLightBrightness`, `setBackLightTime`, `setLedStatus`, `setLanguage`, `setBatteryMode`/`setBatteryModeExt`, `setAirplaneMode`, `setPrivacy`, `setNightAutoUpgrade`, `setIBeaconWakeup`, `setAutoEarDetection`, `writeMotorCmd` (haptics), `calibrate`, `resetLens`, `setActive`, `getAllKeyFunc` (button mapping).

## 📶 Wi-Fi (fast transfer + direct cloud upload)

`openWiFi`/`closeWiFi`, `getWifiList`/`getWifiInfo`/`setSyncWifi`/`deleteWifiInfo`, `getRouterSsid`/`setRouterSsid`, `testWifiInfo`/`testWifiResult`, `getWiFiChannel`/`setWiFiChannel`, `getLteUpload`/`setLteUpload`, and `setWebsocket*` / `setWebsocketDevToken` / `setWebsocketSerToken` (the cloud upload endpoint + tokens the device uses to upload on its own). The `IWifiAgent` side (`connectWifi`, `getFileList`, `fileSyncStart`/`fileSyncStop`, `fileDelete`, `speedTest`, `getDeviceLog`) is the high-speed transfer path over Wi-Fi instead of BLE.

## 🔎 Find My / finding the device

`getFindMyState`/`setFindMyState`/`resetFindMy`, `getFindDevice`/`setFindDevice`.

## 🔄 Firmware / OTA

`appFotaPush`, `interruptFotaPush`, `getSyncOtaFileInfo`, `sendLte4gOta`, `getNightAutoUpgrade`/`setNightAutoUpgrade`.

## 🔐 Pairing / security / multi-device

`connectionBLE`, `disconnectBle`, `depair` (unbind), `resetPassword`, `setAppKey`, `getSecurityCheck`/`setSecurityCheck`, `connectDualDevice`/`disconnectDualDevice`/`setDualConnection`, `sendHostBudPairReq` (earbud pairing), `getPairedList`, `armTokenCollision`/`resendCollisionToken` (bind-token collision handling).

## 🪵 Logs / diagnostics / sensors

`startSyncDeviceLogFile`/`stopSyncDeviceLogFile`/`deleteDeviceLogFile` (146)/`getDeviceLogFileList`, `bleRateTest`, `readDataEntry`/`writeDataEntry`, `readExecution`/`writeExecution`, `syncEyeData`/`clearEyeData` (motion/angle sensor data).

---

## For Plaude Archiver: the "free up space" feature

Everything needed is already in our protocol layer. After a recording is **downloaded, decrypted and verified** (`data.count == size`, header check passes), send:

```
syncFileDel = command 31, payload: sessionId (u32 LE) + CRC
```

Design notes:
- Gate it behind an explicit, off-by-default option. Deleting the only copy off the device is irreversible.
- Only delete after the local `.ogg` exists and decrypted cleanly — never on a partial pull.
- `getStorage` (command 6) gives free/used, so the UI can show how full the device is and how much a cleanup would reclaim.
- The app's own `deleteFile` wrapper does exactly this one-session-at-a-time delete after a cloud backup, so the behavior and cadence match what the device already expects.
