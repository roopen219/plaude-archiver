import Foundation
import Security
import SwiftUI
import AppKit

// One recording as the UI sees it.
struct Recording: Identifiable {
    enum State { case onDevice, downloaded, deleted }
    let sessionId: UInt32
    let sizeBytes: Int
    var state: State = .onDevice
    var localURL: URL?

    var id: UInt32 { sessionId }
    var date: Date { Date(timeIntervalSince1970: TimeInterval(sessionId)) }
    // The device stores raw file size; the playable audio is a bit smaller after the header.
    var sizeText: String { ByteCountFormatter.string(fromByteCount: Int64(sizeBytes), countStyle: .file) }
}

// Drives the dashboard: owns the Bluetooth link, the API and persisted state,
// keeps a live connection, and exposes @Published state for SwiftUI.
@MainActor
final class DeviceModel: ObservableObject {
    @Published var recordings: [Recording] = []
    @Published var storage: StorageInfo?
    @Published var battery: Battery?
    @Published var connected = false
    @Published var busy = false
    @Published var status = "Not connected"
    @Published var deviceName: String?
    @Published var serial: String?
    @Published var signedIn = false
    // Live recording state from the device (cmd 3), and its running time from device events.
    @Published var recordingState: RecordingState?
    @Published var recordingMillis: UInt32?
    @Published var recordingPaused = false
    // Elapsed time for a recording started from this app. The device's own duration events
    // (recordingMillis) win when it sends them; the Note Pro does not.
    @Published var recordingClock: RecordingClock?
    private var refreshQueued = false   // an event asked for a refresh while busy
    @Published var downloading = false   // a download is running; the UI offers Cancel
    private var cancelRequested = false   // stops "Download all" between files, too
    private var keptOnDevice = 0          // delete-after-download skipped: the sizes did not match
    // The Device tab: info and settings read from the device when the tab opens.
    @Published var deviceStatusBytes: [UInt8]?
    @Published var firmwareUpdate: FirmwareUpdateInfo?
    @Published var settingValues: [UInt16: UInt32] = [:]   // missing key = not read, or not on this device
    @Published var settingsLoaded = false
    // Off for the headless test modes: a background poll would compete for the link.
    var pollingEnabled = true
    @Published var deleteAfterDownload = false {
        didSet { guard loaded else { return }; store.deleteAfterSync = deleteAfterDownload; store.save() }
    }

    private var store = Store.load()
    // Lazy so a model that never connects (the screenshot mode) never touches Bluetooth.
    private lazy var ble: BLEManager = {
        let b = BLEManager()
        b.onLog = { [weak self] s in self?.status = s }
        b.onLinkLost = { [weak self] in self?.linkLost() }
        b.onEvent = { [weak self] e in self?.deviceEvent(e) }
        return b
    }()
    private var login: LoginWindow?
    private var privKey: SecKey?
    private var loaded = false   // suppresses the didSet write during init

    init() {
        signedIn = store.userToken != nil
        deleteAfterDownload = store.deleteAfterSync
        loaded = true
    }

    var downloadDirName: String { store.defaultDownloadDir.lastPathComponent }

    func setDownloadDir(_ url: URL) {
        objectWillChange.send()
        store.downloadDir = url.path
        store.save()
    }

    func openDownloadFolder() {
        let dir = store.defaultDownloadDir
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        NSWorkspace.shared.open(dir)
    }

    // MARK: sign in

    func signIn() {
        guard login == nil else { return }   // a sign-in window is already open
        let win = LoginWindow { [weak self] token in
            guard let self else { return }
            self.store.userToken = token
            self.store.apiHost = PlaudAPI.hostFromToken(token)
            self.store.save()
            self.signedIn = true
            self.status = "Signed in."
            self.login = nil
        }
        win.onClose = { [weak self] in self?.login = nil }
        login = win
        win.show()
    }

    func signOut() {
        ble.disconnect()
        store = Store()
        store.save()
        signedIn = false; connected = false
        recordings = []; storage = nil; battery = nil
        clearDeviceState()
        status = "Signed out."
    }

    // MARK: connection

    private func ensureReady() async throws {
        guard let token = store.userToken else { throw APIError.message("not signed in") }
        var api = PlaudAPI(userToken: token, host: store.apiHost)
        if store.devicePrivatePEM == nil {
            status = "Fetching your encryption key…"
            let k = try await api.genKey()
            store.devicePrivatePEM = k.priv; store.devicePublicPEM = k.pub
            store.apiHost = k.host; api.host = k.host; store.save()
        }
        if privKey == nil, let pem = store.devicePrivatePEM {
            privKey = try Crypto.importRSAPrivateKey(pem: Data(pem.utf8))
        }
        if ble.isConnected { return }
        connected = false

        // Bluetooth links fail for passing reasons (a missed advert, a busy radio, a device that
        // was still dropping the last link). Each attempt starts from a clean link.
        let attempts = 3
        for attempt in 1...attempts {
            do {
                try await connectAndUnlock(api: api, token: token)
                return
            } catch {
                ble.disconnect()   // never leave a half-open link: the next scan would not see the device
                Store.log("connect attempt \(attempt) failed: \(error)")
                let retryable = (error as? BLEError)?.isRetryable ?? false
                guard retryable, attempt < attempts else { throw error }
                status = "Connection failed (\(error)). Retrying \(attempt + 1) of \(attempts)…"
                try await Task.sleep(nanoseconds: UInt64(attempt) * 1_500_000_000)
            }
        }
    }

    private func connectAndUnlock(api: PlaudAPI, token: String) async throws {
        status = "Connecting to the device…"
        try await ble.connect(knownSerials: Set(store.snSignatures.keys))
        self.deviceName = ble.discoveredName
        // The serial may be missing from the advert that matched (or there was no advert: the Mac
        // already held the link). The saved serial is only right for the device it was saved with.
        let saved = ble.isKnownPeripheral ? store.lastSerial : nil
        guard let serial = ble.discoveredSerial ?? saved else {
            throw BLEError.message("could not read the device serial")
        }
        if serial != self.serial { clearDeviceState() }   // another device: its settings are not these
        self.serial = serial
        if store.snSignatures[serial] == nil {
            status = "Authorising the device…"
            let s: (sig: String, host: String)
            do { s = try await api.snSign(serial: serial) }
            catch { throw BLEError.fatal("Could not get the device signature from Plaud: \(error)") }
            store.snSignatures[serial] = s.sig; store.apiHost = s.host; store.save()
        }
        guard let pem = store.devicePrivatePEM, let pub = store.devicePublicPEM,
              let sig = store.snSignatures[serial], let key = privKey else {
            throw BLEError.message("missing keys")
        }
        _ = pem
        try await ble.unlockProtocol20(signatureBase64: sig, privateKey: key, publicKeyPEM: pub)
        let userId = PlaudAPI.subject(of: token) ?? serial
        try await ble.handshake(token: userId)
        // Saved only now, together with the peripheral id (in BLEManager.handshake): a serial saved
        // before a failed unlock would later be paired with another device.
        store.lastSerial = serial; store.save()
        connected = true
        // The official app sets the device clock on every connect. Recording ids are start times
        // from that clock, so a drifting clock gives wrong dates. Not fatal: the link still works.
        do { try await ble.syncClock() } catch { Store.log("clock sync failed: \(error)") }
        startPolling()
    }

    // The Device tab's values describe one device; drop them when that device goes away.
    private func clearDeviceState() {
        settingValues = [:]; settingsLoaded = false
        firmwareUpdate = nil; deviceStatusBytes = nil
        recordingState = nil; recordingPaused = false; recordingClock = nil; recordingMillis = nil
    }

    func disconnect() {
        pollTimer?.invalidate(); pollTimer = nil
        ble.disconnect()
        connected = false
        status = "Disconnected."
    }

    // The link dropped by itself (out of range, device off, Bluetooth off). The next action
    // reconnects, so only reset the UI state here.
    private func linkLost() {
        pollTimer?.invalidate(); pollTimer = nil
        connected = false
        recordingMillis = nil
    }

    // Events the device pushes while connected.
    private func deviceEvent(_ e: DeviceEvent) {
        switch e {
        case .recordingDuration(_, let ms):
            recordingMillis = ms
        case .bookmark:
            if !busy { status = "Bookmark added." }
        case .newFile(let sid, _):
            // A recording just finished. List it now, or once the current action is done.
            recordingMillis = nil; recordingPaused = false; recordingClock = nil
            if busy { refreshQueued = true } else { status = "New recording: \(dateText(sid))."; refresh() }
        case .other:
            break
        }
    }

    // Headless full-loop self-test (for --selftest): connect, read status, list, then
    // download + verify ONE recording and delete it from the device. Lossless: the delete
    // only runs after a decrypted .ogg (>0 bytes) is confirmed on disk.
    func selfTest() async throws -> String {
        try await ensureReady()
        guard let key = privKey else { throw BLEError.message("no key") }
        var out = ["connected: \(ble.discoveredName ?? "?") serial=\(serial ?? "?")"]
        let before = try? await ble.getStorage()
        if let s = before { out.append("storage before: free=\(s.free) total=\(s.total)") }
        var files = try await ble.listSessions()
        out.append("recordings before: \(files.count) -> \(files.map { $0.sessionId })")
        guard let target = files.min(by: { $0.size < $1.size }) else { return (out + ["no recordings to test with"]).joined(separator: "\n") }
        out.append("target: session \(target.sessionId) (\(target.size) bytes)")

        let raw = try await ble.pullFile(target) { _, _ in }.data
        guard raw.prefix(8) == Data("PLAUD.AI".utf8) else { throw BLEError.message("unexpected file format; aborting before delete") }
        let dir = store.defaultDownloadDir
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try raw.write(to: dir.appendingPathComponent("plaud_\(target.sessionId).plaud"))
        let ogg = localURL(for: target.sessionId)
        let clear = try Crypto.decryptRecordingFile(raw, privateKey: key)
        try clear.write(to: ogg)
        let n = ((try? FileManager.default.attributesOfItem(atPath: ogg.path)[.size]) as? Int) ?? 0
        guard n > 0 else { throw BLEError.message("decrypted file empty; aborting before delete") }
        out.append("downloaded + decrypted: \(n) bytes -> \(ogg.lastPathComponent) (verified copy on disk)")

        out.append("deleting session \(target.sessionId) from device…")
        try await ble.deleteRecording(target.sessionId)
        files = try await ble.listSessions()
        let gone = !files.contains { $0.sessionId == target.sessionId }
        out.append("recordings after: \(files.count) -> \(files.map { $0.sessionId })")
        out.append(gone ? "DELETE CONFIRMED: session no longer on device ✓" : "DELETE FAILED: session still listed ✗")
        if let s = try? await ble.getStorage(), let b = before {
            out.append("storage after: free=\(s.free) (reclaimed \(Int64(s.free) - Int64(b.free)) bytes)")
        }
        ble.disconnect()
        return out.joined(separator: "\n")
    }

    // Headless read-only check of the live device ops (for --probe-device). Never deletes.
    func probe() async throws -> String {
        try await ensureReady()
        var out = ["connected: \(ble.discoveredName ?? "?")  serial=\(serial ?? "?")"]
        if let s = try? await ble.getStorage() {
            out.append("storage: free=\(s.free) total=\(s.total) duration=\(s.durationSeconds)")
        } else { out.append("storage: (no reply)") }
        if let b = try? await ble.getBattery() {
            out.append("battery: \(b.level)% charging=\(b.charging)")
        } else { out.append("battery: (no reply)") }
        if let r = try? await ble.getRecordingState() {
            out.append("recording: \(r.recording) sessionId=\(r.sessionId)")
        } else { out.append("recording: (no reply)") }
        let files = try await ble.listSessions()
        out.append("recordings: \(files.count)")
        for f in files.prefix(10) { out.append("  session \(f.sessionId) (\(dateText(f.sessionId)))  \(f.size) bytes") }
        ble.disconnect()
        return out.joined(separator: "\n")
    }

    // Headless read-only survey (for --probe-settings): which read commands and settings does
    // this device answer? Sends only "get" commands and common-settings READ (action 1).
    func probeSettings() async throws -> String {
        try await ensureReady()
        func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
        var out = ["connected: \(ble.discoveredName ?? "?")  serial=\(serial ?? "?")"]
        // Common settings, cmd 8: [action u8 = 1 read][setting u16]. Reply: [setting u16 @3][value u32 @5].
        let settings: [(String, UInt16)] = [
            ("BACK_LIGHT_TIME", 1), ("BACK_LIGHT_BRIGHTNESS", 2), ("LANGUAGE", 3), ("AUTO_DELETE_RECORD_FILE", 4),
            ("ENABLE_VAD", 15), ("REC_SCENE", 16), ("REC_MODE", 17), ("VAD_SENSITIVITY", 18), ("VPU_GAIN", 19),
            ("MIC_GAIN", 20), ("WIFI_CHANNEL", 21), ("SWITCH_HANDLER_ID", 22), ("AUTO_POWER_OFF", 23),
            ("SAVE_RAW_FILE", 24), ("AUTO_RECORD", 25), ("AUTO_SYNC", 26), ("FIND_MY", 27), ("VPU_CLK", 30),
            ("AUTO_STOP_RECORD", 31), ("BATTERY_MODE", 32), ("ANC", 36), ("AUTO_CALL_RECORD", 37),
            ("PRE_RECORD", 38), ("SOUND_EFFECT", 39), ("AUTO_EAR_DETECTION", 40), ("NIGHT_AUTO_UPGRADE", 41),
            ("FIND_DEVICE", 42), ("LDAC", 43), ("BATTERY_MODE_EXT", 44), ("SECURITY_CHECK", 45),
            ("DUAL_CONNECTION", 46), ("IBEACON_WAKEUP", 49), ("AIRPLANE_MODE", 50), ("LTE_UPLOAD", 51),
        ]
        for (name, id) in settings {
            let pkts = (try? await ble.rawExchange(8, [1] + Proto.u16le(id), window: 1.2)) ?? []
            out.append("setting \(id) \(name): " + (pkts.isEmpty ? "(no reply)" : pkts.map(hex).joined(separator: " | ")))
        }
        // Plain read commands with no parameters.
        let reads: [(String, UInt16)] = [
            ("getSsn", 2), ("getState", 3), ("getStorage", 6), ("getBattStatus", 9), ("getMotorCmdList", 19),
            ("getLedStatus", 24), ("appGetThirdVersion", 54), ("getAlarmRec", 106), ("getBleDeviceName", 108),
            ("getSDFlashCID", 131), ("getDeviceStatus", 141), ("getEarphoneState", 147), ("getAllKeyFunc", 149),
            ("getPairedList", 150), ("getSyncOtaFileInfo", 151), ("getSigmaLteStatus", 152), ("getWifiList", 122),
            ("getRouterSsid", 15),
        ]
        for (name, id) in reads {
            let pkts = (try? await ble.rawExchange(id, [], window: 1.5)) ?? []
            out.append("cmd \(id) \(name): " + (pkts.isEmpty ? "(no reply)" : pkts.map(hex).joined(separator: " | ")))
        }
        ble.disconnect()
        return out.joined(separator: "\n")
    }

    // Headless check of the newer features (for --probe-features). Its writes leave the device as
    // it was: clock sync, the name written back unchanged, and each editable setting changed and restored.
    // `resumeFrom` is an earlier copy of the smallest recording: the download starts at half of it,
    // so the resume path runs, and the result must equal that copy.
    func probeFeatures(resumeFrom: URL?) async throws -> String {
        try await ensureReady()
        var out = ["connected: \(ble.discoveredName ?? "?")  serial=\(serial ?? "?")"]
        out.append("clock sync: " + ((try? await ble.syncClock()) != nil ? "ok" : "failed"))
        let st = try? await ble.getRecordingState()
        out.append("state: \(st.map { "\($0.state) code=\($0.rawCode) key=\($0.rawKey) session=\($0.sessionId)" } ?? "(no reply)")")
        let name = try? await ble.getDeviceName()
        out.append("name: \(name ?? "(no reply)")")
        if let name, !name.isEmpty {
            out.append("rename to the same name: " + ((try? await ble.setDeviceName(name)) ?? "(no reply)"))
        }
        out.append("status bytes: \((try? await ble.getDeviceStatus()).map { $0.map { String($0) }.joined(separator: ",") } ?? "(no reply)")")
        if let f = try? await ble.getFirmwareUpdateInfo() {
            out.append("firmware update: to \(f.toVersionType)\(f.toVersion) range \(f.start)-\(f.end)")
        }
        // `try?` would flatten "no reply" and "not on this device" into one nil; keep them apart.
        func text(_ op: () async throws -> UInt32?) async -> String {
            do { return try await op().map(String.init) ?? "not on this device" } catch { return "no reply" }
        }
        for def in DeviceSetting.all {
            out.append("setting \(def.id) \(def.label): \(await text { try await self.ble.readSetting(def.id) })")
        }
        // Change each editable setting, read it back, then restore it. Not written: auto sync (26)
        // would let the device upload to Plaud's cloud, auto record (25) does something unknown,
        // and "Shut down" for auto power off could switch the device off.
        let flips: [(UInt16, String, (UInt32) -> UInt32)] = [
            (49, "iBeacon wake-up", { 1 - min($0, 1) }),
            (23, "auto power off", { $0 == 5 ? 4 : 5 }), (32, "battery mode", { $0 == 2 ? 0 : 2 }),
        ]
        for (id, label, other) in flips {
            guard let before = try? await ble.readSetting(id) else { out.append("flip \(label): not readable"); continue }
            let target = other(before)
            let echoed = await text { try await self.ble.writeSetting(id, target) }
            let readBack = await text { try await self.ble.readSetting(id) }
            let restoredEcho = await text { try await self.ble.writeSetting(id, before) }
            let final = await text { try await self.ble.readSetting(id) }
            let ok = readBack == String(target) && final == String(before)
            out.append("flip \(label): \(before) -> wrote \(target), reply \(echoed), read \(readBack); "
                       + "restore reply \(restoredEcho), read \(final) \(ok ? "OK" : "MISMATCH")")
        }
        out.append("state after the flips: \((try? await ble.getRecordingState()).map { "\($0.state)" } ?? "?")")
        let files = try await ble.listSessions()
        out.append("recordings: \(files.map { "\($0.sessionId) (\($0.size) B)" }.joined(separator: ", "))")
        // The resume reference is plaud_<session>.plaud; resume that recording, not another one.
        let refId = resumeFrom.flatMap { UInt32($0.deletingPathExtension().lastPathComponent.replacingOccurrences(of: "plaud_", with: "")) }
        if let target = files.first(where: { $0.sessionId == refId }) ?? files.min(by: { $0.size < $1.size }) {
            let full = target.sessionId == refId ? resumeFrom.flatMap { try? Data(contentsOf: $0) } : nil
            let head = full.map { Data($0.prefix($0.count / 2)) } ?? Data()
            let t0 = Date()
            let pulled = try await ble.pullFile(target, existing: head) { _, _ in }
            out.append("download \(target.sessionId): started at \(head.count), got \(pulled.data.count) of \(target.size) in "
                       + String(format: "%.1f s", Date().timeIntervalSince(t0)) + ", tail crc \(pulled.tailCRC.map(String.init) ?? "none")")
            if let full { out.append("matches the earlier copy: \(pulled.data == full)") }
            if let key = privKey, let clear = try? Crypto.decryptRecordingFile(pulled.data, privateKey: key) {
                var bad = clear; bad[bad.count / 2] ^= 0xFF
                out.append("ogg check: whole \(Crypto.isCompleteOgg(clear)), one byte flipped \(Crypto.isCompleteOgg(bad)), "
                           + "cut short \(Crypto.isCompleteOgg(clear.prefix(clear.count - 1)))")
            }
            // Cancel a download a moment after it starts; the link must still answer afterwards.
            let cancelTarget = files.max(by: { $0.size < $1.size }) ?? target
            Task { try? await Task.sleep(nanoseconds: 150_000_000); self.ble.cancelTransfer() }
            do {
                let got = try await ble.pullFile(cancelTarget) { _, _ in }
                out.append("cancel: the download finished first (\(got.data.count) bytes)")
            } catch BLEError.cancelled {
                out.append("cancel: cancelled; link afterwards: \((try? await ble.getBattery()).map { "battery \($0.level)%" } ?? "no reply")")
            } catch {
                out.append("cancel: failed with \(error)")
            }
            // The app's own download path: a half part file, resume, Ogg check, save. It writes the
            // same files a Download click would. Skipped when delete-after-download is on.
            if let full, !deleteAfterDownload {
                try full.prefix(full.count / 2).write(to: partURL(for: target.sessionId))
                recordings = files.map { Recording(sessionId: $0.sessionId, sizeBytes: Int($0.size)) }
                do {
                    try await downloadOne(target.sessionId)
                    let ogg = (try? Data(contentsOf: localURL(for: target.sessionId))) ?? Data()
                    out.append("app download: \(status) part file left: \(FileManager.default.fileExists(atPath: partURL(for: target.sessionId).path)); "
                               + "saved ogg \(ogg.count) B, whole \(Crypto.isCompleteOgg(ogg))")
                } catch { out.append("app download: failed with \(error)") }
            } else {
                out.append("app download: skipped (\(full == nil ? "no matching reference file" : "delete after download is on"))")
            }
        }
        ble.disconnect()
        return out.joined(separator: "\n")
    }

    // Headless, offline regression check (for --check-decrypt <folder>): decrypt every
    // plaud_<id>.plaud in the folder with this account's stored key, and compare the result with
    // the .ogg next to it, made by an earlier build. No Bluetooth, no network.
    func checkDecrypt(folder: URL) throws -> String {
        guard let pem = store.devicePrivatePEM else { throw BLEError.message("no stored key: sign in and connect once first") }
        let key = try Crypto.importRSAPrivateKey(pem: Data(pem.utf8))
        let files = try FileManager.default.contentsOfDirectory(at: folder, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "plaud" }.sorted { $0.path < $1.path }
        var out: [String] = []
        for f in files {
            let raw = try Data(contentsOf: f)
            let segment = raw.count >= 148 ? Int(raw[144]) | Int(raw[145]) << 8 | Int(raw[146]) << 16 | Int(raw[147]) << 24 : -1
            let line = "\(f.lastPathComponent) segment \(segment): "
            do {
                let clear = try Crypto.decryptRecordingFile(raw, privateKey: key)
                let earlier = try? Data(contentsOf: f.deletingPathExtension().appendingPathExtension("ogg"))
                out.append(line + "\(clear.count) B, whole Ogg \(Crypto.isCompleteOgg(clear)), "
                           + (earlier.map { $0 == clear ? "identical to the earlier .ogg" : "DIFFERS from the earlier .ogg" } ?? "no earlier .ogg"))
            } catch { out.append(line + "failed: \(error)") }
        }
        return out.joined(separator: "\n")
    }

    // Headless check of recording control (for --test-recording). It makes a short recording on
    // the device: start, pause, resume, stop, and prints the device events it saw.
    func testRecording() async throws -> String {
        try await ensureReady()
        var out = ["connected: \(ble.discoveredName ?? "?")"]
        var events: [String] = []
        ble.onEvent = { events.append("\($0)") }
        func state() async -> String {
            (try? await ble.getRecordingState()).map { "\($0.state) code=\($0.rawCode) key=\($0.rawKey) session=\($0.sessionId)" } ?? "?"
        }
        out.append("before: \(await state())")
        let sid = try await ble.startRecording()
        out.append("started, session \(sid); state: \(await state())")
        try await Task.sleep(nanoseconds: 4_000_000_000)
        let live = try await ble.getRecordingState()
        try await ble.pauseRecording(live.sessionId)
        out.append("paused; state: \(await state())")
        try await Task.sleep(nanoseconds: 2_000_000_000)
        try await ble.resumeRecording(live.sessionId)
        out.append("resumed; state: \(await state())")
        try await Task.sleep(nanoseconds: 3_000_000_000)
        try await ble.stopRecording()
        try await Task.sleep(nanoseconds: 2_000_000_000)
        out.append("stopped; state: \(await state())")
        let files = try await ble.listSessions()
        out.append("recordings now: \(files.map { "\($0.sessionId) (\($0.size) B)" }.joined(separator: ", "))")
        out.append("events: \(events.isEmpty ? "none" : events.joined(separator: "; "))")
        ble.disconnect()
        return out.joined(separator: "\n")
    }

    // MARK: actions

    // `bleBusy` serializes every BLE operation (so the background poll can't collide with a
    // user action); `busy` is only the UI flag for user-initiated work.
    private var bleBusy = false
    private var pollTimer: Timer?

    private var pollTask: Task<Void, Never>?

    private func run(_ label: String, _ op: @escaping () async throws -> Void) {
        guard !busy else { return }
        busy = true
        Task {
            await pollTask?.value   // let a background status poll finish, don't drop the click
            bleBusy = true
            do { try await op() }
            catch BLEError.cancelled {
                status = "Download cancelled. The next download resumes where it stopped."
            }
            catch {
                status = "Error: \(error)"
                // A device that stopped answering mid-command leaves the link in an unknown state.
                // Drop it, so the next action starts with a fresh connection.
                if case BLEError.timeout = error { ble.disconnect() }
                connected = ble.isConnected
                if !connected { pollTimer?.invalidate(); pollTimer = nil }
            }
            busy = false; bleBusy = false
            if refreshQueued { refreshQueued = false; refresh() }
        }
    }

    // Quietly refresh live status (battery, storage) while the window is open. No UI busy flag,
    // no status text, and skipped whenever a real operation holds the BLE link.
    private func startPolling() {
        guard pollingEnabled else { return }
        pollTimer?.invalidate()
        pollTimer = Timer.scheduledTimer(withTimeInterval: 12, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.pollStatus() }
        }
    }

    private func pollStatus() {
        guard connected, !bleBusy, !busy, ble.isConnected else { return }
        bleBusy = true
        pollTask = Task {
            defer { self.bleBusy = false; self.pollTask = nil }
            do {
                self.battery = try await self.ble.getBattery()
                self.storage = try await self.ble.getStorage()
            } catch BLEError.timeout {
                // The device stopped answering. Drop the link; the next action reconnects.
                Store.log("status poll timed out; dropping the link")
                self.ble.disconnect()
                self.linkLost()
                self.status = "Lost contact with the device. Refresh to reconnect."
            } catch {}
        }
    }

    func refresh() {
        run("refresh") {
            try await self.ensureReady()
            self.status = "Reading device…"
            try await self.reloadList()
            self.status = "\(self.recordings.count) recording(s) on the device."
        }
    }

    // Read status and the recording list from a connected device.
    private func reloadList() async throws {
        self.storage = try? await self.ble.getStorage()
        self.battery = try? await self.ble.getBattery()
        self.recordingState = try? await self.ble.getRecordingState()
        // The device's state does not say "paused", so the local flag is only kept while it records.
        if self.recordingState?.recording != true { self.recordingPaused = false; self.recordingClock = nil }
        let files = try await self.ble.listSessions()
        let existing = Dictionary(uniqueKeysWithValues: self.recordings.map { ($0.sessionId, $0) })
        self.recordings = files.map { f in
            if let r = existing[f.sessionId] {
                return Recording(sessionId: f.sessionId, sizeBytes: Int(f.size), state: r.state, localURL: r.localURL)
            }
            let url = self.localURL(for: f.sessionId)
            let onDisk = FileManager.default.fileExists(atPath: url.path)
            return Recording(sessionId: f.sessionId, sizeBytes: Int(f.size),
                             state: onDisk ? .downloaded : .onDevice, localURL: onDisk ? url : nil)
        }.sorted { $0.sessionId > $1.sessionId }
    }

    func downloadAll() {
        run("downloadAll") {
            try await self.ensureReady()
            let todo = self.recordings.filter { $0.state == .onDevice }
            self.cancelRequested = false
            self.keptOnDevice = 0
            for rec in todo {
                if self.cancelRequested { throw BLEError.cancelled }
                try await self.downloadOne(rec.sessionId)
            }
            self.status = self.keptOnDevice == 0 ? "Done."
                : "Done. \(self.keptOnDevice) recording(s) stayed on the device: their size on the device did not match the copy."
        }
    }

    func download(_ sessionId: UInt32) {
        run("download") {
            try await self.ensureReady()
            try await self.downloadOne(sessionId)   // sets its own final status
        }
    }

    // Delete every recording on the device (cmd 104). `confirmed` is the list the user saw when
    // they confirmed. The device may hold more by now (a recording made with its button never
    // shows up by itself), so list again and delete nothing if it has anything the user has not seen.
    func deleteAll(confirmed: Set<UInt32>) {
        run("deleteAll") {
            try await self.ensureReady()
            try await self.reloadList()
            if self.recordingState?.recording == true {
                throw BLEError.message("the device is recording. Nothing was deleted.")
            }
            let unseen = self.recordings.filter { !confirmed.contains($0.sessionId) }
            guard unseen.isEmpty else {
                throw BLEError.message("the device has \(unseen.count) recording(s) that were not in the list you confirmed. Nothing was deleted; check the list and try again.")
            }
            let ids = self.recordings.map(\.sessionId)
            try await self.ble.deleteAllRecordings()
            for id in ids { try? FileManager.default.removeItem(at: self.partURL(for: id)) }
            try await self.reloadList()   // show what the device holds now
            self.status = self.recordings.isEmpty ? "Deleted every recording from the device."
                : "The device still lists \(self.recordings.count) recording(s)."
        }
    }

    // MARK: recording control

    func startRecording() {
        run("startRecording") {
            try await self.ensureReady()
            _ = try await self.ble.startRecording()
            self.recordingPaused = false
            self.recordingClock = RecordingClock(start: Date())
            self.recordingState = try? await self.ble.getRecordingState()
            self.status = "Recording."
        }
    }

    func stopRecording() {
        run("stopRecording") {
            try await self.ensureReady()
            try await self.ble.stopRecording()
            self.recordingPaused = false; self.recordingMillis = nil; self.recordingClock = nil
            // The Note Pro sends no "new file" event, and it needs a moment to close the file.
            // List again until the new recording shows up, for up to about 6 seconds.
            let before = Set(self.recordings.map(\.sessionId))
            self.status = "Recording stopped. Saving it on the device…"
            for _ in 0..<6 {
                try await Task.sleep(nanoseconds: 1_000_000_000)
                try await self.reloadList()
                if let new = self.recordings.first(where: { !before.contains($0.sessionId) }) {
                    self.status = "New recording: \(self.dateText(new.sessionId))."
                    return
                }
            }
            self.status = "Recording stopped. It is not in the device's list yet; refresh in a moment."
        }
    }

    func togglePause() {
        run("togglePause") {
            try await self.ensureReady()
            let state = try await self.ble.getRecordingState()
            if self.recordingPaused { try await self.ble.resumeRecording(state.sessionId) }
            else { try await self.ble.pauseRecording(state.sessionId) }
            self.recordingPaused.toggle()
            if self.recordingPaused { self.recordingClock?.pause() } else { self.recordingClock?.resume() }
            self.recordingState = try? await self.ble.getRecordingState()
            self.status = self.recordingPaused ? "Recording paused." : "Recording resumed."
        }
    }

    // MARK: device info and settings

    // Read everything the Device tab shows. Settings the device does not have stay absent.
    func loadDeviceInfo() {
        run("loadDeviceInfo") {
            try await self.ensureReady()
            self.status = "Reading device settings…"
            if let name = try? await self.ble.getDeviceName(), !name.isEmpty { self.deviceName = name }
            self.deviceStatusBytes = try? await self.ble.getDeviceStatus()
            self.firmwareUpdate = try? await self.ble.getFirmwareUpdateInfo()
            self.recordingState = try? await self.ble.getRecordingState()
            var values: [UInt16: UInt32] = [:]
            for def in DeviceSetting.all {
                if let v = try? await self.ble.readSetting(def.id) { values[def.id] = v }
            }
            self.settingValues = values
            self.settingsLoaded = true
            self.status = "Device settings read."
        }
    }

    func setSetting(_ def: DeviceSetting, _ value: UInt32) {
        run("setSetting") {
            try await self.ensureReady()
            guard let confirmed = try await self.ble.writeSetting(def.id, value) else {
                throw BLEError.message("the device does not have the setting \(def.label)")
            }
            self.settingValues[def.id] = confirmed
            self.status = confirmed == value ? "\(def.label) saved." : "The device kept \(def.label) at \(confirmed)."
        }
    }

    func rename(_ name: String) {
        run("rename") {
            try await self.ensureReady()
            self.deviceName = try await self.ble.setDeviceName(name)
            self.status = "Renamed to \(self.deviceName ?? name)."
        }
    }

    func delete(_ sessionId: UInt32) {
        run("delete") {
            try await self.ensureReady()
            try await self.ble.deleteRecording(sessionId)
            self.mark(sessionId, .deleted)
            try? FileManager.default.removeItem(at: self.partURL(for: sessionId))
            self.storage = try? await self.ble.getStorage()
            self.status = "Deleted from device."
        }
    }

    // MARK: helpers

    private func downloadOne(_ sessionId: UInt32) async throws {
        guard let rec = recordings.first(where: { $0.sessionId == sessionId }), let key = privKey else { return }
        downloading = true
        defer { downloading = false }
        let info = RecordingInfo(sessionId: sessionId, size: UInt32(rec.sizeBytes))
        let dir = store.defaultDownloadDir
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let part = partURL(for: sessionId)
        let raw = try await pullWithResume(info, partURL: part)
        try raw.write(to: dir.appendingPathComponent("plaud_\(sessionId).plaud"))
        try? FileManager.default.removeItem(at: part)
        // Only a verified decrypt counts as a safe local copy. If the device ever returns an
        // unexpected format, keep the raw .plaud and NEVER delete the device's copy.
        guard raw.prefix(8) == Data("PLAUD.AI".utf8) else {
            status = "Saved an encrypted copy in an unexpected format — keeping it on the device."
            return
        }
        let ogg = localURL(for: sessionId)
        let clear = try Crypto.decryptRecordingFile(raw, privateKey: key)
        // The cipher has no tag, so damaged bytes still "decrypt". The audio's own page checksums
        // are what proves the copy whole.
        guard Crypto.isCompleteOgg(clear) else {
            Store.log("download \(sessionId): \(raw.count) bytes failed the Ogg check")
            throw BLEError.message("the download of \(dateText(sessionId)) failed its integrity check; it stays on the device. Please download it again.")
        }
        try clear.write(to: ogg)
        updateLocal(sessionId, url: ogg)
        status = "Downloaded \(dateText(sessionId))."
        if deleteAfterDownload {
            // Delete only what was copied whole: the device must still list this recording with a
            // size, and that size must be exactly what arrived.
            let now = try await ble.listSessions().first { $0.sessionId == sessionId }
            guard let now, now.size > 0, Int(now.size) == raw.count else {
                keptOnDevice += 1
                status = "Downloaded \(dateText(sessionId)), but kept it on the device: its size on the device is \(now.map { "\($0.size)" } ?? "unknown"), the copy has \(raw.count) bytes."
                return
            }
            try await ble.deleteRecording(sessionId)
            mark(sessionId, .deleted)
            storage = try? await ble.getStorage()
            status = "Downloaded and removed \(dateText(sessionId)) from the device."
        }
    }

    // Download with progress kept on disk in `partURL`. A broken transfer leaves the part file,
    // and the next attempt (now, after a reconnect, or after an app restart) starts after it.
    private func pullWithResume(_ info: RecordingInfo, partURL: URL) async throws -> Data {
        let total = Int(info.size)
        var reconnects = 0
        while true {
            var saved = (try? Data(contentsOf: partURL)) ?? Data()
            if total > 0, saved.count > total { saved = Data() }   // not this recording's data
            if total > 0, saved.count == total { return saved }    // an earlier attempt got it all
            if !saved.isEmpty { Store.log("resuming \(info.sessionId) at \(saved.count) of \(total) bytes") }
            let writer = try PartWriter(url: partURL, keep: saved.count)
            defer { writer.close() }
            do {
                let pulled = try await ble.pullFile(info, existing: saved, onChunk: writer.append, onProgress: { got, total in
                    if total > 0 { self.status = "Downloading \(self.dateText(info.sessionId)) — \(got * 100 / total)%" }
                })
                if let crc = pulled.tailCRC { Store.log("download \(info.sessionId): \(pulled.data.count) bytes, tail crc \(crc)") }
                return pulled.data
            } catch let error as BLEError where error.isRetryable && reconnects < 2 {
                // The link dropped or stalled for good. Reconnect and carry on from the part file.
                reconnects += 1
                writer.close()
                Store.log("download \(info.sessionId) interrupted (\(error)); reconnecting")
                status = "Connection lost during the download. Reconnecting…"
                ble.disconnect()
                try await ensureReady()
            }
        }
    }

    // Stop the running download. Its part file stays, so the next download resumes from there.
    func cancelDownload() {
        guard downloading else { return }
        cancelRequested = true
        ble.cancelTransfer()
    }

    private func partURL(for sessionId: UInt32) -> URL {
        store.defaultDownloadDir.appendingPathComponent("plaud_\(sessionId).plaud.part")
    }

    private func localURL(for sessionId: UInt32) -> URL {
        store.defaultDownloadDir.appendingPathComponent("plaud_\(sessionId).ogg")
    }
    func dateText(_ sessionId: UInt32) -> String {
        let f = DateFormatter(); f.dateFormat = "MMM d, HH:mm"
        return f.string(from: Date(timeIntervalSince1970: TimeInterval(sessionId)))
    }
    private func mark(_ sessionId: UInt32, _ state: Recording.State) {
        if let i = recordings.firstIndex(where: { $0.sessionId == sessionId }) { recordings[i].state = state }
    }
    private func updateLocal(_ sessionId: UInt32, url: URL) {
        if let i = recordings.firstIndex(where: { $0.sessionId == sessionId }) {
            recordings[i].state = .downloaded; recordings[i].localURL = url
        }
    }
}

// The device settings this app shows: the ones a Note Pro answers (a read-only probe on
// 2026-10-24), with values from the official app's enums. The app's source shows no range for
// gain, sensitivity, Find My or auto-delete, so those are shown but not written. A write test on
// the same day: the Note Pro accepts the editable ones, and keeps "save raw audio" and
// "voice detection" at 0 whatever is written. Auto sync (26) is left out on purpose: it is the
// Plaud app's "Sync in idle", where the device uploads recordings to Plaud's cloud over Wi-Fi.
// Auto record (25) is left out too: the Plaud app gives no description of it for any device.
struct DeviceSetting: Identifiable {
    enum Kind { case toggle, choice([(UInt32, String)]), readOnly }
    let id: UInt16
    let label: String
    let kind: Kind
    var help: String? = nil

    private static let refused = "The Note Pro does not accept changes to this setting over Bluetooth."

    static let all: [DeviceSetting] = [
        DeviceSetting(id: 24, label: "Save raw audio", kind: .readOnly, help: refused),
        DeviceSetting(id: 15, label: "Voice detection", kind: .readOnly, help: refused),
        DeviceSetting(id: 49, label: "iBeacon wake-up", kind: .toggle),
        DeviceSetting(id: 23, label: "Auto power off", kind: .choice([
            // 1 is "SHUT_DOWN" in the app's enum; untested, and it may switch the device off.
            (0, "Off"), (2, "15 minutes"), (3, "30 minutes"), (4, "1 hour"), (5, "5 hours")])),
        DeviceSetting(id: 32, label: "Battery mode", kind: .choice([(0, "Normal"), (1, "Balanced"), (2, "Power")])),
        DeviceSetting(id: 20, label: "Microphone gain", kind: .readOnly),
        DeviceSetting(id: 19, label: "VPU gain", kind: .readOnly),
        DeviceSetting(id: 18, label: "Voice detection sensitivity", kind: .readOnly),
        DeviceSetting(id: 27, label: "Find My", kind: .readOnly),
        DeviceSetting(id: 4, label: "Device auto-delete", kind: .readOnly,
                      help: "The device's own clean-up of old recordings. Change it in the Plaud app."),
    ]
}

// Local timer for a recording started here: wall time minus paused time.
struct RecordingClock {
    let start: Date
    var pausedAt: Date?
    var pausedFor: TimeInterval = 0

    init(start: Date) { self.start = start }
    mutating func pause() { if pausedAt == nil { pausedAt = Date() } }
    mutating func resume() {
        if let p = pausedAt { pausedFor += Date().timeIntervalSince(p); pausedAt = nil }
    }
    func elapsed(at now: Date = Date()) -> TimeInterval {
        (pausedAt ?? now).timeIntervalSince(start) - pausedFor
    }
}

// Appends a download's bytes to its part file in 64 KB batches. The file must stay a clean prefix
// of the recording, or a later resume would splice a hole into it: after any failed write this
// stops writing and cuts the file back to the last good byte (or removes it).
private final class PartWriter {
    private let url: URL
    private let handle: FileHandle
    private var good: UInt64
    private var pending = Data()
    private var broken = false

    init(url: URL, keep: Int) throws {
        if !FileManager.default.fileExists(atPath: url.path) {
            FileManager.default.createFile(atPath: url.path, contents: nil)
        }
        self.url = url
        handle = try FileHandle(forWritingTo: url)
        good = UInt64(keep)
        try handle.truncate(atOffset: good)
        try handle.seekToEnd()
    }

    func append(_ chunk: Data) {
        guard !broken else { return }
        pending.append(chunk)
        if pending.count >= 65_536 { flush() }
    }

    func flush() {
        guard !broken, !pending.isEmpty else { return }
        do {
            try handle.write(contentsOf: pending)
            good += UInt64(pending.count)
            pending.removeAll()
        } catch {
            broken = true
            pending.removeAll()
            Store.log("part file \(url.lastPathComponent): write failed (\(error)); keeping \(good) bytes")
            if (try? handle.truncate(atOffset: good)) == nil { try? FileManager.default.removeItem(at: url) }
        }
    }

    // Safe to call more than once.
    func close() {
        flush()
        try? handle.close()
    }
}
