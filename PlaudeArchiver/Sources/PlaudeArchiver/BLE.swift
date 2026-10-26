import Foundation
import CoreBluetooth
import CryptoKit
import Security

struct RecordingInfo { let sessionId: UInt32; let size: UInt32 }

enum BLEError: Error, CustomStringConvertible {
    case message(String)   // link or protocol trouble; a fresh connection may fix it
    case timeout(String)   // the device or the radio did not answer in time
    case fatal(String)     // a retry now will not help (permission, Bluetooth off, not found, refused)
    case cancelled         // the user stopped it
    var description: String {
        switch self {
        case .message(let m), .timeout(let m), .fatal(let m): return m
        case .cancelled: return "cancelled"
        }
    }
    var isRetryable: Bool {
        switch self { case .fatal, .cancelled: return false; default: return true }
    }
}

@MainActor
final class BLEManager: NSObject, CBCentralManagerDelegate, CBPeripheralDelegate {
    private var central: CBCentralManager!
    private var peripheral: CBPeripheral?
    private var writeChar: CBCharacteristic?
    private var notifyChar: CBCharacteristic?
    private var session: Session?
    private var handshakeDone = false
    private var portVersion = 20

    // Ordered packet buffer + a single pending data waiter (flows are sequential).
    private var buffer: [Data] = []
    private var waiter: (CheckedContinuation<Data, Error>, DispatchWorkItem)?

    // One continuation for the current setup step. Every step starts its radio operation
    // inside awaitStep, after the continuation is registered, so a fast callback can't be lost.
    private enum Step { case power, scan, connect, services, characteristics, notify, write }
    private var stepCont: CheckedContinuation<Void, Error>?
    private var stepTimeout: DispatchWorkItem?
    private var stepKind: Step?
    private var found: CBPeripheral?

    // Flow control for writes without response (CoreBluetooth drops them when its queue is full).
    private var canSendCont: CheckedContinuation<Void, Never>?

    // Peripherals we cancelled ourselves. Their late disconnect callback must not tear down
    // the next connection attempt to the same device.
    private var cancelled = Set<UUID>()

    var onLog: (String) -> Void = { _ in }
    // Called when an established link drops without us asking (out of range, device off, Bluetooth off).
    var onLinkLost: () -> Void = {}
    // Called for each event the device pushes (recording progress, bookmark, new file).
    var onEvent: (DeviceEvent) -> Void = { _ in }
    private(set) var discoveredName: String?
    private(set) var discoveredSerial: String?

    private static let serviceUUID = CBUUID(string: Proto.service)
    private static let advertUUID = CBUUID(string: "504C")
    // Renamed from "lastPeripheralId": builds before 2026-10-24 saved that one before the unlock,
    // so it may name a stranger's device.
    private static let knownIdKey = "lastHandshakenPeripheralId"

    override init() {
        super.init()
        central = CBCentralManager(delegate: self, queue: nil)   // main queue
    }

    // Status line for the UI, also written to the log file.
    private func log(_ s: String) { onLog(s); Store.log(s) }
    // Detail for the log file only.
    private func trace(_ s: String) { Store.log("ble: " + s) }

    // MARK: connection

    // Find, connect and prepare the GATT link. Always starts from a clean state, so it is safe
    // to call again after any failure.
    // `knownSerials`: serials this account has a signature for. A device that advertises one of
    // them is preferred over any other Plaud-looking advertiser nearby.
    func connect(knownSerials: Set<String> = []) async throws {
        tearDown()
        self.knownSerials = knownSerials
        do {
            if central.state != .poweredOn {
                do { try await awaitStep(.power, 10, "power") {} }
                catch BLEError.timeout {
                    // Retrying will not help: either the permission prompt is waiting for an answer,
                    // or Bluetooth is stuck. A rebuilt ad-hoc signed app asks for permission again.
                    switch CBCentralManager.authorization {
                    case .notDetermined:
                        throw BLEError.fatal("Waiting for Bluetooth permission. Please click Allow in the macOS prompt, then refresh.")
                    case .denied, .restricted:
                        throw BLEError.fatal("Bluetooth permission denied. Allow it in System Settings › Privacy & Security › Bluetooth.")
                    default:
                        throw BLEError.fatal("Bluetooth did not become ready (state \(central.state.rawValue)). Try turning Bluetooth off and on.")
                    }
                }
            }
            guard central.state == .poweredOn else { throw BLEError.fatal("Bluetooth is not available.") }

            let p = try await findPeripheral()
            peripheral = p
            p.delegate = self

            log("Connecting to \(discoveredName ?? "the device")…")
            try await awaitStep(.connect, 15, "The device did not accept the connection.") {
                self.central.connect(p, options: nil)
            }
            trace("connected; discovering services")
            try await awaitStep(.services, 10, "The device did not list its services.") {
                p.discoverServices([BLEManager.serviceUUID])
            }
            guard let svc = p.services?.first(where: { $0.uuid == BLEManager.serviceUUID }) else {
                throw BLEError.message("Plaude service not found on the device.")
            }
            try await awaitStep(.characteristics, 10, "The device did not list its characteristics.") {
                p.discoverCharacteristics([CBUUID(string: Proto.notifyChar), CBUUID(string: Proto.writeChar)], for: svc)
            }
            guard let n = notifyChar, writeChar != nil else {
                throw BLEError.message("The device is missing the Plaude characteristics.")
            }
            // The device answers the very first packet we send. If notifications are not on yet,
            // that answer is lost and the unlock waits until it times out.
            try await awaitStep(.notify, 10, "The device did not turn on notifications.") {
                p.setNotifyValue(true, for: n)
            }
            trace("notify on; max write without response = \(p.maximumWriteValueLength(for: .withoutResponse))")
            log("Connected\(discoveredName.map { " to \($0)" } ?? "").")
        } catch {
            tearDown()
            throw error
        }
    }

    // A device the Mac already holds a link to does not advertise, so a scan would never see it.
    // Check for that first, then scan.
    private func findPeripheral() async throws -> CBPeripheral {
        // Name and serial describe the device found in this scan only; never reuse the last one's.
        discoveredName = nil; discoveredSerial = nil
        let held = central.retrieveConnectedPeripherals(withServices: [BLEManager.serviceUUID])
        let knownId = UserDefaults.standard.string(forKey: BLEManager.knownIdKey).flatMap(UUID.init)
        if let p = held.first(where: { $0.identifier == knownId }) ?? held.first {
            discoveredName = p.name
            trace("using a link the system already holds: \(p.identifier)")
            return p
        }
        log("Looking for a Plaude device…")
        found = nil
        candidates.removeAll()
        // The device advertises service 0x504C (and the full 0x1910 is only visible after
        // connecting), so scan broadly and match in didDiscover.
        do {
            try await awaitStep(.scan, 20, "scan") {
                self.central.scanForPeripherals(withServices: nil, options: nil)
            }
        } catch BLEError.timeout {
            central.stopScan()
            // 20 s of scanning already covers many adverts; another round would only add a wait.
            throw BLEError.fatal("Could not find the device. Make sure it is on, nearby, and not connected to the Plaud phone app.")
        } catch {
            central.stopScan()
            throw error
        }
        central.stopScan()
        pickTimer?.cancel(); pickTimer = nil
        guard let p = found else { throw BLEError.message("scan ended without a device") }
        return p
    }

    // Every Plaud-looking advertiser seen in this scan. Something else nearby can look like a
    // Plaud device, accept the connection, and never send a session key.
    private struct Candidate { let peripheral: CBPeripheral; var name: String?; var serial: String?; var rssi: Int }
    private var candidates: [UUID: Candidate] = [:]
    private var pickTimer: DispatchWorkItem?
    private var knownSerials: Set<String> = []

    private var knownPeripheralId: UUID? {
        UserDefaults.standard.string(forKey: BLEManager.knownIdKey).flatMap(UUID.init)
    }
    // The connected device is the one that last completed a handshake, so its saved serial applies.
    var isKnownPeripheral: Bool { peripheral != nil && peripheral?.identifier == knownPeripheralId }

    // A sure match (the last device that completed a handshake, or a serial we hold a signature
    // for) is taken at once. A device with another serial may be a new one to authorise: wait
    // 1.5 s for a better match, then take the strongest. A device that shows no serial is never
    // taken: without its serial there is no signature to send, and the unlock would only hang.
    private func consider(_ c: Candidate) {
        if c.peripheral.identifier == knownPeripheralId || c.serial.map(knownSerials.contains) == true {
            choose(c); return
        }
        guard c.serial != nil, pickTimer == nil else { return }
        let item = DispatchWorkItem { [weak self] in
            guard let self, self.stepKind == .scan, self.found == nil else { return }
            if let best = self.candidates.values.filter({ $0.serial != nil }).max(by: { $0.rssi < $1.rssi }) {
                self.choose(best)
            }
        }
        pickTimer = item
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5, execute: item)
    }

    private func choose(_ c: Candidate) {
        pickTimer?.cancel(); pickTimer = nil
        found = c.peripheral
        discoveredName = c.name
        if let s = c.serial { discoveredSerial = s }
        log("Found \(c.name ?? "device")\(c.serial.map { " (serial \($0))" } ?? "").")
        trace("chose \(c.peripheral.identifier) rssi \(c.rssi) from \(candidates.count) candidate(s)")
        resolveStep(.success(()))
    }

    // Drop the link and every piece of per-connection state. Safe to call at any time.
    func disconnect() { tearDown() }

    private func tearDown() {
        if central.isScanning { central.stopScan() }
        if let p = peripheral, p.state != .disconnected {
            cancelled.insert(p.identifier)
            central.cancelPeripheralConnection(p)
        }
        peripheral = nil; writeChar = nil; notifyChar = nil; found = nil
        pickTimer?.cancel(); pickTimer = nil
        session = nil; handshakeDone = false; portVersion = 20
        buffer.removeAll(); secretParts.removeAll(); secretTotal = nil; sawFE11 = false
        resolveStep(.failure(BLEError.message("disconnected")))
        failWaiter(BLEError.message("disconnected"))
        canSendCont?.resume(); canSendCont = nil
        sendTail = nil
    }

    // Connected, unlocked and handshaken: ready for commands.
    var isConnected: Bool {
        peripheral?.state == .connected && writeChar != nil && session != nil && handshakeDone
    }

    private func awaitStep(_ kind: Step, _ timeout: TimeInterval, _ timeoutMessage: String,
                           start: () -> Void) async throws {
        resolveStep(.failure(BLEError.message("superseded")))   // never leak an older step
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            stepKind = kind
            stepCont = cont
            let item = DispatchWorkItem { [weak self] in
                self?.trace("step \(kind) timed out after \(Int(timeout))s")
                self?.resolveStep(.failure(BLEError.timeout(timeoutMessage)))
            }
            stepTimeout = item
            DispatchQueue.main.asyncAfter(deadline: .now() + timeout, execute: item)
            start()
        }
    }

    private func resolveStep(_ result: Result<Void, Error>) {
        guard let cont = stepCont else { return }
        stepTimeout?.cancel(); stepTimeout = nil; stepCont = nil; stepKind = nil
        cont.resume(with: result)
    }

    private func resolveStep(_ kind: Step, _ error: Error?, _ what: String) {
        guard stepKind == kind else { return }
        if let error {
            trace("\(what) failed: \(error.localizedDescription)")
            resolveStep(.failure(BLEError.message("\(what) failed: \(error.localizedDescription)")))
        } else {
            resolveStep(.success(()))
        }
    }

    private func isCurrent(_ p: CBPeripheral) -> Bool { p === peripheral }

    // An established link went away without us asking.
    private func linkLost(_ reason: String) {
        let wasReady = isConnected
        log(reason)
        tearDown()
        if wasReady { onLinkLost() }
    }

    // MARK: central/peripheral delegate

    func centralManagerDidUpdateState(_ c: CBCentralManager) {
        Store.log("central state = \(c.state.rawValue) (poweredOn=5, unauthorized=3, poweredOff=4)")
        switch c.state {
        case .poweredOn:
            if stepKind == .power { resolveStep(.success(())) }
        case .unauthorized:
            resolveStep(.failure(BLEError.fatal("Bluetooth permission denied. Allow it in System Settings › Privacy & Security › Bluetooth.")))
            if peripheral != nil { linkLost("Bluetooth permission was removed.") }
        case .poweredOff:
            resolveStep(.failure(BLEError.fatal("Bluetooth is turned off.")))
            // CoreBluetooth drops every link on power-off without a disconnect callback.
            if peripheral != nil { linkLost("Bluetooth was turned off.") }
        case .resetting:
            if peripheral != nil { linkLost("Bluetooth restarted; the link was lost.") }
        default: break
        }
    }

    func centralManager(_ c: CBCentralManager, didDiscover p: CBPeripheral,
                        advertisementData: [String: Any], rssi RSSI: NSNumber) {
        guard stepKind == .scan, found == nil else { return }
        let name = p.name ?? (advertisementData[CBAdvertisementDataLocalNameKey] as? String)
        let uuids = (advertisementData[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID]) ?? []
        // Require a strong Plaud signal: the service UUID or a Plaud name. The manufacturer-data
        // serial is NOT enough to match on — its loose hex heuristic fires on unrelated beacons,
        // and a wrong connect stops the scan and then stalls until timeout.
        // The device we last completed a handshake with counts even after a rename.
        let isPlaud = p.identifier == knownPeripheralId
            || uuids.contains(BLEManager.advertUUID) || uuids.contains(BLEManager.serviceUUID)
            || (name?.lowercased().contains("plaud") ?? false)
        guard isPlaud else { return }   // not a Plaud device; keep scanning
        // The serial lives in the manufacturer-data packet, which isn't always the same
        // advertisement that carried the name/service. Keep what earlier adverts gave.
        let serial = (advertisementData[CBAdvertisementDataManufacturerDataKey] as? Data)
            .flatMap { BLEManager.serial(fromManufacturerData: $0) }
        var c = candidates[p.identifier] ?? Candidate(peripheral: p, name: nil, serial: nil, rssi: RSSI.intValue)
        // Log a device when first seen, and again when its serial first shows, with the raw
        // manufacturer data: it is what the serial is parsed from.
        if candidates[p.identifier] == nil || (c.serial == nil && serial != nil) {
            let mfr = (advertisementData[CBAdvertisementDataManufacturerDataKey] as? Data).map { $0.map { String(format: "%02x", $0) }.joined() }
            trace("candidate \(p.identifier) \(name ?? "?") serial \(serial ?? "-") rssi \(RSSI) mfr \(mfr ?? "-")")
        }
        c.name = name ?? c.name
        c.serial = serial ?? c.serial
        c.rssi = RSSI.intValue
        candidates[p.identifier] = c
        consider(c)
    }

    func centralManager(_ c: CBCentralManager, didConnect p: CBPeripheral) {
        guard isCurrent(p) else { return }
        // Cancelling a pending connect does not always send a callback. Once connected again,
        // an old cancel marker would only hide a real disconnect.
        cancelled.remove(p.identifier)
        resolveStep(.connect, nil, "connect")
    }

    func centralManager(_ c: CBCentralManager, didFailToConnect p: CBPeripheral, error: Error?) {
        if cancelled.remove(p.identifier) != nil { return }   // our own cancel
        guard isCurrent(p) else { return }
        resolveStep(.connect, error ?? BLEError.message("unknown error"), "connect")
    }

    func centralManager(_ c: CBCentralManager, didDisconnectPeripheral p: CBPeripheral, error: Error?) {
        if cancelled.remove(p.identifier) != nil { return }   // our own cancel
        guard isCurrent(p) else { return }
        trace("disconnected: \(error?.localizedDescription ?? "no error")")
        linkLost("The device disconnected.")
    }

    func peripheral(_ p: CBPeripheral, didDiscoverServices error: Error?) {
        guard isCurrent(p) else { return }
        resolveStep(.services, error, "service discovery")
    }

    func peripheral(_ p: CBPeripheral, didDiscoverCharacteristicsFor svc: CBService, error: Error?) {
        guard isCurrent(p) else { return }
        for ch in svc.characteristics ?? [] {
            if ch.uuid == CBUUID(string: Proto.notifyChar) { notifyChar = ch }
            if ch.uuid == CBUUID(string: Proto.writeChar) { writeChar = ch }
        }
        resolveStep(.characteristics, error, "characteristic discovery")
    }

    func peripheral(_ p: CBPeripheral, didUpdateNotificationStateFor ch: CBCharacteristic, error: Error?) {
        guard isCurrent(p), ch.uuid == CBUUID(string: Proto.notifyChar) else { return }
        if error == nil, !ch.isNotifying {
            resolveStep(.notify, BLEError.message("notifications stayed off"), "enabling notifications")
        } else {
            resolveStep(.notify, error, "enabling notifications")
        }
    }

    func peripheral(_ p: CBPeripheral, didWriteValueFor ch: CBCharacteristic, error: Error?) {
        guard isCurrent(p) else { return }
        resolveStep(.write, error, "write")
    }

    func peripheralIsReady(toSendWriteWithoutResponse p: CBPeripheral) {
        guard isCurrent(p) else { return }
        canSendCont?.resume(); canSendCont = nil
    }

    func peripheral(_ p: CBPeripheral, didUpdateValueFor ch: CBCharacteristic, error: Error?) {
        guard isCurrent(p), ch.uuid == CBUUID(string: Proto.notifyChar), let raw = ch.value else { return }
        if let s = session {
            if let inner = s.open(raw) { incoming(inner) }   // nil => replay / undecryptable; drop
        } else {
            incoming(raw)
        }
    }

    // MARK: packet plumbing

    private func incoming(_ pkt: Data) {
        // The device pushes events (cmd 19) on its own. They are not answers to a request, so
        // keep them out of the reply stream.
        if pkt.count >= 3, pkt[pkt.startIndex] == 1, cmdOf(pkt) == Proto.CMD_EVENT {
            handleEvent(pkt)
            return
        }
        if let (cont, item) = waiter { waiter = nil; item.cancel(); cont.resume(returning: pkt) }
        else { buffer.append(pkt) }
    }

    // DeviceEventPushInd: [01][13 00][type u16 @3][seq u16 @5][needAck u8 @7][.. @8-10][payload @11].
    private func handleEvent(_ pkt: Data) {
        guard pkt.count >= 11 else { trace("short event packet \(pkt.count) bytes"); return }
        let type = Int(le16(pkt, 3)), seq = le16(pkt, 5)
        if pkt[pkt.startIndex + 7] == 1 {
            // The app acknowledges with cmd 19: [type u16][seq u16], and expects no reply.
            Task { try? await self.send(Proto.command(Proto.CMD_EVENT, Proto.u16le(UInt16(type)) + Proto.u16le(seq))) }
        }
        let sid = pkt.count >= 15 ? le32(pkt, pkt.startIndex.advanced(by: 11)) : 0
        let value = pkt.count >= 19 ? le32(pkt, pkt.startIndex.advanced(by: 15)) : 0
        let event: DeviceEvent
        switch type {
        case 1: event = .recordingDuration(sessionId: sid, milliseconds: value)
        case 2: event = .bookmark(sessionId: sid)
        case 3: event = .newFile(sessionId: sid, size: value)
        default: event = .other(type: type)
        }
        trace("event \(event)")
        onEvent(event)
    }

    private func failWaiter(_ err: Error) {
        guard let (cont, item) = waiter else { return }
        waiter = nil; item.cancel(); cont.resume(throwing: err)
    }

    private func nextPacket(timeout: TimeInterval) async throws -> Data {
        if !buffer.isEmpty { return buffer.removeFirst() }
        guard peripheral?.state == .connected else { throw BLEError.message("not connected") }
        return try await withCheckedThrowingContinuation { cont in
            let item = DispatchWorkItem { [weak self] in
                guard let self, let w = self.waiter else { return }
                self.waiter = nil
                w.0.resume(throwing: BLEError.timeout("timed out waiting for the device"))
            }
            // Only one reader at a time. A second one must not silently replace the first:
            // the replaced continuation would never resume and its task would hang forever.
            failWaiter(BLEError.message("superseded by another device request"))
            waiter = (cont, item)
            DispatchQueue.main.asyncAfter(deadline: .now() + timeout, execute: item)
        }
    }

    // Sends run one at a time, in call order. Each encrypted packet carries the next sequence
    // number, and the device drops a packet whose number is lower than one it has seen. Two sends
    // that overlap (an event ack and a command) could otherwise reach the radio out of order.
    private var sendTail: Task<Void, Never>?

    private func send(_ data: Data) async throws {
        let previous = sendTail
        let op = Task { @MainActor () async throws in
            _ = await previous?.value
            try await self.sendNow(data)
        }
        sendTail = Task { _ = await op.result }
        try await op.value
    }

    private func sendNow(_ data: Data) async throws {
        guard let w = writeChar, let p = peripheral, p.state == .connected else {
            throw BLEError.message("not connected")
        }
        let payload = try (session?.seal(data)) ?? data
        // Right after connecting, the MTU exchange may still be running and the write limit is
        // 20 bytes. A longer write without response is dropped, and the device never answers.
        var waited = 0
        while payload.count > p.maximumWriteValueLength(for: .withoutResponse), waited < 40 {
            try await Task.sleep(nanoseconds: 50_000_000)
            waited += 1
        }
        guard isCurrent(p), p.state == .connected else { throw BLEError.message("not connected") }
        if payload.count <= p.maximumWriteValueLength(for: .withoutResponse) {
            if !p.canSendWriteWithoutResponse { await waitCanSend(p) }
            guard isCurrent(p) else { throw BLEError.message("not connected") }
            p.writeValue(payload, for: w, type: .withoutResponse)
        } else if w.properties.contains(.write) {
            // CoreBluetooth splits a long write with response for us.
            trace("write of \(payload.count) bytes over the \(p.maximumWriteValueLength(for: .withoutResponse))-byte limit; using write with response")
            try await awaitStep(.write, 10, "The device did not confirm a write.") {
                p.writeValue(payload, for: w, type: .withResponse)
            }
        } else {
            throw BLEError.message("packet of \(payload.count) bytes is over the \(p.maximumWriteValueLength(for: .withoutResponse))-byte link limit")
        }
    }

    // Wait until CoreBluetooth has room for another write without response. Capped at 2 s:
    // some stacks never send the ready callback, and a write then still usually gets through.
    private func waitCanSend(_ p: CBPeripheral) async {
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            canSendCont?.resume()
            canSendCont = cont
            DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [weak self] in
                self?.canSendCont?.resume(); self?.canSendCont = nil
            }
        }
    }

    // MARK: protocol-20 unlock

    private var secretParts: [Int: Data] = [:]
    private var secretTotal: Int?
    private var sawFE11 = false

    func unlockProtocol20(signatureBase64: String, privateKey: SecKey, publicKeyPEM: String) async throws {
        guard let sig = Data(base64Encoded: signatureBase64) else { throw BLEError.fatal("bad signature base64") }
        secretParts.removeAll(); secretTotal = nil; sawFE11 = false
        session = nil; handshakeDone = false
        log("Sending the device signature (\(sig.count) bytes)…")

        // After each chunk, wait for a reply. A Note Pro only answers the last chunk, so the
        // wait after the others is short (it was 3 s, which added 6 s to every connect).
        // Only a timeout is expected here; a disconnect or an unsupported-protocol packet
        // must stop the unlock.
        func sendChunks(_ cmd: UInt16, _ blob: Data) async throws {
            let n = (blob.count + 99) / 100
            for i in 0..<n {
                let slice = blob.subdata(in: (i * 100)..<min((i + 1) * 100, blob.count))
                try await send(Proto.feChunk(cmd, total: n, index: i, slice))
                do { _ = try await collectSecret(timeout: i < n - 1 ? 0.3 : 10) }
                catch BLEError.timeout { trace("no reply to chunk \(i + 1)/\(n) of 0x\(String(cmd, radix: 16))") }
            }
        }

        try await sendChunks(Proto.FE10, sig)
        if sawFE11 {
            log("First bind: sending your public key…")
            secretParts.removeAll()
            try await sendChunks(Proto.FE12, Data(publicKeyPEM.utf8))
        }
        log("Waiting for the session key…")
        do {
            while secretTotal == nil || secretParts.count < (secretTotal ?? 1) {
                _ = try await collectSecret(timeout: 10)
            }
        } catch BLEError.timeout {
            // The app has no "signature rejected" reply either: a device that refuses just goes quiet.
            throw BLEError.timeout("The device did not send the session key (got \(secretParts.count) of \(secretTotal.map(String.init) ?? "?") parts).")
        }
        trace("session secret: \(secretParts.count) parts")

        let blob = secretParts.keys.sorted().reduce(Data()) { acc, k in
            let p = secretParts[k]!
            return acc + p.suffix(from: p.startIndex.advanced(by: 4))
        }
        let plain: Data
        do { plain = try Crypto.rsaDecryptPKCS1(blob, key: privateKey) }
        catch { throw BLEError.fatal("Could not decrypt the session key: the device may hold a different account's key. (\(error))") }
        guard plain.count >= 56 else { throw BLEError.message("session secret too short (\(plain.count))") }
        let key = Data(plain.prefix(32))
        let nonce = plain.subdata(in: plain.startIndex.advanced(by: 32)..<plain.startIndex.advanced(by: 44))
        let aad = plain.subdata(in: plain.startIndex.advanced(by: 44)..<plain.startIndex.advanced(by: 56))

        // Verify the tail decrypts to "PLAUD.AI".
        let tail = Data(plain.suffix(from: plain.startIndex.advanced(by: 56)))
        if tail.count >= 16 {
            let box = try ChaChaPoly.SealedBox(nonce: try ChaChaPoly.Nonce(data: nonce),
                                               ciphertext: tail.prefix(tail.count - 16), tag: tail.suffix(16))
            let v = try ChaChaPoly.open(box, using: SymmetricKey(data: key), authenticating: aad)
            guard v == Data("PLAUD.AI".utf8) else { throw BLEError.message("session check failed") }
        }
        session = Session(key: key, nonce: nonce, aad: aad)
        log("Encrypted session established.")
    }

    private func collectSecret(timeout: TimeInterval) async throws -> Data {
        let pkt = try await nextPacket(timeout: timeout)
        guard pkt.count >= 2 else { return pkt }
        let cmd = UInt16(pkt[pkt.startIndex]) | (UInt16(pkt[pkt.startIndex + 1]) << 8)
        if cmd == Proto.FE30 {
            throw BLEError.fatal("device started an ECC session (0xFE30); this build only supports protocol 20")
        }
        if cmd == Proto.FE11 { sawFE11 = true }
        if cmd == Proto.FE12, pkt.count >= 4 {
            sawFE11 = false
            secretTotal = Int(pkt[pkt.startIndex + 2])
            secretParts[Int(pkt[pkt.startIndex + 3])] = pkt
        }
        return pkt
    }

    // MARK: handshake / list / pull

    func handshake(token: String) async throws {
        try await send(Proto.handshake(token: token, portVersion: portVersion, second: false))
        var rsp = try await waitCommand([Proto.CMD_HANDSHAKE, Proto.CMD_GET_SSN], timeout: 10)
        if cmdOf(rsp) == Proto.CMD_GET_SSN {
            log("Second handshake…")
            try await send(Proto.handshake(token: token, portVersion: portVersion, second: true))
            rsp = try await waitCommand([Proto.CMD_HANDSHAKE], timeout: 10)
        }
        let status = rsp.count > 3 ? Int(rsp[rsp.startIndex + 3]) : -1
        guard status == 0 else { throw BLEError.fatal("The device refused the handshake (status \(status)). It may be bound to another account.") }
        if rsp.count >= 6 { portVersion = Int(rsp[rsp.startIndex + 4]) | (Int(rsp[rsp.startIndex + 5]) << 8) }
        handshakeDone = true
        // Only a device that completed a handshake is remembered as ours.
        if let p = peripheral { UserDefaults.standard.set(p.identifier.uuidString, forKey: BLEManager.knownIdKey) }
        log("Handshake OK (protocol \(portVersion)).")
    }

    func listSessions() async throws -> [RecordingInfo] {
        try await send(Proto.sessionList())
        var files: [RecordingInfo] = []
        var seen = Set<UInt32>()
        var total: Int? = nil
        while total == nil || files.count < total! {
            let b = try await waitCommand([Proto.CMD_GET_REC_SESSIONS], timeout: 15)
            if total == nil, b.count >= 9 { total = Int(b[b.startIndex + 7]) | (Int(b[b.startIndex + 8]) << 8) }
            guard b.count >= 11 else { continue }
            let idx = Int(b[b.startIndex + 9]) | (Int(b[b.startIndex + 10]) << 8)
            if idx != files.count { continue }
            let entry = portVersion == 1 ? 8 : (portVersion <= 6 ? 9 : 10)
            var off = 11
            while off + entry <= b.count {
                let sid = le32(b, b.startIndex.advanced(by: off))
                let size = le32(b, b.startIndex.advanced(by: off + 4))
                if seen.insert(sid).inserted { files.append(RecordingInfo(sessionId: sid, size: size)) }
                off += entry
            }
        }
        return files
    }

    // Download one recording. `existing` holds bytes saved by an earlier, broken download; the
    // transfer starts after them. Inside one connection, a gap or a stall restarts the transfer
    // from the last good byte (the official app does the same). `onChunk` gets each new chunk,
    // so the caller can save progress and resume after a disconnect.
    func pullFile(_ rec: RecordingInfo, existing: Data = Data(), onChunk: (Data) -> Void = { _ in },
                  onProgress: (Int, Int) -> Void) async throws -> PulledFile {
        var data = existing
        let total = Int(rec.size)
        var restarts = 0, progressAtRestart = data.count
        transferCancelled = false
        while true {
            var outcome = PullOutcome.gap
            do {
                outcome = try await pullRange(rec, from: data.count) { chunk in
                    data.append(chunk)
                    onChunk(chunk)
                    onProgress(data.count, total)
                }
            } catch BLEError.timeout {
                trace("transfer of \(rec.sessionId) stalled at \(data.count) of \(total)")
            } catch BLEError.cancelled {
                try? await stopTransfer()   // the device would otherwise keep streaming
                throw BLEError.cancelled
            }
            if transferCancelled { try? await stopTransfer(); throw BLEError.cancelled }
            if case .finished(let crc) = outcome, total == 0 || data.count == total {
                return PulledFile(data: data, tailCRC: crc)
            }
            if total > 0, data.count > total {
                throw BLEError.message("download overran: got \(data.count) of \(total) bytes")
            }
            if case .finished = outcome {
                trace("transfer of \(rec.sessionId) ended early at \(data.count) of \(total)")
            }
            // The budget is for restarts that make no progress; a long download over a noisy
            // link may need many restarts, each one moving forward.
            if data.count > progressAtRestart { restarts = 0; progressAtRestart = data.count }
            restarts += 1
            guard restarts <= 3, peripheral?.state == .connected else {
                // A dropped packet ends the transfer early; never present a short file as complete.
                throw BLEError.message("incomplete download: got \(data.count) of \(total) bytes")
            }
            log("Resuming the download at \(data.count * 100 / max(total, 1))%…")
            try? await stopTransfer()
        }
    }

    private enum PullOutcome { case finished(crc: UInt16?), gap }

    // One sync request from `from` to the end. Returns at the tail packet, or at the first gap.
    private func pullRange(_ rec: RecordingInfo, from: Int, append: (Data) -> Void) async throws -> PullOutcome {
        buffer.removeAll()   // drop stray packets from an earlier, interrupted transfer
        try await send(Proto.syncStart(session: rec.sessionId, start: UInt32(from), end: rec.size))
        let head = try await waitCommand([Proto.CMD_SYNC_FILE_START], timeout: 15)
        if head.count > 7, head[head.startIndex + 7] > 0 {
            throw BLEError.message("device refused sync, status=\(head[head.startIndex + 7])")
        }
        var pos = from
        while true {
            if transferCancelled { throw BLEError.cancelled }
            let pkt = try await nextPacket(timeout: 20)
            // Tail: [01][1d 00][session u32][crc u16].
            if pkt.count >= 3, pkt[pkt.startIndex] == 1, cmdOf(pkt) == Proto.CMD_SYNC_FILE_TAIL {
                return .finished(crc: pkt.count >= 9 ? le16(pkt, 7) : nil)
            }
            guard pkt.count >= 1, pkt[pkt.startIndex] == 2 else { continue }
            var i = 1
            if portVersion >= 7 {
                guard pkt.count >= 5, le32(pkt, pkt.startIndex.advanced(by: 1)) == rec.sessionId else { continue }
                i = 5
            }
            guard pkt.count >= i + 5 else { continue }
            let offset = Int(le32(pkt, pkt.startIndex.advanced(by: i)))
            if offset == 0xFFFF_FFFF { return .finished(crc: nil) }
            let n = Int(pkt[pkt.startIndex.advanced(by: i + 4)])
            let start = pkt.startIndex.advanced(by: i + 5)
            let chunk = pkt.subdata(in: start..<min(start.advanced(by: n), pkt.endIndex))
            if offset < pos { continue }      // a repeat of data we already have
            if offset > pos { return .gap }   // a packet went missing
            append(chunk)
            pos += chunk.count
        }
    }

    // Stop the running download at the user's request. The transfer loop throws `.cancelled`.
    private var transferCancelled = false
    func cancelTransfer() {
        transferCancelled = true
        failWaiter(BLEError.cancelled)
    }

    // syncFileStop: cmd 29, no payload; the device answers with cmd 30.
    func stopTransfer() async throws {
        try await send(Proto.command(Proto.CMD_SYNC_FILE_STOP))
        _ = try await waitCommand([Proto.CMD_SYNC_FILE_STOP_RSP], timeout: 5)
        buffer.removeAll()
    }

    // MARK: helpers

    private func waitCommand(_ cmds: [UInt16], timeout: TimeInterval) async throws -> Data {
        let deadline = Date().addingTimeInterval(timeout)
        while true {
            let remaining = deadline.timeIntervalSinceNow
            if remaining <= 0 { throw BLEError.timeout("timed out waiting for the device") }
            let pkt = try await nextPacket(timeout: remaining)
            if pkt.count >= 3, pkt[pkt.startIndex] == 1, cmds.contains(cmdOf(pkt)) { return pkt }
        }
    }

    // The serial's uppercase hex is the serial string and starts with the 3-digit model code
    // (881 = Note Pro, 888 Note, 880/882 Pin, 860 One). The manufacturer data is
    // [company u16][n][project, n bytes][L][version, L bytes][S][serial, S bytes]; the original
    // Note's serial is 9 bytes (roopen219/plaude-archiver#1, from bitboxx). Read the declared
    // length first; if the data does not have that shape, fall back to the older scan for an
    // 8-byte serial, which is what found the Note Pro's serial so far.
    static func serial(fromManufacturerData data: Data) -> String? {
        let models = ["881", "888", "880", "882", "860"]
        let b = [UInt8](data)
        if b.count > 4 {
            let vAt = 3 + Int(b[2])
            if vAt < b.count {
                let sAt = vAt + 1 + Int(b[vAt])
                if sAt < b.count {
                    let sl = Int(b[sAt])
                    if sl >= 8, sl <= 10, sAt + 1 + sl <= b.count {
                        let s = b[(sAt + 1)..<(sAt + 1 + sl)].map { String(format: "%02X", $0) }.joined()
                        if models.contains(where: { s.hasPrefix($0) }) { return s }
                    }
                }
            }
        }
        let hex = data.map { String(format: "%02X", $0) }.joined()
        var i = hex.startIndex
        while let end = hex.index(i, offsetBy: 16, limitedBy: hex.endIndex) {
            let window = String(hex[i..<end])
            if models.contains(where: { window.hasPrefix($0) }) { return window }
            guard let next = hex.index(i, offsetBy: 2, limitedBy: hex.endIndex) else { break }
            i = next   // stay byte-aligned
        }
        return nil
    }

    private func cmdOf(_ pkt: Data) -> UInt16 {
        UInt16(pkt[pkt.startIndex + 1]) | (UInt16(pkt[pkt.startIndex + 2]) << 8)
    }
    private func le16(_ d: Data, _ o: Int) -> UInt16 {
        UInt16(d[d.startIndex + o]) | (UInt16(d[d.startIndex + o + 1]) << 8)
    }
    private func le32(_ d: Data, _ i: Data.Index) -> UInt32 {
        UInt32(d[i]) | (UInt32(d[i + 1]) << 8) | (UInt32(d[i + 2]) << 16) | (UInt32(d[i + 3]) << 24)
    }
    private func le64(_ d: Data, _ o: Int) -> UInt64 {
        let i = d.startIndex.advanced(by: o)
        var v: UInt64 = 0
        for k in 0..<8 { v |= UInt64(d[i + k]) << (8 * k) }
        return v
    }

    // MARK: raw requests (probing)

    // Send one command and collect every packet that arrives within `window` seconds.
    // For finding out which commands a device answers; callers must only send reads.
    func rawExchange(_ cmd: UInt16, _ params: [UInt8] = [], window: TimeInterval = 1.5) async throws -> [Data] {
        buffer.removeAll()
        try await send(Proto.command(cmd, params))
        var got: [Data] = []
        let deadline = Date().addingTimeInterval(window)
        while true {
            let remaining = deadline.timeIntervalSinceNow
            if remaining <= 0 { break }
            do { got.append(try await nextPacket(timeout: remaining)) }
            catch BLEError.timeout { break }
        }
        return got
    }

    // MARK: device status and management (all after the handshake)

    // getStorage (cmd 6): free, total, duration in the device's units.
    func getStorage() async throws -> StorageInfo {
        try await send(Proto.command(Proto.CMD_GET_STORAGE))
        let b = try await waitCommand([Proto.CMD_GET_STORAGE], timeout: 10)
        guard b.count >= 19 else { throw BLEError.message("short storage reply") }
        let free = le64(b, 3), total = le64(b, 11)
        let dur: UInt64 = b.count >= 27 ? le64(b, 19) : 0
        return StorageInfo(free: free, total: total, durationSeconds: dur)
    }

    // getBattStatus (cmd 9): charging flag + level 0–100.
    func getBattery() async throws -> Battery {
        try await send(Proto.command(Proto.CMD_GET_BATTERY))
        let b = try await waitCommand([Proto.CMD_GET_BATTERY], timeout: 10)
        return Battery(charging: b.count > 3 && b[b.startIndex + 3] == 1,
                       level: b.count > 4 ? Int(b[b.startIndex + 4]) : 0)
    }

    // getState (cmd 3): [state code u32 @3][privacy u8 @7][key state u8 @8][u8 @9][scene u8 @10]
    // [session u32 @11]. The app's DeviceStatus.find: code 4099 = recording, else the key state
    // (0 idle, 1 recording, 2 transfer, 3 switching on, 4 switching off).
    func getRecordingState() async throws -> RecordingState {
        try await send(Proto.command(Proto.CMD_GET_STATE))
        let b = try await waitCommand([Proto.CMD_GET_STATE], timeout: 10)
        let code = b.count >= 7 ? le32(b, b.startIndex.advanced(by: 3)) : 0
        let key = b.count >= 9 ? Int(b[b.startIndex + 8]) : 0
        let sid = b.count >= 15 ? le32(b, b.startIndex.advanced(by: 11)) : 0
        let state: RecordingState.Kind = code == 4099 ? .recording
            : [0: .idle, 1: .recording, 2: .transfer, 3: .switchingOn, 4: .switchingOff][key] ?? .idle
        return RecordingState(state: state, sessionId: sid, rawCode: code, rawKey: key)
    }

    // Delete one recording: send cmd 30 with the session id, wait for cmd 31 + status (0 = deleted).
    func deleteRecording(_ sessionId: UInt32) async throws {
        try await send(Proto.command(Proto.CMD_DELETE_FILE, Proto.u32le(sessionId)))
        let b = try await waitCommand([Proto.CMD_DELETE_FILE_RSP], timeout: 15)
        // status is at byte 7 when the reply echoes the session id (protocol >= 7), else byte 3.
        let status = portVersion >= 7 ? (b.count > 7 ? Int(b[b.startIndex + 7]) : -1)
                                      : (b.count > 3 ? Int(b[b.startIndex + 3]) : -1)
        guard status == 0 else { throw BLEError.message("device refused delete, status=\(status)") }
    }

    // clearRecordFile (cmd 104): delete every recording. Reply status @3 (0 = done).
    func deleteAllRecordings() async throws {
        try await send(Proto.command(Proto.CMD_CLEAR_ALL_FILES))
        let b = try await waitCommand([Proto.CMD_CLEAR_ALL_FILES], timeout: 30)
        let status = b.count > 3 ? Int(b[b.startIndex + 3]) : 0
        guard status == 0 else { throw BLEError.message("device refused to delete all, status=\(status)") }
    }

    // MARK: clock

    // syncTime (cmd 4): [unix seconds u32][timezone hours i8][timezone minutes i8]. The official app
    // sends this on every connect. Recording ids are start times from this clock.
    func syncClock(now: Date = Date()) async throws {
        let offset = TimeZone.current.secondsFromGMT(for: now) / 60
        let hours = Int8(offset / 60), minutes = Int8(offset % 60)
        try await send(Proto.command(Proto.CMD_TIME_SYNC, Proto.u32le(UInt32(now.timeIntervalSince1970))
                                     + [UInt8(bitPattern: hours), UInt8(bitPattern: minutes)]))
        _ = try await waitCommand([Proto.CMD_TIME_SYNC], timeout: 5)
    }

    // MARK: recording control (the official app always passes 0 as the extra argument)

    // startRecord: cmd 20, [1][0]. Reply: session u32 @3, start u32 @7, status u8 @11 (0 = ok).
    func startRecording() async throws -> UInt32 {
        try await send(Proto.command(Proto.CMD_RECORD_START, [1, 0]))
        let b = try await waitCommand([Proto.CMD_RECORD_START], timeout: 10)
        let status = b.count > 11 ? Int(b[b.startIndex + 11]) : 0
        guard status == 0 else { throw BLEError.message("device refused to start recording, status=\(status)") }
        return b.count >= 7 ? le32(b, b.startIndex.advanced(by: 3)) : 0
    }

    // stopRecord: cmd 23, [1][0]. Reply: session u32 @3, reason u8 @7, file exists u8 @8, size u32 @9.
    func stopRecording() async throws {
        try await send(Proto.command(Proto.CMD_RECORD_STOP, [1, 0]))
        _ = try await waitCommand([Proto.CMD_RECORD_STOP], timeout: 10)
    }

    // recordPause / recordResume: cmd 21 / 22, [session u32 (0 below protocol 7)][0].
    func pauseRecording(_ sessionId: UInt32) async throws {
        try await recordControl(Proto.CMD_RECORD_PAUSE, sessionId)
    }

    func resumeRecording(_ sessionId: UInt32) async throws {
        try await recordControl(Proto.CMD_RECORD_RESUME, sessionId)
    }

    private func recordControl(_ cmd: UInt16, _ sessionId: UInt32) async throws {
        let sid = portVersion >= 7 ? sessionId : 0
        try await send(Proto.command(cmd, Proto.u32le(sid) + [0]))
        _ = try await waitCommand([cmd], timeout: 10)
    }

    // MARK: device info

    // getBleDeviceName (cmd 108): the name as zero-padded UTF-8 after the 3-byte header.
    func getDeviceName() async throws -> String {
        try await send(Proto.command(Proto.CMD_GET_NAME))
        return Self.name(from: try await waitCommand([Proto.CMD_GET_NAME], timeout: 5))
    }

    // setBleDeviceName (cmd 107): the name as UTF-8 in 32 zero-padded bytes; the reply is cmd 108.
    func setDeviceName(_ name: String) async throws -> String {
        var bytes = Array(name.utf8)
        guard !bytes.isEmpty, bytes.count <= 32 else { throw BLEError.message("the name must be 1 to 32 bytes") }
        bytes += [UInt8](repeating: 0, count: 32 - bytes.count)
        try await send(Proto.command(Proto.CMD_SET_NAME, bytes))
        return Self.name(from: try await waitCommand([Proto.CMD_GET_NAME], timeout: 5))
    }

    private static func name(from b: Data) -> String {
        let raw = b.dropFirst(3).prefix { $0 != 0 }
        return String(decoding: raw, as: UTF8.self)
    }

    // getDeviceStatus (cmd 141): four raw status bytes. The app only logs them.
    func getDeviceStatus() async throws -> [UInt8] {
        try await send(Proto.command(Proto.CMD_DEVICE_STATUS))
        let b = try await waitCommand([Proto.CMD_DEVICE_STATUS], timeout: 5)
        return Array(b.dropFirst(3).prefix(4))
    }

    // getSyncOtaFileInfo (cmd 151): a pending firmware file. [uid u32 @3][start u32 @7][end u32 @11]
    // [version: type char in the low byte, number in the upper 24 bits, u32 @15].
    func getFirmwareUpdateInfo() async throws -> FirmwareUpdateInfo {
        try await send(Proto.command(Proto.CMD_OTA_INFO))
        let b = try await waitCommand([Proto.CMD_OTA_INFO], timeout: 5)
        guard b.count >= 19 else { throw BLEError.message("short firmware info reply") }
        let v = le32(b, b.startIndex.advanced(by: 15))
        return FirmwareUpdateInfo(start: le32(b, b.startIndex.advanced(by: 7)), end: le32(b, b.startIndex.advanced(by: 11)),
                                  toVersion: v >> 8, toVersionType: v & 0xFF == 0 ? "" : String(UnicodeScalar(UInt8(v & 0xFF))))
    }

    // MARK: settings

    // Common settings (cmd 8): read [1][setting u16], write [2][setting u16][value u32].
    // Reply [setting u16 @3][value u32 @5]; 0xFFFFFFFF means the device does not have the setting.
    func readSetting(_ id: UInt16) async throws -> UInt32? {
        buffer.removeAll()   // a late reply to an earlier, timed-out request must not count as this one
        try await send(Proto.command(Proto.CMD_SETTING, [1] + Proto.u16le(id)))
        return try await settingReply(id)
    }

    func writeSetting(_ id: UInt16, _ value: UInt32) async throws -> UInt32? {
        buffer.removeAll()
        try await send(Proto.command(Proto.CMD_SETTING, [2] + Proto.u16le(id) + Proto.u32le(value)))
        return try await settingReply(id)
    }

    private func settingReply(_ id: UInt16) async throws -> UInt32? {
        let deadline = Date().addingTimeInterval(5)
        while true {
            let b = try await waitCommand([Proto.CMD_SETTING], timeout: max(0.1, deadline.timeIntervalSinceNow))
            guard b.count >= 9, le16(b, 3) == id else { continue }   // a reply for another setting
            let v = le32(b, b.startIndex.advanced(by: 5))
            return v == 0xFFFF_FFFF ? nil : v
        }
    }
}

struct StorageInfo { let free: UInt64; let total: UInt64; let durationSeconds: UInt64 }
struct Battery { let charging: Bool; let level: Int }
struct RecordingState {
    enum Kind { case idle, recording, transfer, switchingOn, switchingOff }
    let state: Kind
    let sessionId: UInt32
    let rawCode: UInt32
    let rawKey: Int
    var recording: Bool { state == .recording }
}
struct PulledFile { let data: Data; let tailCRC: UInt16? }
struct FirmwareUpdateInfo { let start: UInt32; let end: UInt32; let toVersion: UInt32; let toVersionType: String }

enum DeviceEvent: CustomStringConvertible {
    case recordingDuration(sessionId: UInt32, milliseconds: UInt32)
    case bookmark(sessionId: UInt32)
    case newFile(sessionId: UInt32, size: UInt32)
    case other(type: Int)
    var description: String {
        switch self {
        case .recordingDuration(let s, let ms): return "recording \(s) at \(ms) ms"
        case .bookmark(let s): return "bookmark in \(s)"
        case .newFile(let s, let n): return "new file \(s) (\(n) bytes)"
        case .other(let t): return "event type \(t)"
        }
    }
}
