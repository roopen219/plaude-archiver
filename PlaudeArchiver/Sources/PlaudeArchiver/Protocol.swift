import Foundation
import CryptoKit

// Tinnotech BLE SDK wire protocol (com.tinnotech.penblesdk). Little-endian throughout.
enum Proto {
    // GATT UUIDs for the Plaud service.
    static let service = "1910"
    static let notifyChar = "2BB0"   // device -> app
    static let writeChar  = "2BB1"   // app -> device

    // Command ids.
    static let CMD_HANDSHAKE: UInt16 = 1
    static let CMD_GET_SSN: UInt16 = 2
    static let CMD_GET_STATE: UInt16 = 3        // GetStateRsp: state code, key state, session id
    static let CMD_TIME_SYNC: UInt16 = 4        // [unix u32][tz hours i8][tz minutes i8]
    static let CMD_GET_STORAGE: UInt16 = 6      // StorageRsp: free / total / duration
    static let CMD_SETTING: UInt16 = 8          // common settings: [action u8][setting u16][value u32]
    static let CMD_GET_BATTERY: UInt16 = 9      // BattStatusRsp: charging + level
    static let CMD_EVENT: UInt16 = 19           // device -> app event push; app -> device ack
    static let CMD_RECORD_START: UInt16 = 20
    static let CMD_RECORD_PAUSE: UInt16 = 21
    static let CMD_RECORD_RESUME: UInt16 = 22
    static let CMD_RECORD_STOP: UInt16 = 23
    static let CMD_GET_REC_SESSIONS: UInt16 = 26
    static let CMD_SYNC_FILE_START: UInt16 = 28
    static let CMD_SYNC_FILE_TAIL: UInt16 = 29  // reply; as a request, 29 stops the transfer
    static let CMD_SYNC_FILE_STOP: UInt16 = 29
    static let CMD_SYNC_FILE_STOP_RSP: UInt16 = 30
    static let CMD_DELETE_FILE: UInt16 = 30     // send with session id; reply is CMD_DELETE_FILE_RSP
    static let CMD_DELETE_FILE_RSP: UInt16 = 31 // SyncRecFileDelRsp: status (0 = deleted)
    static let CMD_CLEAR_ALL_FILES: UInt16 = 104
    static let CMD_SET_NAME: UInt16 = 107       // reply is CMD_GET_NAME
    static let CMD_GET_NAME: UInt16 = 108
    static let CMD_DEVICE_STATUS: UInt16 = 141
    static let CMD_OTA_INFO: UInt16 = 151
    static let FE10: UInt16 = 0xFE10   // app -> device: SN signature
    static let FE11: UInt16 = 0xFE11   // device -> app: send your public key
    static let FE12: UInt16 = 0xFE12   // session secret / public-key carrier
    static let FE30: UInt16 = 0xFE30   // ECC start (protocol 30) -> unsupported here

    static func u16le(_ v: UInt16) -> [UInt8] { [UInt8(v & 0xff), UInt8((v >> 8) & 0xff)] }
    static func u32le(_ v: UInt32) -> [UInt8] {
        [UInt8(v & 0xff), UInt8((v >> 8) & 0xff), UInt8((v >> 16) & 0xff), UInt8((v >> 24) & 0xff)]
    }

    // [0x01][cmd u16][params]
    static func command(_ cmd: UInt16, _ params: [UInt8] = []) -> Data {
        Data([0x01] + u16le(cmd) + params)
    }

    // bxa.y(): [01][01 00][02 00][P if pv>=3][token padded to 16 or 32 ASCII chars]
    static func handshake(token: String, portVersion: Int, second: Bool) -> Data {
        let n = portVersion >= 9 ? 32 : 16
        var t = Array(token.utf8)
        if t.count < n { t += [UInt8](repeating: 0x30, count: n - t.count) }  // '0' padding
        t = Array(t.prefix(n))
        var body: [UInt8] = [0x02, 0x00]
        if portVersion >= 3 { body.append(second ? 1 : 0) }
        return command(CMD_HANDSHAKE, body + t)
    }

    // eda: [now u32][start session u32][flag u8]
    static func sessionList(start: UInt32 = 0, flag: UInt8 = 0) -> Data {
        let now = UInt32(Date().timeIntervalSince1970)
        return command(CMD_GET_REC_SESSIONS, u32le(now) + u32le(start) + [flag])
    }

    // ybm: [session u32][start offset u32][end offset u32]
    static func syncStart(session: UInt32, start: UInt32, end: UInt32) -> Data {
        command(CMD_SYNC_FILE_START, u32le(session) + u32le(start) + u32le(end))
    }

    // [cmd u16][total u8][index u8][<=100 bytes] used for FE10/FE12 chunks.
    static func feChunk(_ cmd: UInt16, total: Int, index: Int, _ slice: Data) -> Data {
        // [UInt8] + Data does not compile on Swift 6.2 (#1); join as Data.
        Data(u16le(cmd) + [UInt8(total), UInt8(index)]) + slice
    }
}

// Protocol-20 encrypted session: ChaCha20-Poly1305 over (seq u32 || packet), fixed nonce + AAD.
final class Session {
    private let key: SymmetricKey
    private let nonce: Data
    private let aad: Data
    private var txSeq: UInt32 = 1   // first packet sent uses 2 (g03.M pre-increment)
    private var rxSeq: Int64 = -1

    init(key: Data, nonce: Data, aad: Data) {
        self.key = SymmetricKey(data: key)
        self.nonce = nonce
        self.aad = aad
    }

    func seal(_ plaintext: Data) throws -> Data {
        txSeq &+= 1
        let framed = Data(Proto.u32le(txSeq)) + plaintext
        let box = try ChaChaPoly.seal(framed, using: key,
                                      nonce: try ChaChaPoly.Nonce(data: nonce),
                                      authenticating: aad)
        return box.ciphertext + box.tag   // device expects ct||tag with the fixed nonce
    }

    // Returns the inner packet, or nil if it is a replay or cannot be authenticated.
    func open(_ data: Data) -> Data? {
        guard data.count >= 16 else { return nil }
        let ct = data.prefix(data.count - 16)
        let tag = data.suffix(16)
        guard let box = try? ChaChaPoly.SealedBox(nonce: try ChaChaPoly.Nonce(data: nonce),
                                                  ciphertext: ct, tag: tag),
              let plain = try? ChaChaPoly.open(box, using: key, authenticating: aad),
              plain.count >= 4 else { return nil }
        let seq = Int64(UInt32(plain[plain.startIndex]) | (UInt32(plain[plain.startIndex+1]) << 8)
                        | (UInt32(plain[plain.startIndex+2]) << 16) | (UInt32(plain[plain.startIndex+3]) << 24))
        if seq <= rxSeq { return nil }
        rxSeq = seq
        return plain.suffix(from: plain.startIndex.advanced(by: 4))
    }
}
