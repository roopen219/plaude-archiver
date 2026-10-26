import Foundation
import CryptoKit
import CommonCrypto
import Security

enum CryptoError: Error, CustomStringConvertible {
    case message(String)
    var description: String { if case .message(let m) = self { return m }; return "crypto error" }
}

enum Crypto {

    // MARK: base64url

    static func base64urlDecode(_ s: String) -> Data? {
        var t = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while t.count % 4 != 0 { t += "=" }
        return Data(base64Encoded: t)
    }

    // MARK: Fernet (x-encrypt-response: 1)
    // Key baked into the Plaud app (class wng). 32 bytes: HMAC key [0:16], AES key [16:32].

    static let fernetKey = base64urlDecode("8rRmMCskL3NaUiGr-UsmEEeI8NKH-ZfeGbpRGqSLpuI=")!

    static func fernetDecrypt(_ token: String) throws -> Data {
        guard let raw = base64urlDecode(token.trimmingCharacters(in: .whitespacesAndNewlines)) else {
            throw CryptoError.message("Fernet: bad base64")
        }
        guard raw.count >= 73, raw[raw.startIndex] == 0x80 else {
            throw CryptoError.message("Fernet: bad version/length")
        }
        let body = raw.prefix(raw.count - 32)
        let mac = raw.suffix(32)
        let hmacKey = SymmetricKey(data: fernetKey.prefix(16))
        let good = HMAC<SHA256>.isValidAuthenticationCode(mac, authenticating: body, using: hmacKey)
        guard good else { throw CryptoError.message("Fernet: HMAC check failed") }
        let iv = raw.subdata(in: raw.startIndex.advanced(by: 9) ..< raw.startIndex.advanced(by: 25))
        let ct = raw.subdata(in: raw.startIndex.advanced(by: 25) ..< (raw.startIndex.advanced(by: raw.count - 32)))
        return try aesCBCDecrypt(ct, key: fernetKey.suffix(16), iv: iv)
    }

    static func aesCBCDecrypt(_ data: Data, key: Data, iv: Data) throws -> Data {
        var out = Data(count: data.count + kCCBlockSizeAES128)
        let outCapacity = out.count
        var moved = 0
        let status = out.withUnsafeMutableBytes { outBuf in
            data.withUnsafeBytes { dataBuf in
                key.withUnsafeBytes { keyBuf in
                    iv.withUnsafeBytes { ivBuf in
                        CCCrypt(CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES),
                                CCOptions(kCCOptionPKCS7Padding),
                                keyBuf.baseAddress, key.count,
                                ivBuf.baseAddress,
                                dataBuf.baseAddress, data.count,
                                outBuf.baseAddress, outCapacity, &moved)
                    }
                }
            }
        }
        guard status == kCCSuccess else { throw CryptoError.message("AES-CBC failed (\(status))") }
        out.removeSubrange(moved..<out.count)
        return out
    }

    // MARK: RSA private key from gen_key PEM; PKCS#1 v1.5 decrypt.

    static func importRSAPrivateKey(pem: Data) throws -> SecKey {
        let text = String(data: pem, encoding: .utf8) ?? ""
        let b64 = text
            .replacingOccurrences(of: "-----BEGIN PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "-----END PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "-----BEGIN RSA PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "-----END RSA PRIVATE KEY-----", with: "")
            .components(separatedBy: .whitespacesAndNewlines).joined()
        guard let der = Data(base64Encoded: b64) else { throw CryptoError.message("RSA: bad PEM base64") }
        // gen_key returns PKCS#8; SecKeyCreateWithData wants PKCS#1. Unwrap if needed.
        let pkcs1 = text.contains("RSA PRIVATE KEY") ? der : try pkcs8ToPKCS1(der)
        let attrs: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits: 2048,
        ]
        var err: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(pkcs1 as CFData, attrs as CFDictionary, &err) else {
            throw CryptoError.message("RSA import failed: \(err?.takeRetainedValue().localizedDescription ?? "?")")
        }
        return key
    }

    // Extract the PKCS#1 RSAPrivateKey from a PKCS#8 PrivateKeyInfo DER.
    private static func pkcs8ToPKCS1(_ der: Data) throws -> Data {
        let b = [UInt8](der)
        var i = 0
        func readTLV() throws -> (tag: UInt8, start: Int, len: Int) {
            guard i + 2 <= b.count else { throw CryptoError.message("DER truncated") }
            let tag = b[i]; i += 1
            var len = Int(b[i]); i += 1
            if len & 0x80 != 0 {
                let n = len & 0x7f
                guard n <= 4, i + n <= b.count else { throw CryptoError.message("DER bad length") }
                len = 0
                for _ in 0..<n { len = (len << 8) | Int(b[i]); i += 1 }
            }
            let start = i
            guard len >= 0, start + len <= b.count else { throw CryptoError.message("DER length overflow") }
            i += len
            return (tag, start, len)
        }
        let seq = try readTLV()                 // SEQUENCE PrivateKeyInfo
        guard seq.tag == 0x30 else { throw CryptoError.message("DER: expected SEQUENCE") }
        i = seq.start
        _ = try readTLV()                       // INTEGER version
        let alg = try readTLV(); i = alg.start + alg.len   // SEQUENCE AlgorithmIdentifier (skip)
        let oct = try readTLV()                 // OCTET STRING = PKCS#1
        guard oct.tag == 0x04 else { throw CryptoError.message("DER: expected OCTET STRING") }
        return Data(b[oct.start ..< oct.start + oct.len])
    }

    static func rsaDecryptPKCS1(_ cipher: Data, key: SecKey) throws -> Data {
        var err: Unmanaged<CFError>?
        guard let plain = SecKeyCreateDecryptedData(key, .rsaEncryptionPKCS1, cipher as CFData, &err) else {
            throw CryptoError.message("RSA decrypt failed: \(err?.takeRetainedValue().localizedDescription ?? "?")")
        }
        return plain as Data
    }

    // MARK: Plain ChaCha20 (RFC 8439) for recording file content (fem.a.a).
    // 32-byte key, 12-byte nonce, 32-bit block counter.

    private static func rotl(_ x: UInt32, _ n: UInt32) -> UInt32 { (x << n) | (x >> (32 - n)) }

    private static func quarterRound(_ s: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int) {
        s[a] = s[a] &+ s[b]; s[d] = rotl(s[d] ^ s[a], 16)
        s[c] = s[c] &+ s[d]; s[b] = rotl(s[b] ^ s[c], 12)
        s[a] = s[a] &+ s[b]; s[d] = rotl(s[d] ^ s[a], 8)
        s[c] = s[c] &+ s[d]; s[b] = rotl(s[b] ^ s[c], 7)
    }

    private static func chachaBlock(key: [UInt32], counter: UInt32, nonce: [UInt32]) -> [UInt8] {
        var state = [UInt32](repeating: 0, count: 16)
        state[0] = 0x61707865; state[1] = 0x3320646e; state[2] = 0x79622d32; state[3] = 0x6b206574
        for i in 0..<8 { state[4 + i] = key[i] }
        state[12] = counter
        for i in 0..<3 { state[13 + i] = nonce[i] }
        var working = state
        for _ in 0..<10 {
            quarterRound(&working, 0, 4, 8, 12)
            quarterRound(&working, 1, 5, 9, 13)
            quarterRound(&working, 2, 6, 10, 14)
            quarterRound(&working, 3, 7, 11, 15)
            quarterRound(&working, 0, 5, 10, 15)
            quarterRound(&working, 1, 6, 11, 12)
            quarterRound(&working, 2, 7, 8, 13)
            quarterRound(&working, 3, 4, 9, 14)
        }
        var out = [UInt8]()
        out.reserveCapacity(64)
        for i in 0..<16 {
            let v = working[i] &+ state[i]
            out.append(UInt8(v & 0xff)); out.append(UInt8((v >> 8) & 0xff))
            out.append(UInt8((v >> 16) & 0xff)); out.append(UInt8((v >> 24) & 0xff))
        }
        return out
    }

    static func chacha20(_ data: Data, key: Data, nonce: Data, counter: UInt32) -> Data {
        func words(_ d: Data) -> [UInt32] {
            var w = [UInt32]()
            var i = d.startIndex
            while i < d.endIndex {
                let b0 = UInt32(d[i]); let b1 = UInt32(d[i+1]); let b2 = UInt32(d[i+2]); let b3 = UInt32(d[i+3])
                w.append(b0 | (b1 << 8) | (b2 << 16) | (b3 << 24))
                i = i.advanced(by: 4)
            }
            return w
        }
        let k = words(key), n = words(nonce)
        let bytes = [UInt8](data)
        var out = [UInt8](repeating: 0, count: bytes.count)
        var blockCounter = counter
        var off = 0
        while off < bytes.count {
            let ks = chachaBlock(key: k, counter: blockCounter, nonce: n)
            let end = min(64, bytes.count - off)
            for i in 0..<end { out[off + i] = bytes[off + i] ^ ks[i] }
            off += end
            blockCounter &+= 1
        }
        return Data(out)
    }

    // MARK: A full recording file ("PLAUD.AI", version 1) -> Ogg Opus.

    static func decryptRecordingFile(_ data: Data, privateKey: SecKey) throws -> Data {
        guard data.count >= 512, data.prefix(8) == Data("PLAUD.AI".utf8) else {
            throw CryptoError.message("not a PLAUD.AI file")
        }
        func u16(_ off: Int) -> Int { Int(data[off]) | (Int(data[off+1]) << 8) }
        func u32(_ off: Int) -> UInt32 {
            UInt32(data[off]) | (UInt32(data[off+1]) << 8) | (UInt32(data[off+2]) << 16) | (UInt32(data[off+3]) << 24)
        }
        let version = u16(8)
        guard version == 1 else {
            throw CryptoError.message("header version \(version) not supported (version 2 = ECDH, protocol 30)")
        }
        let headerSize = u16(10)
        guard headerSize >= 512, headerSize <= data.count else {
            throw CryptoError.message("bad header size \(headerSize)")
        }
        let counter = u32(128)
        let nonce = data.subdata(in: 132..<144)
        let keyCipher = data.subdata(in: 256..<512)
        var contentKey = try rsaDecryptPKCS1(keyCipher, key: privateKey)
        if contentKey.count > 32 { contentKey = contentKey.suffix(32) }  // firmware anomaly fallback
        guard contentKey.count == 32 else { throw CryptoError.message("content key wrong length") }
        let body = data.subdata(in: headerSize..<data.count)
        return try decryptBody(body, key: contentKey, nonce: nonce, counter: counter, segmentSize: Int(u32(144)))
    }

    // Two body layouts, chosen by the header's segment size (u32 at 144):
    // - 0 (the Note Pro): one ChaCha20 stream from the header's counter, and the result is Ogg.
    // - above 0 (the original Note: 80): each segment is encrypted on its own, with the block
    //   counter back at 0 (the official app's yl7.a passes 0 for every segment). The result is
    //   bare Opus frames, one per segment, which are wrapped in Ogg here.
    // Reported with a patch by bitboxx in roopen219/plaude-archiver#1.
    static func decryptBody(_ body: Data, key: Data, nonce: Data, counter: UInt32, segmentSize: Int) throws -> Data {
        guard segmentSize > 0 else { return chacha20(body, key: key, nonce: nonce, counter: counter) }
        guard segmentSize <= 4096 else { throw CryptoError.message("segment size \(segmentSize) not supported") }
        var clear = Data(capacity: body.count)
        var off = body.startIndex
        while off < body.endIndex {
            let end = min(off + segmentSize, body.endIndex)
            clear.append(chacha20(body.subdata(in: off..<end), key: key, nonce: nonce, counter: 0))
            off = end
        }
        if clear.prefix(4) == Data("OggS".utf8) { return clear }
        // The Ogg pages below are built here, so their CRCs prove nothing about the decrypt.
        // Check the frames themselves first, by the official app's rule.
        guard opusFramesLookValid(clear, frameBytes: segmentSize) else {
            throw CryptoError.message("the decrypted audio is not Opus frames; the key or the segment layout is wrong")
        }
        return OggOpus.wrap(clear, frameBytes: segmentSize)
    }

    // The official app's check for bare-frame recordings (fem.a.o): skip all-zero frames; every
    // other frame starts with Opus TOC byte 0xB8 or 0xB9 (CELT wideband, 20 ms, mono). It allows
    // fewer than 5 frames that do not.
    static func opusFramesLookValid(_ data: Data, frameBytes: Int) -> Bool {
        let d = [UInt8](data)
        guard frameBytes > 0, d.count >= frameBytes else { return false }
        var nonZero = 0, valid = 0
        var i = 0
        while i + frameBytes <= d.count {
            if d[i..<(i + frameBytes)].contains(where: { $0 != 0 }) {
                nonZero += 1
                if d[i] == 0xB8 || d[i] == 0xB9 { valid += 1 }
            }
            i += frameBytes
        }
        return nonZero > 0 && nonZero - valid < 5
    }

    // MARK: Ogg integrity

    // True when `data` is a whole Ogg stream: pages back to back to the last byte, every page's
    // CRC-32 correct, and the last page marked end-of-stream. The recording cipher (ChaCha20) has
    // no authentication tag, so a damaged download still "decrypts"; this is the check that a
    // local copy is safe before the device's copy is deleted.
    static func isCompleteOgg(_ data: Data) -> Bool {
        let d = [UInt8](data)
        var i = 0
        var lastHeaderType: UInt8 = 0
        while i < d.count {
            guard i + 27 <= d.count, d[i] == 0x4F, d[i + 1] == 0x67, d[i + 2] == 0x67, d[i + 3] == 0x53 else { return false }
            let segments = Int(d[i + 26])
            guard i + 27 + segments <= d.count else { return false }
            let body = d[(i + 27)..<(i + 27 + segments)].reduce(0) { $0 + Int($1) }
            let size = 27 + segments + body
            guard i + size <= d.count else { return false }
            let stored = UInt32(d[i + 22]) | UInt32(d[i + 23]) << 8 | UInt32(d[i + 24]) << 16 | UInt32(d[i + 25]) << 24
            var crc: UInt32 = 0
            for k in i..<(i + size) {
                let byte = (k >= i + 22 && k < i + 26) ? 0 : d[k]   // the CRC field counts as zero
                crc = (crc << 8) ^ oggCRCTable[Int((crc >> 24) ^ UInt32(byte))]
            }
            guard crc == stored else { return false }
            lastHeaderType = d[i + 5]
            i += size
        }
        return !d.isEmpty && lastHeaderType & 0x04 != 0
    }

    // CRC-32 with polynomial 0x04C11DB7, not reflected, initial value 0 (the Ogg spec).
    private static let oggCRCTable: [UInt32] = (0..<256).map { n in
        var c = UInt32(n) << 24
        for _ in 0..<8 { c = c & 0x8000_0000 != 0 ? (c << 1) ^ 0x04C1_1DB7 : c << 1 }
        return c
    }
}

// Wraps the original Note's bare Opus frames (CELT wideband, 20 ms, mono, one frame per segment)
// in an Ogg Opus stream, one frame per packet and 50 frames per page.
// From bitboxx's patch in roopen219/plaude-archiver#1; checked there against an independent decoder.
enum OggOpus {
    private static let crcTable: [UInt32] = (0..<256).map { i -> UInt32 in
        var r = UInt32(i) << 24
        for _ in 0..<8 { r = (r & 0x8000_0000) != 0 ? (r << 1) ^ 0x04C1_1DB7 : r << 1 }
        return r
    }

    private static func le<T: FixedWidthInteger>(_ v: T) -> Data { withUnsafeBytes(of: v.littleEndian) { Data($0) } }

    private static func page(_ serial: UInt32, _ seq: UInt32, _ granule: UInt64, _ packets: [Data], _ type: UInt8) -> Data {
        var lacing = [UInt8]()
        for p in packets { lacing += Array(repeating: 255, count: p.count / 255); lacing.append(UInt8(p.count % 255)) }
        var out = Data("OggS".utf8)
        out.append(contentsOf: [0, type])
        out.append(le(granule)); out.append(le(serial)); out.append(le(seq))
        out.append(contentsOf: [0, 0, 0, 0, UInt8(lacing.count)])
        out.append(contentsOf: lacing)
        for p in packets { out.append(p) }
        var crc: UInt32 = 0
        for b in out { crc = (crc << 8) ^ crcTable[Int(((crc >> 24) ^ UInt32(b)) & 0xFF)] }
        out.replaceSubrange(22..<26, with: le(crc))
        return out
    }

    static func wrap(_ raw: Data, frameBytes: Int = 80, inputRate: UInt32 = 16000) -> Data {
        let bytes = [UInt8](raw)
        let frames = stride(from: 0, to: bytes.count - frameBytes + 1, by: frameBytes).map { Data(bytes[$0..<($0 + frameBytes)]) }
        let serial: UInt32 = 0x504C_4144
        var head = Data("OpusHead".utf8)
        head.append(contentsOf: [1, 1])                       // version 1, one channel
        head.append(le(UInt16(312))); head.append(le(inputRate))
        head.append(contentsOf: [0, 0, 0])                    // output gain, mapping family 0
        var tags = Data("OpusTags".utf8)
        tags.append(le(UInt32(6))); tags.append(Data("plaude".utf8)); tags.append(le(UInt32(0)))
        var out = page(serial, 0, 0, [head], 0x02)
        out.append(page(serial, 1, 0, [tags], 0x00))
        var seq: UInt32 = 2, granule: UInt64 = 0, i = 0
        while i < frames.count {
            let chunk = Array(frames[i..<min(i + 50, frames.count)])
            granule += 960 * UInt64(chunk.count)              // 20 ms at 48 kHz per frame
            out.append(page(serial, seq, granule, chunk, i + 50 >= frames.count ? 0x04 : 0x00))
            seq += 1; i += 50
        }
        return out
    }
}
