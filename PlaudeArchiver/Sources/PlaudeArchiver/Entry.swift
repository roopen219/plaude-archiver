import AppKit

@main
struct PlaudApp {
    @MainActor
    static func main() {
        // Hidden self-test: decrypt a downloaded .plaud file with an RSA PEM, write .ogg. For verification.
        let args = CommandLine.arguments
        if args.count == 4, args[1] == "--decrypt" {
            do {
                let data = try Data(contentsOf: URL(fileURLWithPath: args[2]))
                let key = try Crypto.importRSAPrivateKey(pem: try Data(contentsOf: URL(fileURLWithPath: args[3])))
                let out = try Crypto.decryptRecordingFile(data, privateKey: key)
                let dst = (args[2] as NSString).deletingPathExtension + ".swift.ogg"
                try out.write(to: URL(fileURLWithPath: dst))
                FileHandle.standardOutput.write(Data("decrypted \(out.count) bytes -> \(dst)\n".utf8))
                exit(0)
            } catch { FileHandle.standardError.write(Data("selftest error: \(error)\n".utf8)); exit(1) }
        }

        // Hidden offline check: decrypt the .plaud files in a folder and compare with their .ogg.
        if args.count == 3, args[1] == "--check-decrypt" {
            do {
                let report = try DeviceModel().checkDecrypt(folder: URL(fileURLWithPath: args[2]))
                FileHandle.standardOutput.write(Data((report + "\n").utf8))
                exit(0)
            } catch { FileHandle.standardError.write(Data("check error: \(error)\n".utf8)); exit(1) }
        }

        // Hidden headless device checks. --probe-device and --probe-settings only read;
        // --probe-features changes settings and restores them; --test-recording makes a short recording;
        // --selftest downloads and then deletes one recording.
        let modes = ["--probe-device", "--selftest", "--probe-settings", "--probe-features", "--test-recording"]
        if let mode = modes.first(where: args.contains) {
            let model = DeviceModel()
            model.pollingEnabled = false
            Task {
                do {
                    let report: String
                    switch mode {
                    case "--selftest": report = try await model.selfTest()
                    case "--probe-settings": report = try await model.probeSettings()
                    case "--test-recording": report = try await model.testRecording()
                    case "--probe-features":
                        // Optional: --resume-from <earlier .plaud copy of the smallest recording>
                        let i = args.firstIndex(of: "--resume-from")
                        let url = i.flatMap { $0 + 1 < args.count ? URL(fileURLWithPath: args[$0 + 1]) : nil }
                        report = try await model.probeFeatures(resumeFrom: url)
                    default: report = try await model.probe()
                    }
                    FileHandle.standardOutput.write(Data((report + "\n").utf8))
                    exit(0)
                } catch {
                    FileHandle.standardError.write(Data("probe error: \(error)\n".utf8))
                    exit(1)
                }
            }
            // Spin the main run loop so CoreBluetooth (queue: nil = main) delivers callbacks.
            RunLoop.main.run()
            return
        }

        // Hidden README screenshots from sample data; never touches the device or the network.
        if args.count == 3, args[1] == "--screenshots" {
            Screenshots.run(outDir: args[2])
            return
        }

        let app = NSApplication.shared
        let delegate = AppDelegate()
        app.delegate = delegate
        app.run()
    }
}
