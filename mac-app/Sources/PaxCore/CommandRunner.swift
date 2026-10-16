// SPDX-License-Identifier: GPL-3.0-only
import Foundation

public struct CommandResult: Sendable {
    public let exitCode: Int32
    public let stdout: Data
    public let stderr: Data

    public init(exitCode: Int32, stdout: Data, stderr: Data) {
        self.exitCode = exitCode
        self.stdout = stdout
        self.stderr = stderr
    }

    public var stdoutString: String { String(decoding: stdout, as: UTF8.self) }
    public var stderrString: String { String(decoding: stderr, as: UTF8.self) }
}

/// Abstraction over `Process` so cfgutil calls can be unit-tested.
public protocol CommandRunner: Sendable {
    func run(_ executable: URL, arguments: [String], stdin: Data?) async throws -> CommandResult
}

public struct ProcessRunner: CommandRunner {
    public init() {}

    public func run(_ executable: URL, arguments: [String], stdin: Data?) async throws -> CommandResult {
        try await withCheckedThrowingContinuation { continuation in
            let process = Process()
            process.executableURL = executable
            process.arguments = arguments
            let out = Pipe()
            let err = Pipe()
            process.standardOutput = out
            process.standardError = err
            let input = Pipe()
            if stdin != nil { process.standardInput = input }

            // Collect output on background threads to avoid pipe-buffer deadlocks.
            let outBox = DataBox()
            let errBox = DataBox()
            let group = DispatchGroup()
            group.enter()
            DispatchQueue.global().async {
                outBox.set(out.fileHandleForReading.readDataToEndOfFile())
                group.leave()
            }
            group.enter()
            DispatchQueue.global().async {
                errBox.set(err.fileHandleForReading.readDataToEndOfFile())
                group.leave()
            }
            process.terminationHandler = { proc in
                group.wait()
                continuation.resume(returning: CommandResult(
                    exitCode: proc.terminationStatus, stdout: outBox.get(), stderr: errBox.get()))
            }
            do {
                try process.run()
                if let stdin {
                    input.fileHandleForWriting.write(stdin)
                    try? input.fileHandleForWriting.close()
                }
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }
}

/// Thread-safe holder for pipe output collected on a background queue.
private final class DataBox: @unchecked Sendable {
    private let lock = NSLock()
    private var data = Data()

    func set(_ value: Data) {
        lock.lock(); defer { lock.unlock() }
        data = value
    }

    func get() -> Data {
        lock.lock(); defer { lock.unlock() }
        return data
    }
}
