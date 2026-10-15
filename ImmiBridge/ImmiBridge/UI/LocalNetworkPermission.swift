import Foundation
import Network

/// Triggers and probes macOS Local Network privacy.
///
/// Plain `URLSession` requests to LAN IPs often fail with
/// "Local network prohibited" *without* ever showing the system dialog, and
/// once the system has recorded a decision the dialog never reappears.
///
/// Strategy (per TN3179):
/// 1. Browse a Bonjour type declared in `NSBonjourServices` (`NWBrowser`).
/// 2. Open a real TCP `NWConnection` to the Immich host when known — that is
///    the operation that actually needs Local Network access.
/// 3. Keep both alive long enough for the user to answer the system sheet.
///
/// Important: while the system sheet is visible, macOS may report
/// `localNetworkDenied` *before* the user answers. That is temporary — we must
/// not treat it as a final denial until the wait window expires.
enum LocalNetworkPermission {
    enum AccessState: Equatable, Sendable {
        case allowed
        case denied
        case undetermined
        case unreachable(String)
    }

    private static let lock = NSLock()
    private static var browser: NWBrowser?
    private static var connection: NWConnection?
    private static var keepAliveWorkItem: DispatchWorkItem?
    private static var reprobeWorkItem: DispatchWorkItem?
    private static var lastObservedState: AccessState = .undetermined
    /// Saw a local-network-denied path while the sheet may still be up.
    private static var sawTransientDenial = false
    private static var activeHost: String?
    private static var activePort: UInt16?

    // MARK: - Fire-and-forget prompt (UI button / onAppear)

    /// Starts Bonjour browse (and optional TCP connect) so TCC can show the sheet.
    /// Safe to call repeatedly; overlaps are coalesced.
    static func requestPrompt(host: String? = nil, port: UInt16? = nil) {
        let work = {
            startProbesOnMain(host: host, port: port, keepAlive: 12.0, reprobing: false)
        }
        if Thread.isMainThread {
            work()
        } else {
            DispatchQueue.main.async(execute: work)
        }
    }

    // MARK: - Awaitable probe (connection test path)

    /// Probes Local Network access by connecting to `host:port`.
    /// If the system sheet is shown, waits up to `timeout` for the user.
    /// Does **not** return `.denied` until the timeout elapses — early denials
    /// while the sheet is open are treated as still undetermined.
    @discardableResult
    static func ensureAccess(
        host: String,
        port: UInt16,
        timeout: TimeInterval = 45
    ) async -> AccessState {
        await withCheckedContinuation { continuation in
            DispatchQueue.main.async {
                startProbesOnMain(host: host, port: port, keepAlive: timeout + 2, reprobing: true)

                let deadline = Date().addingTimeInterval(timeout)
                var finished = false

                func finish(_ state: AccessState) {
                    guard !finished else { return }
                    finished = true
                    continuation.resume(returning: state)
                }

                func poll() {
                    let state: AccessState = {
                        lock.lock()
                        defer { lock.unlock() }
                        return lastObservedState
                    }()

                    switch state {
                    case .allowed:
                        finish(.allowed)
                    case .unreachable(let msg):
                        // Reached the host path — Local Network is effectively granted.
                        finish(.unreachable(msg))
                    case .denied:
                        // Should only appear after we finalize at timeout; still wait.
                        if Date() >= deadline {
                            finish(.denied)
                        } else {
                            DispatchQueue.main.asyncAfter(deadline: .now() + 0.4, execute: poll)
                        }
                    case .undetermined:
                        if Date() >= deadline {
                            lock.lock()
                            let denied = sawTransientDenial
                            lock.unlock()
                            finish(denied ? .denied : .undetermined)
                        } else {
                            DispatchQueue.main.asyncAfter(deadline: .now() + 0.4, execute: poll)
                        }
                    }
                }

                // Give NW a tick to leave `.setup` / enter `.waiting`.
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.35, execute: poll)
            }
        }
    }

    // MARK: - Internals

    private static func startProbesOnMain(
        host: String?,
        port: UInt16?,
        keepAlive: TimeInterval,
        reprobing: Bool
    ) {
        lock.lock()
        browser?.cancel()
        connection?.cancel()
        keepAliveWorkItem?.cancel()
        reprobeWorkItem?.cancel()
        browser = nil
        connection = nil
        keepAliveWorkItem = nil
        reprobeWorkItem = nil
        lastObservedState = .undetermined
        sawTransientDenial = false
        activeHost = host
        activePort = port
        lock.unlock()

        startBonjourBrowse()

        if let host, let port, !host.isEmpty, port > 0 {
            startTCPProbe(host: host, port: port)
        }

        if reprobing, let host, let port, !host.isEmpty, port > 0 {
            scheduleReprobe(host: host, port: port)
        }

        let work = DispatchWorkItem {
            lock.lock()
            browser?.cancel()
            connection?.cancel()
            reprobeWorkItem?.cancel()
            browser = nil
            connection = nil
            keepAliveWorkItem = nil
            reprobeWorkItem = nil
            lock.unlock()
        }
        lock.lock()
        keepAliveWorkItem = work
        lock.unlock()
        DispatchQueue.main.asyncAfter(deadline: .now() + keepAlive, execute: work)
    }

    /// While the permission sheet is open, connections fail immediately with
    /// localNetworkDenied. Restart the TCP probe every few seconds so that
    /// after the user taps Allow we observe `.ready` without another button press.
    private static func scheduleReprobe(host: String, port: UInt16) {
        let work = DispatchWorkItem {
            lock.lock()
            let state = lastObservedState
            let stillTarget = (activeHost == host && activePort == port)
            lock.unlock()
            guard stillTarget else { return }
            switch state {
            case .allowed, .unreachable:
                return
            case .denied, .undetermined:
                startTCPProbe(host: host, port: port)
                scheduleReprobe(host: host, port: port)
            }
        }
        lock.lock()
        reprobeWorkItem?.cancel()
        reprobeWorkItem = work
        lock.unlock()
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.0, execute: work)
    }

    private static func startBonjourBrowse() {
        // Service type must appear in Info.plist → NSBonjourServices.
        let descriptor = NWBrowser.Descriptor.bonjour(type: "_http._tcp", domain: "local.")
        let params = NWParameters()
        params.includePeerToPeer = true
        let newBrowser = NWBrowser(for: descriptor, using: params)
        newBrowser.stateUpdateHandler = { state in
            switch state {
            case .ready:
                break
            case .waiting(let error), .failed(let error):
                if isLocalNetworkDenied(error) {
                    noteTransientDenial()
                }
            default:
                break
            }
        }
        newBrowser.browseResultsChangedHandler = { _, _ in
            // Finding any result implies LAN browse is allowed.
            lock.lock()
            lastObservedState = .allowed
            lock.unlock()
        }
        newBrowser.start(queue: .main)

        lock.lock()
        browser = newBrowser
        lock.unlock()
    }

    private static func startTCPProbe(host: String, port: UInt16) {
        let nwHost = NWEndpoint.Host(host)
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { return }

        lock.lock()
        connection?.cancel()
        connection = nil
        lock.unlock()

        let params = NWParameters.tcp
        params.prohibitExpensivePaths = false
        params.includePeerToPeer = false

        let conn = NWConnection(host: nwHost, port: nwPort, using: params)
        conn.stateUpdateHandler = { state in
            switch state {
            case .ready:
                lock.lock()
                lastObservedState = .allowed
                lock.unlock()
                conn.cancel()
            case .waiting(let error):
                if isLocalNetworkDenied(error)
                    || conn.currentPath?.unsatisfiedReason == .localNetworkDenied {
                    // Temporary while the system sheet is up — do not finalize.
                    noteTransientDenial()
                }
            case .failed(let error):
                if isLocalNetworkDenied(error) {
                    noteTransientDenial()
                } else {
                    lock.lock()
                    // Connection refused / host unreachable still means LAN access worked.
                    if lastObservedState != .allowed {
                        lastObservedState = .unreachable(error.localizedDescription)
                    }
                    lock.unlock()
                }
            case .cancelled:
                break
            default:
                break
            }
        }
        conn.start(queue: .main)

        lock.lock()
        connection = conn
        lock.unlock()
    }

    private static func noteTransientDenial() {
        lock.lock()
        sawTransientDenial = true
        // Stay undetermined until timeout so the UI can wait for Allow.
        // Do not clobber a successful allow / reachability result.
        switch lastObservedState {
        case .allowed, .unreachable:
            break
        case .denied, .undetermined:
            lastObservedState = .undetermined
        }
        lock.unlock()
    }

    private static func isLocalNetworkDenied(_ error: NWError) -> Bool {
        // kDNSServiceErr_PolicyDenied (-65570) — Local Network privacy denied.
        if case .dns(let code) = error, Int32(code) == -65570 {
            return true
        }
        let text = String(describing: error).lowercased()
        if text.contains("local network") && (text.contains("denied") || text.contains("prohibited")) {
            return true
        }
        if text.contains("policy denied") {
            return true
        }
        return false
    }

    /// Parse host + port from an Immich base URL string (e.g. `http://192.168.0.200:2283`).
    static func hostPort(from urlString: String) -> (host: String, port: UInt16)? {
        guard let url = URL(string: urlString.trimmingCharacters(in: .whitespacesAndNewlines)),
              let host = url.host, !host.isEmpty else { return nil }
        let scheme = (url.scheme ?? "http").lowercased()
        let port: UInt16
        if let p = url.port {
            port = UInt16(clamping: p)
        } else {
            port = (scheme == "https") ? 443 : 80
        }
        return (host, port)
    }
}
