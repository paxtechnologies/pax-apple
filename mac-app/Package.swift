// swift-tools-version:5.9
// SPDX-License-Identifier: GPL-3.0-only
//
// Build on a Mac with Xcode 15+ command line tools:
//   cd mac-app && swift build && swift run Pax
// The app needs Apple Configurator (Mac App Store) with its "Automation Tools"
// installed (Apple Configurator > Install Automation Tools...), which puts
// `cfgutil` at /usr/local/bin/cfgutil.
import PackageDescription

var targets: [Target] = [
    // Foundation-only logic: device operations, escrow client, setup state.
    .target(name: "PaxCore", path: "Sources/PaxCore"),
    .testTarget(name: "PaxCoreTests", dependencies: ["PaxCore"], path: "Tests/PaxCoreTests"),
]
var products: [Product] = [.library(name: "PaxCore", targets: ["PaxCore"])]
#if os(macOS)
// SwiftUI front end (SwiftUI only exists on macOS; Linux CI/dev builds PaxCore and its tests).
targets.append(.executableTarget(name: "Pax", dependencies: ["PaxCore"], path: "Sources/Pax"))
products.insert(.executable(name: "Pax", targets: ["Pax"]), at: 0)
#endif

let package = Package(
    name: "Pax",
    // v0.8.20: macOS 12 Monterey or later. Anything newer is behind `if #available`.
    platforms: [.macOS(.v12)],
    products: products,
    targets: targets
)
