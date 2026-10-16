// SPDX-License-Identifier: GPL-3.0-only
import SwiftUI
import AppKit
import UniformTypeIdentifiers
import PaxCore

/// v0.7.0 "Import list": paste a list or choose a .txt/.csv file, see how many
/// sites it holds, then add them all. Comments, blank lines and anything that
/// isn't a website are skipped and counted.
struct ImportListSheet: View {
    /// Already on the list (not counted as new).
    let alreadyBlocked: Set<String>
    /// Room left.
    let cap: Int
    /// Show the iPhone web-filter note.
    var forIPhoneProfile = false
    let onAdd: (_ sites: [String], _ skipped: Int) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var text = ""
    @State private var fileName: String?
    @State private var fileError: String?

    private var result: BulkSiteImport.Result {
        BulkSiteImport.parse(text, alreadyBlocked: alreadyBlocked, cap: cap)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Import a list").font(Theme.heading(24)).foregroundStyle(Theme.primaryText)
            Text("Paste sites, one per line, or choose a .txt or .csv file. Web addresses and hosts-file "
                 + "lines work too. Lines starting with # or ! are ignored.")
                .font(Theme.body(13)).foregroundStyle(Theme.mutedText)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 12) {
                Button("Choose file…") { chooseFile() }.buttonStyle(SecondaryButtonStyle())
                if let fileName {
                    Text(fileName).font(Theme.body(12)).foregroundStyle(Theme.mutedText).lineLimit(1)
                }
            }
            TextEditor(text: $text)
                .font(.system(size: 12, design: .monospaced))
                .frame(minHeight: 180)
                .overlay(RoundedRectangle(cornerRadius: Theme.smallRadius).stroke(Theme.border))
            preview
            HStack {
                Button("Cancel") { dismiss() }.buttonStyle(SecondaryButtonStyle())
                Spacer()
                Button(result.sites.isEmpty ? "Add sites"
                       : "Add \(result.sites.count) site\(result.sites.count == 1 ? "" : "s")") {
                    onAdd(result.sites, result.skipped)
                    dismiss()
                }
                .buttonStyle(PrimaryButtonStyle(accent: true))
                .disabled(result.sites.isEmpty)
            }
        }
        .padding(28)
        .frame(width: 560)
        .background(Theme.background)
    }

    @ViewBuilder private var preview: some View {
        let r = result
        VStack(alignment: .leading, spacing: 6) {
            if text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                Text("Nothing to add yet.").font(Theme.body(13)).foregroundStyle(Theme.mutedText)
            } else {
                Text("Ready to add \(r.sites.count) site\(r.sites.count == 1 ? "" : "s").")
                    .font(Theme.body(14, weight: .medium)).foregroundStyle(Theme.primaryText)
                if r.skipped > 0 {
                    Text("\(r.skipped) entr\(r.skipped == 1 ? "y wasn't a website" : "ies weren't websites") and will be skipped.")
                        .font(Theme.body(12.5)).foregroundStyle(Theme.mutedText)
                }
                if r.duplicates > 0 {
                    Text("\(r.duplicates) repeat\(r.duplicates == 1 ? "" : "s") or already on your list.")
                        .font(Theme.body(12.5)).foregroundStyle(Theme.mutedText)
                }
                if r.capReached {
                    Text("Your list holds up to \(min(cap, BulkSiteImport.maxPerImport)) more sites, so the "
                         + "last \(r.overCap) won't be added.")
                        .font(Theme.body(12.5)).foregroundStyle(Theme.accent)
                }
            }
            if forIPhoneProfile && r.sites.count > BulkSiteImport.iosCustomLimit {
                Text("Your iPhone's own web filter keeps the first \(BulkSiteImport.iosCustomLimit). The rest are "
                     + "still blocked through Pax's filter once it's running.")
                    .font(Theme.body(12.5)).foregroundStyle(Theme.accent)
            }
            if let fileError {
                Text(fileError).font(Theme.body(12.5)).foregroundStyle(Theme.accent)
            }
        }
    }

    private func chooseFile() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.plainText, .commaSeparatedText, .text]
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        // A sane size: big blocklists are a few MB; anything much larger isn't a list.
        if let size = try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize, size > 8_000_000 {
            fileError = "That file is too big to be a list of sites (over 8 MB)."
            return
        }
        guard let data = try? Data(contentsOf: url) else {
            fileError = "Pax couldn't open that file."
            return
        }
        text = String(decoding: data, as: UTF8.self)
        fileName = url.lastPathComponent
        fileError = nil
    }
}
