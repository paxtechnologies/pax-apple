// SPDX-License-Identifier: GPL-3.0-only
import SwiftUI

// v0.8.20: Pax runs on macOS 12 Monterey or later. SwiftUI that only exists on
// macOS 13+ goes through these small wrappers, so macOS 13 and later look exactly
// as before and macOS 12 gets the nearest calm equivalent.

/// A text field that grows from one to four lines as you type (macOS 13+). On
/// macOS 12 it is a normal one-line field: long text scrolls inside it, and pasting
/// works the same.
struct GrowingTextField: View {
    let placeholder: String
    @Binding var text: String

    init(_ placeholder: String, text: Binding<String>) {
        self.placeholder = placeholder
        self._text = text
    }

    var body: some View {
        if #available(macOS 13, *) {
            TextField(placeholder, text: $text, axis: .vertical)
                .lineLimit(1...4)
        } else {
            TextField(placeholder, text: $text)
        }
    }
}
