import Foundation

enum DemoData {
    static let browsers: [BrowserTarget] = [
        .init(id: "chrome", name: "Google Chrome", bundleID: "com.google.Chrome", subtitle: "Separate profiles · Browser automation", symbol: "globe", canHost: true),
        .init(id: "safari", name: "Safari", bundleID: "com.apple.Safari", subtitle: "Everyday-browser pairing · No browser automation", symbol: "safari", canHost: true),
        .init(id: "edge", name: "Microsoft Edge", bundleID: "com.microsoft.edgemac", subtitle: "Separate profiles · Browser automation", symbol: "globe", canHost: true),
        .init(id: "vscode", name: "Visual Studio Code", bundleID: "com.microsoft.VSCode", subtitle: "Electron app · Attach to an existing session", symbol: "chevron.left.forwardslash.chevron.right", canHost: false)
    ]

    static func sessions() -> [Session] {
        [
            Session(name: "Website review", device: "This Mac", kind: .browser, profile: "Review", isFavorite: true, entries: [
                .init(role: .user, text: "Review the landing page’s accessibility. Focus on keyboard navigation and the sign-up form."),
                .init(role: .tool, text: "Inspected navigation and 4 form controls"),
                .init(role: .assistant, text: "The main navigation works well with the keyboard. I found two improvements for the sign-up form:\n\n**Give the email field a visible label.** Its placeholder disappears as soon as someone starts typing.\n\n**Make the error actionable.** Move the validation message beside the field and associate it with the input.\n\nThe page structure is otherwise clear, with a single heading and a predictable focus order."),
                .init(role: .notice, text: "Sample activity · No website was accessed")
            ], access: .init(browser: "Google Chrome", folders: [.init(name: "website", path: "~/Projects/website")])),
            Session(name: "Research", device: "Mac mini", kind: .remote, profile: "Research", entries: [
                .init(role: .user, text: "Compare the papers and make a reading list for the team."),
                .init(role: .assistant, text: "I’ve grouped the reading list into background, methods, and open questions. Share another paper or send a follow-up to refine the selection."),
                .init(role: .notice, text: "Sample activity · No documents were read")
            ], access: .init(folders: [.init(name: "papers", path: "~/Documents/papers")])),
            Session(name: "Everyday", device: "This Mac", kind: .everyday, profile: "Default browser", connection: .disconnected, entries: [], access: .init())
        ]
    }
}
