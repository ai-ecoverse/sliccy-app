import AppKit

@MainActor
enum FolderPicker {
    static func choose(completion: @escaping @MainActor (URL?) -> Void) {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.prompt = "Choose Folder"
        panel.message = "This preview saves the folder path only. Nothing is read or shared."
        panel.begin { result in completion(result == .OK ? panel.url : nil) }
    }
}
