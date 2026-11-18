import AppKit
import Foundation
import UserNotifications

@MainActor
protocol ApprovalNotifying: AnyObject {
    func post(_ item: ApprovalItem, session: UUID, title: String)
    func withdraw(_ items: [String], session: UUID)
}

/// macOS notifications for new approvals, with Allow once and Deny. A notification never offers Always.
@MainActor
final class ApprovalNotifier: NSObject, ApprovalNotifying, UNUserNotificationCenterDelegate {
    static let category = "sliccy.approval"
    /// The only answers a notification offers.
    static let answers: [ApprovalAnswer] = [.once, .deny]
    private let answer: @MainActor (UUID, String, ApprovalAnswer) -> Void
    private let open: @MainActor (UUID) -> Void
    private var authorization: Task<Bool, Never>?
    /// Posted identifiers not yet withdrawn. A post waiting for authorization is dropped once withdrawn.
    private var pending: Set<String> = []

    /// Notification Center needs a bundled app; tests and `swift run` get no notifier.
    static func make(answer: @escaping @MainActor (UUID, String, ApprovalAnswer) -> Void,
                     open: @escaping @MainActor (UUID) -> Void) -> ApprovalNotifier? {
        guard Bundle.main.bundleURL.pathExtension == "app", Bundle.main.bundleIdentifier != nil else { return nil }
        return ApprovalNotifier(answer: answer, open: open)
    }

    private init(answer: @escaping @MainActor (UUID, String, ApprovalAnswer) -> Void, open: @escaping @MainActor (UUID) -> Void) {
        self.answer = answer
        self.open = open
        super.init()
        let center = UNUserNotificationCenter.current()
        center.delegate = self
        let actions = Self.answers.map { answer in
            // Allowing from a locked Mac needs the user to unlock; a fast Deny stays possible.
            UNNotificationAction(identifier: answer.rawValue, title: answer.title, options: answer == .deny ? [.destructive] : [.authenticationRequired])
        }
        center.setNotificationCategories([UNNotificationCategory(identifier: Self.category, actions: actions, intentIdentifiers: [])])
    }

    static func identifier(_ item: String, session: UUID) -> String { "approval/\(session.uuidString)/\(item)" }

    func post(_ item: ApprovalItem, session: UUID, title: String) {
        let content = UNMutableNotificationContent()
        content.title = "\(title): \(item.kindLabel)"
        content.subtitle = item.agentLabel
        let detail = item.detailText
        content.body = detail.count > 200 ? String(detail.prefix(199)) + "…" : detail
        content.categoryIdentifier = Self.category
        content.userInfo = ["session": session.uuidString, "item": item.id]
        let identifier = Self.identifier(item.id, session: session)
        pending.insert(identifier)
        let request = UNNotificationRequest(identifier: identifier, content: content, trigger: nil)
        if authorization == nil {
            authorization = Task { (try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound])) ?? false }
        }
        let authorization = authorization
        Task { [weak self] in
            guard await authorization?.value == true, self?.pending.contains(identifier) == true else { return }
            try? await UNUserNotificationCenter.current().add(request)
        }
    }

    func withdraw(_ items: [String], session: UUID) {
        let ids = items.map { Self.identifier($0, session: session) }
        pending.subtract(ids)
        let center = UNUserNotificationCenter.current()
        center.removePendingNotificationRequests(withIdentifiers: ids)
        center.removeDeliveredNotifications(withIdentifiers: ids)
    }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse) async {
        let info = response.notification.request.content.userInfo
        let action = response.actionIdentifier
        guard let session = (info["session"] as? String).flatMap(UUID.init(uuidString:)), let item = info["item"] as? String else { return }
        await MainActor.run {
            if let answer = ApprovalAnswer(rawValue: action), Self.answers.contains(answer) {
                self.answer(session, item, answer)
            } else if action == UNNotificationDefaultActionIdentifier {
                self.open(session)
            }
        }
    }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification) async -> UNNotificationPresentationOptions {
        [.banner, .list, .sound]
    }
}
