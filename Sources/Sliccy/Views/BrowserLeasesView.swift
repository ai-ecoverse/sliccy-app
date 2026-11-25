import SwiftUI

struct BrowserLeasesView: View {
    let control: BrowserLeaseControl
    let selectedBrowser: String
    @State private var review: BrowserLeaseReview?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Requests and active leases on this link. Refresh to check for changes.")
                    .font(.callout).foregroundStyle(.secondary)
                Spacer()
                Button("Refresh") { control.refresh() }.disabled(control.busy)
            }
            if control.busy { ProgressView("Checking the local broker…").controlSize(.small) }
            if let message = control.message { Text(message).font(.callout) }
            if let snapshot = control.snapshot {
                let revision = control.revision
                if snapshot.active.isEmpty && snapshot.pending.isEmpty { Text("No requests or active leases.") }
                ForEach(snapshot.pending) { item in
                    Divider()
                    HStack {
                        VStack(alignment: .leading) {
                            Text(item.parent == nil ? "Pending browser request" : "Requested expansion")
                            Text(verbatim: "\(item.request) · \(selectedBrowser) · \(item.link)").font(.caption)
                        }
                        Spacer()
                        Button("Review…") {
                            review = BrowserLeaseReview(control: control, revision: revision,
                                item: item, parent: snapshot.parent(of: item), selectedBrowser: selectedBrowser)
                        }
                    }
                }
                ForEach(snapshot.active) { item in
                    Divider()
                    TimelineView(.explicit([Date.now, item.deadline].sorted())) { _ in
                        let expired = Date.now >= item.deadline
                        VStack(alignment: .leading, spacing: 6) {
                            Text(expired ? "Deadline passed" : "Active at last refresh").font(.headline)
                            Text(verbatim: "Lease: \(item.lease)").font(.caption)
                            LeaseIdentity(browser: selectedBrowser, link: item.link, jkt: item.jkt)
                            LeaseRules(allow: item.allow)
                            Text(verbatim: "Ends \(item.deadline.ISO8601Format())")
                            Button("Revoke now", role: .destructive) {
                                control.decide(.revoke(item), reviewed: revision)
                            }.disabled(expired)
                            Text("Revoking stops further access. It does not undo actions already taken.")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
            }
        }
        .sheet(item: $review) { BrowserLeaseReviewSheet(review: $0) }
    }
}

private struct BrowserLeaseReview: Identifiable {
    let id = UUID()
    let control: BrowserLeaseControl
    let revision: UUID
    let item: PendingBrowserLease
    let parent: ActiveBrowserLease?
    let selectedBrowser: String
}

private struct LeaseIdentity: View {
    let browser: String, link: String, jkt: String
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(verbatim: "Browser: \(browser) · one task tab")
            Text(verbatim: "Paired link: \(link)")
            Text(verbatim: "Holder: jkt:\(jkt)").font(.system(.callout, design: .monospaced))
                .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
        }
    }
}

private struct LeaseRules: View {
    let allow: [BrowserLeaseRule]
    var body: some View {
        ForEach(allow, id: \.self) { rule in
            VStack(alignment: .leading) {
                Text(rule.kind.label).font(.caption).foregroundStyle(.secondary)
                // No shortened host, Markdown, hot link, or origin-only rendering.
                Text(verbatim: rule.url).font(.system(.callout, design: .monospaced))
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

private struct BrowserLeaseReviewSheet: View {
    let review: BrowserLeaseReview
    @Environment(\.dismiss) private var dismiss
    private var item: PendingBrowserLease { review.item }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if review.control.revision != review.revision || review.control.snapshot == nil {
                Text("This review is no longer current.").font(.headline)
                Button("Close") { dismiss() }.keyboardShortcut(.cancelAction)
            } else {
                Text(item.parent == nil ? "Allow this job to use one new tab?" : "Add scope to the existing tab?")
                    .font(.title2.bold())
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        Text(verbatim: "Request: \(item.request)").font(.caption)
                        LeaseIdentity(browser: review.selectedBrowser, link: item.link, jkt: item.jkt)
                        Text("Compare the full holder fingerprint with your job. A link name does not identify the job.")
                            .font(.callout).foregroundStyle(.secondary)
                        Divider()
                        if item.parent != nil {
                            Text("Add only").font(.headline)
                            LeaseRules(allow: item.allow)
                            if let parent = review.parent {
                                Text(verbatim: "Keep \(parent.id) · same job and tab").font(.headline)
                                LeaseRules(allow: parent.allow)
                                Text(verbatim: "Still ends \(parent.deadline.ISO8601Format()) · no extra time")
                            } else { Text("No matching active parent lease. This expansion cannot be approved.") }
                        } else if let ttl = item.ttlSeconds {
                            Text("Requested sites").font(.headline)
                            LeaseRules(allow: item.allow)
                            Text(verbatim: "Duration from approval: \(Duration.seconds(ttl).formatted(.units(allowed: [.days, .hours, .minutes, .seconds], width: .wide)))")
                        }
                        Text("The job can read, click, type and submit as you. Other tabs stay private. URL scope limits the driver, not what the site can do.")
                    }.frame(maxWidth: .infinity, alignment: .leading)
                }
                Divider()
                HStack {
                    Button("Not now") { dismiss() }.keyboardShortcut(.cancelAction)
                    Spacer()
                    // Return takes the safe action. Opening or dismissing this sheet never grants.
                    Button(item.parent == nil ? "Deny" : "Keep original scope") { send(.deny(item)) }
                        .keyboardShortcut(.defaultAction)
                    TimelineView(.explicit(([Date.now] + (review.parent.map { [$0.deadline] } ?? [])).sorted())) { _ in
                        let action = BrowserLeaseDecision.approve(item, parent: review.parent)
                        Button(item.parent == nil ? "Approve this lease" : "Approve additions only") { send(action) }
                            .disabled(review.control.snapshot?.permits(action, at: .now) != true)
                    }
                }
            }
        }.padding(24).frame(width: 540, height: 480)
    }

    private func send(_ action: BrowserLeaseDecision) {
        review.control.decide(action, reviewed: review.revision)
        dismiss()
    }
}
