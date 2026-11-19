import AppKit

/// Display, Security and Session submenus. Table driven: every entry is either a
/// toggle (env var "1"/"0") or a single-choice list (env var set to the chosen
/// value, or removed for the "default / follow client" choice). Changes go
/// through `apply`, which writes the LaunchAgent plist and reloads the daemon.
final class AdvancedMenu: NSObject {

    /// Boolean env var. `defaultOn` says what the daemon does when it is unset.
    struct Toggle {
        let key: String
        let title: String
        let defaultOn: Bool
    }

    /// Single-choice env var. A choice with `value == nil` removes the variable.
    struct Choice {
        let key: String
        let title: String
        let options: [(label: String, value: String?)]
        let note: String?
    }

    static let displayToggles: [Toggle] = [
        Toggle(key: "RDP_VIRTUAL_DISPLAY", title: "Use virtual displays (one per client monitor)", defaultOn: true),
        Toggle(key: "RDP_GFX_RESET",       title: "Dynamic resolution (resize with the client window)", defaultOn: true),
        Toggle(key: "RDP_HIDPI",           title: "HiDPI (Retina) desktop", defaultOn: true),
    ]
    static let displayChoices: [Choice] = [
        Choice(key: "RDP_SCALE", title: "Scale",
               options: [("Follow client", nil), ("100%", "100"), ("125%", "125"), ("150%", "150"),
                         ("175%", "175"), ("200%", "200"), ("250%", "250"), ("300%", "300")],
               note: nil),
        Choice(key: "RDP_PHYSICAL_DISPLAYS", title: "Physical displays during a session",
               options: [("Aside (default)", nil), ("Aside", "aside"), ("Mirror", "mirror")],
               note: nil),
    ]
    static let securityToggles: [Toggle] = [
        Toggle(key: "RDP_LEGACY_SECURITY", title: "Offer legacy RDP security (insecure, old clients)", defaultOn: false),
    ]
    static let securityChoices: [Choice] = [
        Choice(key: "RDP_TLS_MIN", title: "Minimum TLS version",
               options: [("1.2 (default)", nil), ("1.0", "1.0"), ("1.1", "1.1"), ("1.2", "1.2"), ("1.3", "1.3")],
               note: nil),
        Choice(key: "RDP_NLA", title: "Network Level Authentication",
               options: [("Auto (default)", nil), ("Auto", "auto"), ("Off", "off"), ("Require", "require")],
               note: nil),
    ]
    static let sessionChoices: [Choice] = [
        Choice(key: "RDP_IDLE_TIMEOUT_MIN", title: "Disconnect idle clients after",
               options: [("Never (default)", nil), ("5 minutes", "5"), ("15 minutes", "15"),
                         ("30 minutes", "30"), ("1 hour", "60"), ("2 hours", "120")],
               note: nil),
    ]
    /// Written by the GUI only; the daemon side is added in parallel work.
    static let performanceChoices: [Choice] = [
        Choice(key: "RDP_FPS", title: "Frame rate",
               options: [("Default", nil), ("30 fps", "30"), ("60 fps", "60")], note: nil),
        Choice(key: "RDP_AUDIO_CODEC", title: "Audio codec",
               options: [("Auto (default)", nil), ("Auto", "auto"), ("PCM", "pcm")], note: nil),
    ]

    private let apply: (String, String?) -> Void
    private var toggleItems: [String: NSMenuItem] = [:]
    private var toggleSpecs: [String: Toggle] = [:]
    private var choiceItems: [String: [NSMenuItem]] = [:]
    private var choiceSpecs: [String: Choice] = [:]
    private var customItems: [String: NSMenuItem] = [:]

    init(apply: @escaping (String, String?) -> Void) {
        self.apply = apply
        super.init()
    }

    /// Appends the headers and submenus to `menu`.
    func install(into menu: NSMenu) {
        addSection("Display", toggles: Self.displayToggles, choices: Self.displayChoices, to: menu)
        addSection("Security", toggles: Self.securityToggles, choices: Self.securityChoices, to: menu)
        addSection("Session", toggles: [], choices: Self.sessionChoices, to: menu)
        addSection("Performance", toggles: [], choices: Self.performanceChoices, to: menu)
    }

    private func addSection(_ name: String, toggles: [Toggle], choices: [Choice], to menu: NSMenu) {
        let header = NSMenuItem(title: name, action: nil, keyEquivalent: "")
        header.isEnabled = false
        menu.addItem(header)

        for t in toggles {
            let item = NSMenuItem(title: t.title, action: #selector(toggleChanged(_:)), keyEquivalent: "")
            item.target = self
            item.representedObject = t.key
            toggleItems[t.key] = item
            toggleSpecs[t.key] = t
            menu.addItem(item)
        }
        for c in choices {
            let parent = NSMenuItem(title: c.title, action: nil, keyEquivalent: "")
            let sub = NSMenu(title: c.title)
            var items: [NSMenuItem] = []
            for opt in c.options {
                let item = NSMenuItem(title: opt.label, action: #selector(choiceChanged(_:)), keyEquivalent: "")
                item.target = self
                item.representedObject = [c.key, opt.value ?? ""]
                sub.addItem(item)
                items.append(item)
            }
            // Shown (checked, disabled) only when the plist holds a value that is not a preset.
            let custom = NSMenuItem(title: "", action: nil, keyEquivalent: "")
            custom.isHidden = true
            custom.isEnabled = false
            sub.addItem(custom)
            customItems[c.key] = custom
            parent.submenu = sub
            choiceItems[c.key] = items
            choiceSpecs[c.key] = c
            menu.addItem(parent)
        }
        menu.addItem(.separator())
    }

    /// Updates checkmarks from the plist environment (nil = plist unreadable).
    func refresh(env: [String: String]?) {
        for (key, item) in toggleItems {
            guard let spec = toggleSpecs[key] else { continue }
            item.isEnabled = env != nil
            let raw = env?[key]
            let on: Bool
            if let raw = raw, !raw.isEmpty { on = spec.defaultOn ? (raw != "0") : (raw == "1") }
            else { on = spec.defaultOn }
            item.state = (env != nil && on) ? .on : .off
        }
        for (key, items) in choiceItems {
            let current = env?[key] ?? ""
            // The "default" entry (value nil -> "") is checked when unset; a named entry
            // matching the current value wins over it.
            var matched = false
            for item in items {
                let pair = (item.representedObject as? [String]) ?? []
                let v = pair.count == 2 ? pair[1] : ""
                item.isEnabled = env != nil
                item.state = .off
                if env != nil, !current.isEmpty, v.lowercased() == current.lowercased(), !matched {
                    item.state = .on; matched = true
                }
            }
            if env != nil, current.isEmpty, let first = items.first { first.state = .on; matched = true }
            if let custom = customItems[key] {
                let isCustom = env != nil && !matched
                custom.isHidden = !isCustom
                custom.title = "Custom: \(current)"
                custom.state = isCustom ? .on : .off
            }
        }
    }

    @objc private func toggleChanged(_ sender: NSMenuItem) {
        guard let key = sender.representedObject as? String else { return }
        apply(key, sender.state == .on ? "0" : "1")
    }

    @objc private func choiceChanged(_ sender: NSMenuItem) {
        guard let pair = sender.representedObject as? [String], pair.count == 2 else { return }
        apply(pair[0], pair[1].isEmpty ? nil : pair[1])
    }
}
