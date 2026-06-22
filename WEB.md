# ARGUS Dashboard UI — Master Prompt for AI Code Generation

> Paste prompt ini langsung ke AI lo (Claude, GPT-4, Cursor, etc.) untuk generate full UI.

---

## CONTEXT & IDENTITY

You are a senior frontend engineer and UI/UX designer specializing in security operations platforms (SOC dashboards, SIEM, firewall management). You will build the complete frontend UI for **ARGUS** — a next-generation self-hosted eBPF firewall & router automation platform.

ARGUS is named after the hundred-eyed giant of Greek mythology — always vigilant. The UI must embody this identity: omniscient, alert, precise, and never sleeping.

---

## DELIVERABLE

Build a **single-file React JSX artifact** (`argus_dashboard.jsx`) — a complete, interactive, pixel-perfect ARGUS dashboard. This is NOT a prototype or wireframe. This is production-quality UI that a security engineer would use daily.

---

## TECH CONSTRAINTS

- **Framework:** React with hooks (`useState`, `useEffect`, `useRef`, `useCallback`, `useMemo`)
- **Styling:** Pure CSS-in-JS (inline styles or `<style>` tag in the component) — NO Tailwind, NO external CSS files
- **Charts:** Use `recharts` library (`import { LineChart, BarChart, ... } from "recharts"`)
- **Icons:** Use Unicode/emoji symbols or inline SVG — NO icon libraries
- **State:** All data is mocked/simulated — NO real API calls
- **No `localStorage`** — all state in React memory
- **Default export required**

---

## DESIGN SYSTEM — FOLLOW EXACTLY

### Color Palette (Dark Theme Primary)

```
--bg-root:        #080b10   /* Deepest black, main background */
--bg-panel:       #0d1117   /* Card/panel backgrounds */
--bg-elevated:    #141923   /* Input, table row hover, modals */
--bg-border:      #1e2a38   /* All borders */
--cyan-primary:   #00d4ff   /* Primary accent — data, links, active states */
--cyan-glow:      #00d4ff22 /* Cyan glow for shadows */
--green-ok:       #00ff88   /* Allow, online, success, healthy */
--red-danger:     #ff3b5c   /* Deny, blocked, critical, error */
--yellow-warn:    #ffb800   /* Warning, rate-limit, medium severity */
--purple-audit:   #b06bff   /* Audit log, compliance, VPN */
--text-primary:   #e8edf3   /* Main body text */
--text-secondary: #7a8fa8   /* Labels, subtitles, placeholders */
--text-muted:     #3d5068   /* Disabled, ghost text */
```

### Typography

```
Display font:  "JetBrains Mono", "Fira Code", monospace  — used for ALL numeric data, IPs, hashes, codes
Body font:     "Inter", "Segoe UI", system-ui, sans-serif — used for labels, descriptions, navigation
Scale:
  --text-xs: 11px / line-height 1.4
  --text-sm: 13px / line-height 1.5
  --text-base: 14px / line-height 1.6
  --text-lg: 16px / line-height 1.5
  --text-xl: 20px / line-height 1.3
  --text-2xl: 28px / line-height 1.2
  --text-3xl: 40px / line-height 1.1
```

### Spacing & Radius

```
Spacing unit: 4px base (8, 12, 16, 20, 24, 32, 40, 48)
Border radius:
  --radius-sm: 4px
  --radius-md: 8px
  --radius-lg: 12px
  --radius-xl: 16px
  --radius-pill: 9999px
```

### Elevation & Glow System

```
Panel:   box-shadow: 0 1px 3px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.03)
Card:    box-shadow: 0 4px 16px rgba(0,0,0,0.4), 0 0 0 1px #1e2a38
Glow-cyan:  box-shadow: 0 0 20px rgba(0,212,255,0.15), 0 0 40px rgba(0,212,255,0.05)
Glow-red:   box-shadow: 0 0 20px rgba(255,59,92,0.2)
Glow-green: box-shadow: 0 0 16px rgba(0,255,136,0.15)
```

### The Signature Element

The **ARGUS Eye** — a stylized animated SVG eye icon in the header/logo area. This single decorative element:
- Has an animated iris that slowly scans left→right (CSS keyframe, 4s loop, ease-in-out)
- Pulses with a cyan glow on new alerts
- This is the only "decorative" animation — everything else is functional micro-interaction

---

## ANIMATIONS — SPEC

Every interactive element must have smooth, purposeful animation. Implement ALL of the following:

### Button Animations
```css
/* All .btn elements */
transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);

/* Primary button hover */
transform: translateY(-1px);
box-shadow: 0 4px 20px rgba(0,212,255,0.3);

/* Primary button active/press */
transform: translateY(0px) scale(0.98);

/* Danger button hover */
box-shadow: 0 4px 20px rgba(255,59,92,0.3);

/* Icon buttons: rotate on hover */
transform: rotate(90deg); /* e.g., refresh icon */

/* Loading state: spin animation */
@keyframes spin { to { transform: rotate(360deg); } }
```

### Data & State Animations
```css
/* New data row appearing in table */
@keyframes slideInRow {
  from { opacity: 0; transform: translateX(-8px); }
  to   { opacity: 1; transform: translateX(0); }
}

/* Stat card number update */
@keyframes countPulse {
  0%   { color: #00d4ff; }
  100% { color: #e8edf3; }
}

/* Critical alert pulse */
@keyframes alertPulse {
  0%, 100% { box-shadow: 0 0 0 0 rgba(255,59,92,0.4); }
  50%       { box-shadow: 0 0 0 8px rgba(255,59,92,0); }
}

/* Packet flow shimmer on stat cards */
@keyframes shimmer {
  0%   { background-position: -200% 0; }
  100% { background-position: 200% 0; }
}

/* Page/tab transition */
@keyframes fadeSlideIn {
  from { opacity: 0; transform: translateY(6px); }
  to   { opacity: 1; transform: translateY(0); }
}

/* Status dot pulse (live indicator) */
@keyframes livePulse {
  0%, 100% { opacity: 1; transform: scale(1); }
  50%       { opacity: 0.5; transform: scale(1.3); }
}

/* Modal open */
@keyframes modalIn {
  from { opacity: 0; transform: scale(0.96) translateY(-8px); }
  to   { opacity: 1; transform: scale(1) translateY(0); }
}
```

### Chart Animations
- All recharts charts must use `isAnimationActive={true}` with `animationDuration={800}`
- Line charts: animated draw from left to right on mount
- Bar charts: bars grow from bottom
- Data updates: smooth value transition (not jump)

---

## PAGES / VIEWS — BUILD ALL 7

The app is a single-page app with a sidebar nav. Build ALL views accessible via navigation:

---

### 1. DASHBOARD (`/dashboard`) — Main Landing

**Layout:** 2-column grid — left: metrics + charts, right: live event feed

**Stat Cards Row (top):** 4 cards using monospace font for numbers
- 📦 **Packets Allowed** — green accent — large number, +X/s live rate
- 🚫 **Packets Dropped** — red accent — large number, blocks/s rate  
- 🔗 **Active Connections** — cyan accent — current count
- 🌐 **Blocked IPs** — yellow accent — total in blocklist
- Each card: animated number counter on mount, shimmer loading state, trend arrow (↑↓) with color

**Charts Section:**
- **Packet Rate Line Chart** (recharts LineChart): 60-second rolling window, two lines (allowed=green, dropped=red), live updates every 2s, smooth animation
- **Protocol Distribution Bar Chart** (recharts BarChart): TCP/UDP/ICMP/Other, cyan bars with hover tooltips
- **Connection State Donut** (recharts PieChart): New/Established/Closing segments, legend with percentages

**Live Event Feed (right sidebar):**
- Real-time scrolling feed of events (packet blocked, rule matched, scan detected, etc.)
- Each entry: timestamp (monospace), severity badge, event description
- New events animate in from top with `slideInRow`
- "Paused" toggle button to freeze feed

**System Health Bar (bottom):**
- Horizontal status bar: API ● ONLINE | eBPF ● ACTIVE | DB ● IN-MEMORY | WebSocket ● CONNECTED
- Each status dot has `livePulse` animation

---

### 2. FIREWALL RULES (`/rules`) — CRUD Management

**Layout:** Full-width table with toolbar on top

**Toolbar:**
- Search input (filter by name, CIDR, port in real-time)
- Filter dropdowns: Action (All/Allow/Deny/Rate-Limit) | Direction (All/Inbound/Outbound/Forward) | Status (All/Enabled/Disabled)
- "New Rule" primary button (opens modal)
- "Import JSON" + "Export ▾" dropdown (JSON/YAML/CSV)
- Bulk actions bar (appears when rows selected): "Enable Selected" | "Disable Selected" | "Delete Selected" (danger)

**Rules Table:**
- Columns: ☐ (checkbox) | Priority | Name | Action (badge) | Direction (badge) | Src CIDR | Dst CIDR | Proto | Port | Status (toggle) | Actions
- Action badges: Allow=green, Deny=red, Rate-Limit=yellow — with rounded pill style
- Priority column: drag handle icon (visual only, no actual DnD needed)
- Status: animated toggle switch (ON/OFF) — clicking it toggles enabled state immediately
- Actions: Edit ✏️ | Delete 🗑️ | Duplicate 📋 buttons per row — icon buttons with hover tooltip
- Row hover: subtle background highlight with transition
- Empty state: "No rules configured. Click 'New Rule' to add your first firewall rule." with CTA button

**Rule Form Modal:**
- Opens with `modalIn` animation + backdrop blur
- Fields: Name*, Action* (select), Direction* (select), Src CIDR, Dst CIDR, Src Port (0-65535), Dst Port (0-65535), Protocol (select: TCP/UDP/ICMP/Any), Priority (number), Description (textarea), Enabled (toggle)
- Real-time CIDR validation (highlight red if invalid format)
- Submit button: loading spinner state during "save"
- Cancel closes with reverse animation

**Rule Simulator Panel (below table):**
- Collapsible section "🔬 Packet Simulator"
- Inputs: Src IP, Dst IP, Src Port, Dst Port, Protocol, Direction
- "Simulate" button → shows result: which rule matched (highlight that row in table) + final action (Allow/Deny)
- Result displays with color-coded animation

---

### 3. CONNECTIONS (`/connections`) — Live Connection Tracker

**Layout:** Filter bar + live table

**Live Indicator:** Animated "● LIVE" badge in header, connection count updates in real-time

**Filter Bar:**
- Search by IP or port
- Filter: State (All/New/Established/Closing/Closed) | Protocol (All/TCP/UDP/ICMP)
- "Kill Connection" (red button, appears when row selected)
- Auto-refresh toggle (default ON, 2s interval)

**Connections Table:**
- Columns: Src IP:Port | → | Dst IP:Port | Protocol | State | Duration | Packets | Action
- State badges: New=cyan, Established=green, Closing=yellow, Closed=muted
- Duration: live timer counting up (HH:MM:SS) in monospace
- New connections row: `slideInRow` animation
- Connections closing: row fades out with `opacity: 0` transition before removal
- Click row: expand details panel below (inline, accordion style) showing full 5-tuple + timestamps

**Stats row above table:**
- 3 inline stats: Total Active | New/s Rate | TCP:UDP:ICMP ratio bar

---

### 4. ALERTS (`/alerts`) — Alert Rules + History

**Layout:** Split — left: alert rules config, right: alert history

**Alert Rules (left panel):**
- List of configured alert rules: name, condition, notification channels (Webhook/Slack/Discord/Email badges)
- Each rule: toggle on/off, delete, edit
- "Create Alert Rule" button → inline form expands below
- Form: Name, Condition (threshold type + value), Notification channels (checkbox group), Cooldown (seconds)

**Alert History (right panel):**
- Timeline-style list of fired alerts
- Each alert: severity icon (🔴🟡🟢), timestamp, rule name, details
- Unacknowledged alerts: pulsing left border (red/yellow/green based on severity)
- "Acknowledge" button per item — clicking adds ✓ checkmark and mutes the pulse
- "Acknowledge All" bulk button

**Critical Alert Toast System:**
- When a new critical alert fires (simulated), show floating toast in top-right
- Toast: red border, alert message, dismiss button
- Auto-dismisses after 8 seconds with progress bar countdown animation

---

### 5. AUDIT LOG (`/audit`) — Hash-Chained Security Audit

**Layout:** Filter toolbar + table + integrity verification panel

**Filter Bar:**
- Filter by: Actor (input) | Action type (select: login.success, rule.create, rule.delete, etc.) | Date range picker (two date inputs)
- "Export JSON" button
- "Verify Integrity" primary button (cyan)

**Audit Table:**
- Columns: Timestamp | Actor | Action | Resource | IP Address | Status | Hash (truncated)
- Timestamp: monospace, relative time on hover (title tooltip)
- Action: color-coded (login.*=purple, rule.*=cyan, block.*=red)
- Status: ✓ Success (green) | ✗ Failed (red)
- Hash: first 12 chars + "..." with full hash on hover in monospace tooltip
- Click row: show full details in a slide-out right panel with all fields including full hash + previous_hash

**Hash Chain Visualization (below table):**
- Compact horizontal chain diagram: [Entry 1 hash] → [Entry 2 hash] → [Entry 3 hash] → ...
- Each node: small box with truncated hash, connected by arrows
- Chain shows last 5 entries

**Integrity Verification Panel:**
- "Verify Integrity" button triggers simulated check (spinning loader 1.5s)
- Result: "✓ Hash chain intact — All 247 entries verified" (green panel) OR "⚠ Integrity violation at entry #183" (red panel)
- Panel animates in with `modalIn`

---

### 6. IP REPUTATION (`/reputation`) — Threat Intelligence

**Layout:** 2-column — left: search + top offenders, right: detail view

**Search Bar:**
- Large IP input with "Check Reputation" button
- Lookup shows animated result card: IP, score (-100 to 100), threat intel source, last seen

**Reputation Score Gauge:**
- For searched IP: visual gauge/meter showing score
- Colors: -100 to -50 = red (MALICIOUS), -49 to 0 = yellow (SUSPICIOUS), 1 to 100 = green (CLEAN)
- Animated needle/fill transition when score appears

**Top Offenders Table:**
- Top 20 IPs with lowest reputation scores
- Columns: IP | Score (colored) | Category | Source | Actions
- Score: shown as colored badge + small inline bar
- "Block IP" action button per row (danger, with confirmation)
- Quick filter: show only Blocklisted / Suspicious / All

---

### 7. SETTINGS & SYSTEM (`/settings`) — Admin Panel

**Layout:** Sidebar tabs within the page

**Tabs:** General | Users | VPN Portal | Backup | Cluster | Syslog | QoS

**Users Tab:**
- Table: Username | Role (badge: Admin=purple, Operator=cyan, Viewer=muted) | Status | Actions
- Add User button → inline form (username, password, role select)
- Delete user: confirmation inline (don't use browser alert())
- Role badges: pill-shaped, colored

**Backup Tab:**
- "Create Backup" button (shows loading → "✓ Backup created: argus-backup-2024-01-15T14:23:00.json")
- Table of existing backups: ID (truncated), Timestamp, Size, Checksum (truncated), Actions (Download/Restore)
- "Restore" button: shows confirmation modal with backup details before proceeding

**VPN Portal Tab:**
- Table: pending WireGuard peer requests
- Columns: Requester | Requested At | Status | Actions (Approve/Deny)
- Approved: show download config button
- Status badges: Pending=yellow, Approved=green, Denied=red, Revoked=muted

**Cluster Tab:**
- Node list: Node ID | IP | Role (Leader/Follower) | Status | Last Heartbeat
- Leader node: highlighted with cyan border
- Health status: colored dots with livePulse animation for online nodes

---

## NAVIGATION — SIDEBAR DESIGN

**Sidebar Layout:**
- Fixed left sidebar, 220px wide
- Logo area (top): ARGUS Eye SVG + "ARGUS" text in JetBrains Mono
- Nav items: icon + label, 7 pages
- Active state: cyan left border (3px) + cyan text + subtle bg glow
- Hover state: smooth bg transition
- Bottom: User info (username + role badge) + logout button

**Nav Items:**
```
◈  Dashboard
⊞  Rules
⊷  Connections
⚡ Alerts        [badge: unread count]
⊟  Audit Log
◉  Reputation
⚙  Settings
```

**Alert Badge:** red pill badge on "Alerts" nav item showing unread count, animated pop-in when count changes

---

## MOCK DATA — GENERATE REALISTIC DATA

Generate realistic, security-relevant mock data. NOT placeholder "Lorem ipsum" or "Test data".

```javascript
// Example mock data patterns to use:

// IPs: Use real-looking IPs from various ranges
const mockIPs = ['192.168.1.105', '10.0.0.23', '203.0.113.47', '45.33.32.156', '185.220.101.42'];

// Rules: Real-world firewall rule names
'Block Tor Exit Nodes', 'Allow Internal DNS', 'Rate Limit SSH Attempts', 
'Deny Bogon Ranges', 'Allow HTTPS Outbound', 'Block AbuseIPDB Feeds'

// Audit actions
'rule.create', 'rule.delete', 'login.success', 'login.failed', 
'block.add', 'block.remove', 'backup.create', 'user.create'

// Alert messages  
'Port scan detected from 185.220.101.42 (47 ports in 8s)',
'Rate limit exceeded: 203.0.113.47 → 192.168.1.1:22 (850 req/min)',
'Threat intel hit: 45.33.32.156 on Spamhaus DROP list'
```

**Live Simulation:**
- Use `setInterval` to simulate live data:
  - Every 2s: update packet counters (random ±50-500)
  - Every 5s: add a new connection to the connections table
  - Every 8s: generate a new audit log entry
  - Every 15s: randomly fire an alert (30% chance each interval)
  - Every 30s: close a random connection

---

## UX REQUIREMENTS — ANTI-BUG CHECKLIST

Implement ALL of these to prevent common UI bugs:

### Form Validation
- Every required field validated before submit
- CIDR format validation: regex `/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/`
- Port range: 0-65535 only
- Error messages appear INLINE below the field (not alert())
- Error state: red border + red helper text
- Success state: remove error on valid input (onChange, not onBlur only)

### Table Edge Cases
- Empty state UI for every table (meaningful message + action)
- Loading state: skeleton rows (3 animated shimmer rows) while data loads
- Single-item vs multi-item: "1 rule" vs "24 rules" (not "1 rules")
- Pagination: show "Showing 1-20 of 87 rules" — proper bounds checking

### Modal/Overlay
- Click outside backdrop → close modal
- Escape key → close modal
- Prevent body scroll when modal is open (`overflow: hidden` on body)
- Focus trap inside modal (first input gets focus on open)
- Loading state on submit button (disable + spinner, prevent double-submit)

### Navigation
- Active page persists on reload (or implement hash-based routing)
- Current page title shown in header
- Browser back button works (or at minimum, state doesn't break)

### Performance
- Large tables (connections, audit): virtual scroll or pagination (max 50 rows rendered)
- `useCallback` for event handlers passed to lists
- `useMemo` for filtered/sorted data

### Accessibility
- All interactive elements are keyboard-navigable (tabIndex where needed)
- Buttons have aria-label when icon-only
- Color is never the ONLY indicator of status (always pair with text/icon)
- Minimum tap target: 44×44px for all clickable elements

---

## CODE QUALITY REQUIREMENTS

1. **Single component file** — all components defined in one JSX file, organized with comments
2. **No magic numbers** — all colors/sizes as named CSS variables in a `const STYLES = {}` object at top of file
3. **Component structure:**
   ```
   // ─── CONSTANTS & STYLES ──────────────────
   // ─── MOCK DATA ───────────────────────────
   // ─── UTILITY HOOKS ───────────────────────
   // ─── SHARED COMPONENTS ───────────────────
   //   └── Button, Badge, Card, Table, Modal, Toggle, Input
   // ─── PAGE COMPONENTS ─────────────────────
   //   └── Dashboard, Rules, Connections, Alerts, Audit, Reputation, Settings
   // ─── SIDEBAR NAVIGATION ──────────────────
   // ─── ROOT APP COMPONENT ──────────────────
   ```
4. **Error boundaries** — wrap each page in a try-catch with error fallback UI
5. **Comments** — section headers and complex logic explained
6. **No console.error** in production code — handle all errors gracefully in UI

---

## FINAL OUTPUT REQUIREMENTS

- Single `.jsx` file, complete and runnable
- Minimum **1,200 lines** of code (this is a full dashboard, not a toy)
- All 7 pages functional with navigation
- All animations implemented
- All mock data realistic
- Recharts properly imported and used for all charts
- Zero broken states — every interaction has a response

Begin generating the complete ARGUS Dashboard UI now. Start with the constants/styles section, then mock data, then build each component from smallest (Button, Badge) to largest (pages, layout).
