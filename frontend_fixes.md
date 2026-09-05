# TraceShield MVP — Frontend Fix List

> **Scope:** `frontend/src/` — Next.js 14 App Router, TailwindCSS, TypeScript  
> **Priority Legend:** 🔴 Bug · 🟠 UX Problem · 🟡 Missing Feature · 🟢 Polish

---

## 🔴 BUG FIXES (Fix These First)

---

### BUG-01 — File Input Accepts Wrong File Types
**File:** [`src/app/page.tsx` → line 480](file:///c:/Users/Aditya%20S%20Yadav/Desktop/traceshield-mvp/frontend/src/app/page.tsx#L480)

**Problem:**
```tsx
// CURRENT — wrong
<input accept=".eml,.msg,image/*" ... />
```
The backend (`main.py`) only parses `.eml` email files using Python's `BytesParser`. Accepting `image/*` and `.msg` files will cause the backend to return a 500 or empty parse result with no useful error shown to the user.

**Fix:**
```tsx
// CORRECT
<input accept=".eml" ... />
```
Also update the helper text below the dropzone from:
```
image/*, .eml, .msg • Max 10.0 MB
```
to:
```
.eml files only • Max 10.0 MB • Parsed in isolated sandbox
```

---

### BUG-02 — Navbar Backend Status is Always "Pulsing Orange" (Never Actually Checks Health)
**File:** [`src/components/dashboard/Navbar.tsx` → line 45](file:///c:/Users/Aditya%20S%20Yadav/Desktop/traceshield-mvp/frontend/src/components/dashboard/Navbar.tsx#L45)

**Problem:**
The status dot is hardcoded with `animate-pulse` and amber color — it never actually pings the backend. Whether the server is up or down, it always shows the same pulsing dot. This is misleading, especially during a demo.

**Backend health endpoint available:** `GET /api/v1/health` → returns `{ "status": "ok" }`

**Fix:** Add a `useEffect` in `Navbar.tsx` that pings `/api/v1/health` on mount and every 30 seconds:
```tsx
const [backendStatus, setBackendStatus] = useState<"checking" | "online" | "offline">("checking");

useEffect(() => {
  const check = async () => {
    try {
      const res = await fetch(`${apiBaseUrl}/api/v1/health`, { signal: AbortSignal.timeout(3000) });
      setBackendStatus(res.ok ? "online" : "offline");
    } catch {
      setBackendStatus("offline");
    }
  };
  check();
  const interval = setInterval(check, 30000);
  return () => clearInterval(interval);
}, [apiBaseUrl]);
```

Then change the dot color based on status:
- `checking` → gray, no pulse
- `online` → green (`bg-emerald-500`), pulse
- `offline` → red (`bg-red-500`), pulse

---

### BUG-03 — "New Scan" Does Not Clear Previous Case Results
**File:** [`src/app/page.tsx` → line 467](file:///c:/Users/Aditya S Yadav/Desktop/traceshield-mvp/frontend/src/app/page.tsx#L467)

**Problem:**
Clicking "New Scan" only calls `fileInputRef.current.click()`. It does NOT reset `caseData`, `error`, or `loading` state. So the old analysis stays on screen while the new file is being uploaded — very confusing.

**Fix:** In the `onNewScan` handler, reset state before opening the file picker:
```tsx
onNewScan={() => {
  setCaseData(null);   // clear old results
  setError(null);      // clear old errors
  if (fileInputRef.current) {
    fileInputRef.current.value = "";  // reset input so same file can be re-uploaded
    fileInputRef.current.click();
  }
}}
```

---

## 🟡 MISSING FEATURES (Data Exists in Backend, No UI)

---

### FEAT-01 — AI Review Card is Missing Entirely
**File:** [`src/app/page.tsx`](file:///c:/Users/Aditya%20S%20Yadav/Desktop/traceshield-mvp/frontend/src/app/page.tsx)

**Problem:**
The backend returns `ai_review` in the case JSON when risk score ≥ 70:
```json
{
  "ai_review": {
    "is_false_positive": false,
    "adjusted_score": 85,
    "adjusted_band": "HIGH",
    "analyst_summary": "This email shows clear signs of phishing..."
  }
}
```
Currently **zero UI** exists to display this. The AI analysis is completely invisible to the user.

**Fix:** Add a new card in the results section below the Risk Score card:

```tsx
{caseData.ai_review && !caseData.ai_review.error && (
  <Card className="bg-[#1A1C20] border-[#2E2722] p-6 space-y-4">
    <div className="flex items-center gap-2 pb-3 border-b border-[#2E2722]">
      <Cpu className="w-4 h-4 text-[#D47E30]" />
      <h3 className="font-semibold text-sm text-zinc-200">Tier 2 AI Review</h3>
      <Badge className={caseData.ai_review.is_false_positive
        ? "bg-emerald-900/50 text-emerald-300 border-emerald-700"
        : "bg-red-900/50 text-red-300 border-red-700"}>
        {caseData.ai_review.is_false_positive ? "False Positive Detected" : "Threat Confirmed"}
      </Badge>
    </div>
    <p className="text-sm text-zinc-300 leading-relaxed">
      {caseData.ai_review.analyst_summary}
    </p>
    <div className="flex gap-4 text-xs text-zinc-400">
      <span>Adjusted Score: <strong className="text-[#FDFBD4]">{caseData.ai_review.adjusted_score}</strong></span>
      <span>Adjusted Band: <strong className="text-[#D47E30]">{caseData.ai_review.adjusted_band}</strong></span>
    </div>
  </Card>
)}
```

Also handle the case where AI review is unavailable:
```tsx
{caseData.risk?.score >= 70 && caseData.ai_review?.error && (
  <p className="text-xs text-zinc-500 italic">AI review unavailable — GROQ_API_KEY may not be set.</p>
)}
```

---

### FEAT-02 — SPF / DKIM / DMARC Authentication Badges Not Shown
**File:** [`src/app/page.tsx`](file:///c:/Users/Aditya%20S%20Yadav/Desktop/traceshield-mvp/frontend/src/app/page.tsx)

**Problem:**
The backend returns SPF and DKIM results in `message.authentication`:
```json
{
  "authentication": {
    "spf": "pass",
    "dkim": "fail"
  }
}
```
The current UI shows Subject, From, Reply-To, Return-Path — but **no authentication results at all**. For an email security tool, this is a critical omission.

**Fix:** Add an "Authentication" row to the 2×2 metadata grid:

```tsx
{/* Authentication Status */}
<div className="flex flex-col gap-1.5 md:col-span-2">
  <span className="text-[11px] font-sans font-medium uppercase tracking-wider text-zinc-400">
    Authentication
  </span>
  <div className="flex gap-2 flex-wrap">
    {[
      { label: "SPF", value: caseData.message?.authentication?.spf ?? caseData.message?.spf },
      { label: "DKIM", value: caseData.message?.authentication?.dkim ?? caseData.message?.dkim },
    ].map(({ label, value }) => {
      const status = (value || "none").toLowerCase();
      const color = status === "pass"
        ? "bg-emerald-900/40 text-emerald-300 border-emerald-700/50"
        : status === "fail"
        ? "bg-red-900/40 text-red-300 border-red-700/50"
        : "bg-zinc-800 text-zinc-400 border-zinc-700";
      return (
        <span key={label} className={`px-3 py-1 rounded-full text-xs font-mono border font-semibold ${color}`}>
          {label}: {status.toUpperCase()}
        </span>
      );
    })}
  </div>
</div>
```

---

### FEAT-03 — No Loading Progress Steps (Just a Spinner)
**File:** [`src/app/page.tsx` → lines 536–551](file:///c:/Users/Aditya%20S%20Yadav/Desktop/traceshield-mvp/frontend/src/app/page.tsx#L536-L551)

**Problem:**
The loading state shows one spinner and one static message. The backend does 4 distinct steps (parse → score → enrich → AI review), but the user sees none of this.

**Fix:** Add a `loadingStep` state with a fake progress ticker:
```tsx
const [loadingStep, setLoadingStep] = useState(0);
const STEPS = [
  "Parsing MIME structure...",
  "Evaluating deterministic rules...",
  "Enriching indicators & correlating cases...",
  "Running Tier 2 AI review...",
  "Assembling case report...",
];
```

Use `setInterval` to advance through steps while loading, and show each step with a checkmark once passed:
```tsx
// Step 1 ✓  Step 2 ✓  Step 3 ●  Step 4 ○  Step 5 ○
```

---

## 🟠 UX PROBLEMS

---

### UX-01 — Risk Score Label Says "Prototype Risk Score"
**File:** [`src/app/page.tsx` → line 684](file:///c:/Users/Aditya%20S%20Yadav/Desktop/traceshield-mvp/frontend/src/app/page.tsx#L684)

**Problem:**
```tsx
<span>Prototype Risk Score</span>
```
Saying "Prototype" in the UI looks unprofessional, especially for a SIH demo or any presentation.

**Fix:**
```tsx
<span>Risk Score</span>
```
Optionally add a small tooltip `ⓘ` explaining it's rule-based, not a probability.

---

### UX-02 — No "Clear / Reset" Button After Results Are Shown
**File:** [`src/app/page.tsx`](file:///c:/Users/Aditya%20S%20Yadav/Desktop/traceshield-mvp/frontend/src/app/page.tsx)

**Problem:**
Once results are displayed, the only way to reset is "New Scan" in the navbar — which isn't obvious. Many users will be confused about how to scan another email.

**Fix:** Add a visible "Analyze Another Email" button at the bottom of the results section:
```tsx
<button
  onClick={() => { setCaseData(null); setError(null); }}
  className="flex items-center gap-2 text-sm text-zinc-400 hover:text-zinc-200 border border-zinc-800 hover:border-zinc-600 px-4 py-2 rounded-lg transition-colors"
>
  <ArrowRight className="w-4 h-4 rotate-180" />
  Analyze Another Email
</button>
```

---

### UX-03 — Upload Zone is Too Small and Feels Cramped
**File:** [`src/app/page.tsx` → line 493](file:///c:/Users/Aditya%20S%20Yadav/Desktop/traceshield-mvp/frontend/src/app/page.tsx#L493)

**Problem:**
`py-8` gives the dropzone only ~64px of vertical padding. It's easy to miss on larger screens and feels like an afterthought.

**Fix:** Increase padding and add a more prominent visual:
```tsx
// Change py-8 → py-14
// Change icon from w-6 h-6 → w-8 h-8
// Add a subtle glow ring on hover
className="... py-14 hover:shadow-[0_0_20px_rgba(212,126,48,0.08)]"
```

---

### UX-04 — Empty State References a Hardcoded Filename
**File:** [`src/app/page.tsx` → line 566](file:///c:/Users/Aditya%20S%20Yadav/Desktop/traceshield-mvp/frontend/src/app/page.tsx#L566)

**Problem:**
```tsx
<code>data/fixtures/test_phishing.eml</code>
```
This is a backend file path that means nothing to a regular user (or a judge at SIH).

**Fix:** Remove the hardcoded path. Replace with:
```tsx
<p className="text-xs text-zinc-400">
  Upload a suspicious <code>.eml</code> email file to analyze its headers,
  authentication signals, URLs, and campaign correlation.
</p>
```

---

### UX-05 — Reason Codes Are Plain Text, Not Visual Chips
**File:** [`src/app/page.tsx`](file:///c:/Users/Aditya%20S%20Yadav/Desktop/traceshield-mvp/frontend/src/app/page.tsx)

**Problem:**
The `reason_codes` from the backend (e.g. `REPLY_TO_MISMATCH`, `URGENT_SUBJECT`, `SUSPICIOUS_URL`) are shown as plain text list items. For an investigation tool, these should stand out clearly.

**Fix:** Render each reason code as a styled chip with color coding:
```tsx
{caseData.risk?.reason_codes?.map((r, i) => (
  <div key={i} className="flex items-start gap-3 p-3 rounded-lg bg-[#121417] border border-[#2A231D]">
    <span className="font-mono text-xs text-[#D47E30] bg-[#2A2118] px-2 py-0.5 rounded border border-[#D47E30]/30 whitespace-nowrap">
      {r.code}
    </span>
    <span className="text-xs text-zinc-300">{r.title}</span>
  </div>
))}
```

---

### UX-06 — ThreatGraph is Broken on Mobile
**File:** [`src/app/page.tsx` → lines 229–248](file:///c:/Users/Aditya%20S%20Yadav/Desktop/traceshield-mvp/frontend/src/app/page.tsx#L229-L248)

**Problem:**
On mobile the SVG connector lines between graph nodes are hardcoded to `hidden md:hidden` — they don't show at all. The nodes stack vertically with no visual connection between them.

**Fix:** Replace the mobile SVG section with simple vertical dashed lines using CSS borders, or show a simplified linear layout with arrows between nodes instead of trying to replicate the grid graph on small screens.

---

### UX-07 — SHA-256 Only Shows 16 Characters with No Way to See Full Hash
**File:** [`src/app/page.tsx` → line 601](file:///c:/Users/Aditya%20S%20Yadav/Desktop/traceshield-mvp/frontend/src/app/page.tsx#L601)

**Problem:**
```tsx
{caseData.artifact.sha256.substring(0, 16)}...
```
The copy button copies the full hash (good), but there's no tooltip or expand option to see the full value without copying it.

**Fix:** Add a `title` attribute to show full hash on hover:
```tsx
<span 
  className="text-[#FDFBD4] font-mono cursor-help" 
  title={caseData.artifact.sha256}
>
  {caseData.artifact.sha256.substring(0, 16)}...
</span>
```

---

## 🟢 POLISH / NICE-TO-HAVE

---

### POLISH-01 — Add Session Case History Sidebar
The backend stores all analyzed cases in-memory per session. The frontend could show a sidebar/panel listing previous case IDs (e.g. TS-DEMO-001, TS-DEMO-002) so the user can see how many they've scanned and compare results.

---

### POLISH-02 — Animate Results Cards on Appearance
When results load, all cards appear instantly. A staggered fade-in animation (`opacity-0 → opacity-100` with `transition-delay`) would make the dashboard feel much more premium.

---

### POLISH-03 — Add Favicon / Brand Icon
The current favicon is the default Next.js icon. Replace it with a shield icon matching the brand.

---

## Summary Table

| ID | Priority | File | Effort |
|---|---|---|---|
| BUG-01 | 🔴 Bug | `page.tsx` L480 | 2 min |
| BUG-02 | 🔴 Bug | `Navbar.tsx` | 20 min |
| BUG-03 | 🔴 Bug | `page.tsx` L467 | 5 min |
| FEAT-01 | 🟡 Missing | `page.tsx` | 30 min |
| FEAT-02 | 🟡 Missing | `page.tsx` | 15 min |
| FEAT-03 | 🟡 Missing | `page.tsx` | 25 min |
| UX-01 | 🟠 UX | `page.tsx` L684 | 1 min |
| UX-02 | 🟠 UX | `page.tsx` | 10 min |
| UX-03 | 🟠 UX | `page.tsx` L493 | 5 min |
| UX-04 | 🟠 UX | `page.tsx` L566 | 2 min |
| UX-05 | 🟠 UX | `page.tsx` | 15 min |
| UX-06 | 🟠 UX | `page.tsx` L229 | 30 min |
| UX-07 | 🟠 UX | `page.tsx` L601 | 2 min |
| POLISH-01 | 🟢 Polish | New component | 45 min |
| POLISH-02 | 🟢 Polish | `page.tsx` | 10 min |
| POLISH-03 | 🟢 Polish | `public/` | 5 min |

**Quick wins (under 5 min each):** BUG-01, BUG-03, UX-01, UX-04, UX-07 → do these first.  
**Biggest visual impact:** FEAT-01, FEAT-02, UX-05 → AI Review card + auth badges + reason code chips.
