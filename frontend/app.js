// ═══════════════════════════════════════════════════════════
//  ScamShield v4 — Conversation-Aware Messenger Engine
//  Structured messages[] payload, multi-tier verdicts,
//  behavioral explainability, full backward compatibility
// ═══════════════════════════════════════════════════════════

const API_URL = "http://localhost:8000/analyze";

// ── Tuning ────────────────────────────────────────────────
const MIN_CHARS        = 8;
const SILENCE_TIMEOUT  = 4000;   // 4s silence → commit
const MIN_NEW_WORDS    = 3;      // min words before commit
const ANALYZE_COOLDOWN = 2000;   // min ms between API calls

// ═══════════════════════════════════════════════════════════
//  DOM
// ═══════════════════════════════════════════════════════════
const $messages     = document.getElementById("chat-messages");
const $emptyState   = document.getElementById("empty-state");
const $input        = document.getElementById("inputText");
const $btnSend      = document.getElementById("btn-send");
const $btnMic       = document.getElementById("btn-mic");
const $btnStop      = document.getElementById("btn-stop");
const $btnReset     = document.getElementById("btn-reset");
const $speechStatus = document.getElementById("speech-status");
const $verdictStrip = document.getElementById("verdict-strip");
const $resultOverlay= document.getElementById("result-overlay");
const $resultPanel  = document.getElementById("result-panel");
const $resultBack   = document.getElementById("result-backdrop");
const $speakerLabel = document.getElementById("speaker-label");
const $speakerToggle= document.getElementById("speaker-toggle");
const $chatArea       = document.getElementById("chat-area");
const $analysisPanel  = document.getElementById("analysis-panel");

// ═══════════════════════════════════════════════════════════
//  STATE
// ═══════════════════════════════════════════════════════════
let conversation      = [];        // { role, text, timestamp }
let currentRole       = "other";   // "me" | "other"
let recognition       = null;
let isListening       = false;
let speechBuffer      = "";
let interimText       = "";
let silenceTimer      = null;
let lastAnalyzeTime   = 0;
let lastAnalyzedLen   = 0;
let lastResult        = null;
let isAnalyzing       = false;
let interimRowEl      = null;

// ═══════════════════════════════════════════════════════════
//  SPEAKER TOGGLE
// ═══════════════════════════════════════════════════════════
$speakerToggle.addEventListener("click", (e) => {
    const btn = e.target.closest(".role-btn");
    if (!btn) return;
    const role = btn.dataset.role;
    if (role === currentRole) return;

    currentRole = role;

    $speakerToggle.querySelectorAll(".role-btn").forEach(b => {
        b.classList.toggle("active", b.dataset.role === role);
    });

    const label = role === "me" ? "Me" : "Other Person";
    $speakerLabel.innerHTML = `Speaking as <strong>${label}</strong>`;

    if (isListening && speechBuffer.trim().length >= MIN_CHARS) {
        const prevRole = role === "me" ? "other" : "me";
        commitSpeech(prevRole);
    }
});

// ═══════════════════════════════════════════════════════════
//  SEND (TEXT INPUT)
// ═══════════════════════════════════════════════════════════
$btnSend.addEventListener("click", sendTextMessage);

$input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        sendTextMessage();
    }
});

$input.addEventListener("input", () => {
    $input.style.height = "auto";
    $input.style.height = Math.min($input.scrollHeight, 120) + "px";
});

function sendTextMessage() {
    const text = $input.value.trim();
    if (!text) return;

    addMessage(currentRole, text);
    $input.value = "";
    $input.style.height = "auto";
    analyzeConversation();
}

// ═══════════════════════════════════════════════════════════
//  CONVERSATION MANAGEMENT
// ═══════════════════════════════════════════════════════════
function addMessage(role, text) {
    const msg = {
        role,
        text: text.trim(),
        timestamp: Date.now(),
    };
    conversation.push(msg);
    renderMessage(msg, conversation.length - 1);
    hideEmptyState();
    scrollToBottom();
    return msg;
}

function hideEmptyState() {
    if ($emptyState && $emptyState.parentNode) {
        $emptyState.remove();
    }
}

/**
 * Build structured messages[] payload for v4 API.
 * Falls back to flat text if conversation is empty.
 */
function getConversationPayload() {
    if (conversation.length === 0) return null;
    return {
        messages: conversation.map(m => ({
            role: m.role,       // "me" | "other"
            text: m.text,
        })),
    };
}

// ═══════════════════════════════════════════════════════════
//  CHAT RENDERING
// ═══════════════════════════════════════════════════════════
function renderMessage(msg, index) {
    const prev = index > 0 ? conversation[index - 1] : null;
    const isContinuation = prev && prev.role === msg.role;
    const isGroupStart = !isContinuation;

    const row = document.createElement("div");
    row.className = `msg-row ${msg.role}`;
    if (isContinuation) row.classList.add("continuation");
    if (isGroupStart) row.classList.add("group-start");
    row.dataset.index = index;

    const sender = document.createElement("div");
    sender.className = "msg-sender";
    sender.textContent = msg.role === "me" ? "Me" : "Other Person";

    const bubble = document.createElement("div");
    bubble.className = "msg-bubble";
    bubble.textContent = msg.text;

    const time = document.createElement("div");
    time.className = "msg-time";
    time.textContent = formatTime(msg.timestamp);

    row.appendChild(sender);
    row.appendChild(bubble);
    row.appendChild(time);

    if (interimRowEl && interimRowEl.parentNode) {
        $messages.insertBefore(row, interimRowEl);
    } else {
        $messages.appendChild(row);
    }
}

function renderAllMessages() {
    $messages.innerHTML = "";
    if (conversation.length === 0) {
        $messages.innerHTML = `
            <div id="empty-state" class="empty-state">
                <div class="empty-icon">
                    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    </svg>
                </div>
                <p class="empty-title">Start a Conversation</p>
                <p class="empty-desc">Type or speak as either party.<br>ScamShield analyses the full conversation in real time.</p>
            </div>`;
        return;
    }
    conversation.forEach((msg, i) => renderMessage(msg, i));
}

function formatTime(ts) {
    const d = new Date(ts);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function scrollToBottom() {
    requestAnimationFrame(() => {
        $chatArea.scrollTop = $chatArea.scrollHeight;
    });
}

// ── Interim bubble ────────────────────────────────────────
function showInterimBubble(text) {
    if (!interimRowEl) {
        interimRowEl = document.createElement("div");
        interimRowEl.className = `msg-row ${currentRole} interim-row`;

        const sender = document.createElement("div");
        sender.className = "msg-sender";
        sender.textContent = currentRole === "me" ? "Me" : "Other Person";

        const bubble = document.createElement("div");
        bubble.className = "msg-bubble msg-interim";
        bubble.dataset.interimBubble = "true";

        interimRowEl.appendChild(sender);
        interimRowEl.appendChild(bubble);
        $messages.appendChild(interimRowEl);
    }

    interimRowEl.className = `msg-row ${currentRole} interim-row`;
    const senderEl = interimRowEl.querySelector(".msg-sender");
    if (senderEl) senderEl.textContent = currentRole === "me" ? "Me" : "Other Person";

    const bubble = interimRowEl.querySelector(".msg-bubble");
    if (bubble) bubble.textContent = text;

    scrollToBottom();
}

function removeInterimBubble() {
    if (interimRowEl && interimRowEl.parentNode) {
        interimRowEl.remove();
    }
    interimRowEl = null;
}

// ── Analyzing indicator ───────────────────────────────────
let analyzingEl = null;

function showAnalyzingIndicator() {
    removeAnalyzingIndicator();
    analyzingEl = document.createElement("div");
    analyzingEl.className = "msg-analyzing";
    analyzingEl.innerHTML = `
        <div class="analyzing-dots"><span></span><span></span><span></span></div>
        Analyzing conversation
    `;
    $messages.appendChild(analyzingEl);
    scrollToBottom();
}

function removeAnalyzingIndicator() {
    if (analyzingEl && analyzingEl.parentNode) {
        analyzingEl.remove();
    }
    analyzingEl = null;
}


// ═══════════════════════════════════════════════════════════
//  SPEECH RECOGNITION
// ═══════════════════════════════════════════════════════════
const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;

if (!SpeechRecognition) {
    $btnMic.disabled = true;
    $btnMic.title = "Speech recognition requires Chrome or Edge";
}

function initRecognition() {
    if (!SpeechRecognition) return;

    recognition = new SpeechRecognition();
    recognition.continuous     = true;
    recognition.interimResults = true;
    recognition.lang           = "en-IN";
    recognition.maxAlternatives = 1;

    recognition.onstart = () => {
        isListening = true;
        $btnMic.classList.add("hidden");
        $btnStop.classList.remove("hidden");
        showSpeechStatus("🎙 Listening… speak now");
    };

    recognition.onresult = (event) => {
        let newFinal = "";
        let interim  = "";

        for (let i = event.resultIndex; i < event.results.length; i++) {
            const t = event.results[i][0].transcript;
            if (event.results[i].isFinal) {
                newFinal += t + " ";
            } else {
                interim += t;
            }
        }

        if (newFinal) {
            speechBuffer += newFinal;
            console.log(`[SPEECH] Buffer appended: "${newFinal.trim()}"`);
        }
        interimText = interim;

        const display = (speechBuffer + interimText).trim();
        if (display) showInterimBubble(display);

        clearTimeout(silenceTimer);
        showSpeechStatus("🎙 Speech detected…");

        silenceTimer = setTimeout(() => {
            handleSilence();
        }, SILENCE_TIMEOUT);
    };

    recognition.onerror = (event) => {
        console.error("[SPEECH] Error:", event.error);
        if (event.error === "not-allowed" || event.error === "permission-denied") {
            showSpeechStatus("🚫 Microphone access denied");
            stopListening();
            return;
        }
        if (event.error === "no-speech") {
            showSpeechStatus("🎙 No speech heard — still listening…");
            return;
        }
        if (isListening && event.error !== "aborted") {
            setTimeout(() => { if (isListening) recognition.start(); }, 300);
        }
    };

    recognition.onend = () => {
        if (isListening) {
            setTimeout(() => {
                if (isListening) {
                    try { recognition.start(); } catch (_) {}
                }
            }, 100);
        } else {
            commitSpeechIfReady(currentRole);
        }
    };

    recognition.onspeechstart = () => showSpeechStatus("🎙 Speech detected…");
    recognition.onspeechend   = () => showSpeechStatus("⏳ Waiting for more speech…");
}

function handleSilence() {
    const text = (speechBuffer + interimText).trim();
    const wordCount = text ? text.split(/\s+/).length : 0;
    if (text.length >= MIN_CHARS && wordCount >= MIN_NEW_WORDS) {
        commitSpeech(currentRole);
        showSpeechStatus("🎙 Committed. Keep speaking…");
    } else {
        showSpeechStatus("🎙 Listening… speak now");
    }
}

function commitSpeech(role) {
    const text = (speechBuffer + interimText).trim();
    if (!text || text.length < MIN_CHARS) return;
    removeInterimBubble();
    addMessage(role, text);
    speechBuffer = "";
    interimText  = "";
    analyzeConversation();
}

function commitSpeechIfReady(role) {
    const text = (speechBuffer + interimText).trim();
    if (text.length >= MIN_CHARS) {
        removeInterimBubble();
        addMessage(role, text);
        speechBuffer = "";
        interimText  = "";
        analyzeConversation();
    } else {
        removeInterimBubble();
        speechBuffer = "";
        interimText  = "";
    }
}

$btnMic.addEventListener("click", startListening);
$btnStop.addEventListener("click", stopListening);

function startListening() {
    if (!SpeechRecognition) return;
    speechBuffer = "";
    interimText  = "";
    initRecognition();
    try {
        recognition.start();
    } catch (e) {
        console.error("[SPEECH] Start failed:", e);
        showSpeechStatus("Failed to start mic: " + e.message);
    }
}

function stopListening() {
    isListening = false;
    clearTimeout(silenceTimer);
    $btnStop.classList.add("hidden");
    $btnMic.classList.remove("hidden");
    hideSpeechStatus();
    if (recognition) {
        try { recognition.stop(); } catch (_) {}
        recognition = null;
    }
}

function showSpeechStatus(text) {
    $speechStatus.textContent = text;
    $speechStatus.classList.remove("hidden");
}

function hideSpeechStatus() {
    $speechStatus.classList.add("hidden");
    $speechStatus.textContent = "";
}


// ═══════════════════════════════════════════════════════════
//  API — ANALYZE FULL CONVERSATION (v4: structured payload)
// ═══════════════════════════════════════════════════════════
async function analyzeConversation() {
    if (conversation.length === 0) return;
    if (isAnalyzing) return;

    const now = Date.now();
    if (now - lastAnalyzeTime < ANALYZE_COOLDOWN) {
        setTimeout(() => analyzeConversation(), ANALYZE_COOLDOWN);
        return;
    }

    isAnalyzing = true;
    lastAnalyzeTime = now;

    // Build structured payload — messages[] array
    const payload = getConversationPayload();
    if (!payload) {
        isAnalyzing = false;
        return;
    }

    console.log("[API] Sending structured conversation →", payload.messages.length, "messages");
    showAnalyzingIndicator();

    try {
        const res = await fetch(API_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),   // { messages: [{role, text}, ...] }
        });

        if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`);

        const data = await res.json();
        console.log("[API] Response ←", data);

        lastResult = data;
        removeAnalyzingIndicator();
        updateVerdictStrip(data);
        populateResultPanel(data);
        shield.setRisk(verdictToRisk(data.verdict));

    } catch (err) {
        console.error("[API] Error:", err);
        removeAnalyzingIndicator();
        updateVerdictStrip({
            verdict: "ERROR",
            confidence: "—",
            reasons: [buildErrorMessage(err)],
            actions: [],
        });
    } finally {
        isAnalyzing = false;
    }
}

function buildErrorMessage(err) {
    if (err.message.includes("Failed to fetch") || err.message.includes("NetworkError")) {
        return "Cannot reach backend. Ensure server is running on port 8000.";
    }
    if (err.message.startsWith("HTTP")) {
        return `Server error: ${err.message}`;
    }
    return "Unexpected: " + err.message;
}


// ═══════════════════════════════════════════════════════════
//  ANALYSIS PANEL — persistent left sidebar, live updates
// ═══════════════════════════════════════════════════════════
function updateAnalysisPanel(data) {
    if (!$analysisPanel) return;

    const TREND_ICON = { "ESCALATING": "🔴", "STABLE": "🟡", "DE-ESCALATING": "🟢" };
    const trendIcon  = TREND_ICON[data.trend] || "🟡";
    const trendLabel = data.trend || "STABLE";

    const isScam       = data.verdict === "SCAM";
    const isSuspicious = data.verdict === "SUSPICIOUS";
    const isSafe       = data.verdict === "SAFE";

    const verdictClass = isScam ? "scam" : isSuspicious ? "suspicious" : isSafe ? "safe" : "error";
    const verdictIcon  = isScam ? "🚨" : isSuspicious ? "⚠️" : isSafe ? "✅" : "⚙️";
    const verdictLabel = isScam ? "SCAM" : isSuspicious ? "SUSPICIOUS" : isSafe ? "SAFE" : data.verdict;

    // Strip the raw score breakdown line from sidebar (keep it in overlay only)
    const filteredReasons = (data.reasons || []).filter(r => !r.startsWith("Risk Scores —"));

    const reasonsHtml = filteredReasons.slice(0, 6)
        .map(r => `<li class="ap-reason-item">${esc(r)}</li>`)
        .join("") || `<li class="ap-reason-item">No specific signals detected.</li>`;

    const actionsHtml = (data.actions || [])
        .map(a => `<li class="ap-action-item">${esc(a)}</li>`)
        .join("") || `<li class="ap-action-item">Stay vigilant.</li>`;

    const html = `
        <div class="ap-header ap-header-${verdictClass}">
            <span class="ap-verdict-icon">${verdictIcon}</span>
            <div class="ap-verdict-label">${esc(verdictLabel)}</div>
            <div class="ap-conf">${esc(data.confidence || "—")} CONFIDENCE</div>
        </div>
        <div class="ap-trend">
            <span class="ap-trend-icon">${trendIcon}</span>
            <span class="ap-trend-label">${esc(trendLabel)}</span>
        </div>
        <div class="ap-section">
            <div class="ap-section-title">Analysis</div>
            <ul class="ap-list">${reasonsHtml}</ul>
        </div>
        <div class="ap-section">
            <div class="ap-section-title">Recommended Actions</div>
            <ul class="ap-list ap-actions-list">${actionsHtml}</ul>
        </div>
        <div class="ap-footer">Engine: ${esc(data.provider || "—")}</div>
    `;

    // Smooth fade — add class, update DOM, remove class in next frame
    $analysisPanel.classList.add("ap-updating");
    $analysisPanel.innerHTML = html;
    requestAnimationFrame(() => $analysisPanel.classList.remove("ap-updating"));
}


// ═══════════════════════════════════════════════════════════
//  VERDICT STRIP — now handles SUSPICIOUS tier
// ═══════════════════════════════════════════════════════════
function updateVerdictStrip(data) {
    $verdictStrip.classList.remove("hidden", "scam", "safe", "suspicious");

    // Phase 4: trend indicator — value comes from our own enum, not user input
    const TREND_ICON = { "ESCALATING": " 🔴", "STABLE": " 🟡", "DE-ESCALATING": " 🟢" };
    const trendTag   = TREND_ICON[data.trend] || "";

    if (data.verdict === "SCAM") {
        $verdictStrip.classList.add("scam");
        $verdictStrip.innerHTML = `
            <span class="strip-dot"></span>
            SCAM DETECTED — ${esc(data.confidence || "")} CONFIDENCE${trendTag}
            <span class="strip-dot"></span>
        `;
    } else if (data.verdict === "SUSPICIOUS") {
        $verdictStrip.classList.add("suspicious");
        $verdictStrip.innerHTML = `
            <span class="strip-dot"></span>
            ⚠ SUSPICIOUS ACTIVITY — ${esc(data.confidence || "")} CONFIDENCE${trendTag}
            <span class="strip-dot"></span>
        `;
    } else if (data.verdict === "SAFE") {
        $verdictStrip.classList.add("safe");
        $verdictStrip.innerHTML = `
            <span class="strip-dot"></span>
            CONVERSATION LOOKS SAFE${trendTag}
        `;
    } else {
        $verdictStrip.classList.add("safe");
        $verdictStrip.innerHTML = `⚠ Analysis Error`;
    }
}
$verdictStrip.addEventListener("click", () => {
    if (lastResult) showResultOverlay(lastResult);
});


// ═══════════════════════════════════════════════════════════
//  RESULT PANEL — extended for SUSPICIOUS tier
// ═══════════════════════════════════════════════════════════
function populateResultPanel(data) {
    lastResult = data;
    // Live-update the persistent left panel on every result
    updateAnalysisPanel(data);
    // Overlay is now opt-in via verdict strip click — no forced pop-up
}

function showResultOverlay(data) {
    const isScam       = data.verdict === "SCAM";
    const isSuspicious = data.verdict === "SUSPICIOUS";
    const panelClass   = isScam ? "scam" : isSuspicious ? "suspicious" : data.verdict === "ERROR" ? "error" : "safe";

    $resultPanel.className = `result-panel ${panelClass}`;

    const reasonsHtml = (data.reasons || []).map(r => `<li>${esc(r)}</li>`).join("");
    const actionsHtml = (data.actions || []).map(a => `<li>${esc(a)}</li>`).join("");

    let matchesSection = "";
    if ((isScam || isSuspicious) && data.matches && data.matches.length > 0) {
        matchesSection = `
            <div class="result-section">
                <div class="result-section-title">Triggered Patterns</div>
                <ul>${data.matches.map(m => `<li>${esc(m)}</li>`).join("")}</ul>
            </div>
        `;
    }

    let verdictIcon, verdictLabel, safetyMsg;
    if (isScam) {
        verdictIcon  = "🚨";
        verdictLabel = "Scam Detected";
        safetyMsg    = "⛔ Do NOT proceed. Follow the actions above immediately.";
    } else if (isSuspicious) {
        verdictIcon  = "⚠️";
        verdictLabel = "Suspicious Activity";
        safetyMsg    = "🟡 Proceed with extreme caution. Verify the other party independently before taking any action.";
    } else {
        verdictIcon  = "✅";
        verdictLabel = "Looks Safe";
        safetyMsg    = "Conversation appears safe. Stay alert for changes.";
    }

    $resultPanel.innerHTML = `
        <div class="result-header">
            <div class="result-verdict">${verdictIcon} ${esc(verdictLabel)}</div>
            <div class="result-conf">
                Confidence: ${esc(data.confidence || "—")} · Cluster: ${esc(data.cluster || "—")}
            </div>
        </div>
        ${matchesSection}
        <div class="result-section">
            <div class="result-section-title">Analysis</div>
            <ul>${reasonsHtml || "<li>No specific reasons.</li>"}</ul>
        </div>
        <div class="result-section result-actions">
            <div class="result-section-title">Recommended Actions</div>
            <ul>${actionsHtml || "<li>Proceed with caution.</li>"}</ul>
        </div>
        <div class="result-safety">${safetyMsg}</div>
        <button class="result-close" id="result-close-btn">Dismiss</button>
        <div class="result-provider">Engine: ${esc(data.provider || "UNKNOWN")}</div>
    `;

    $resultOverlay.classList.remove("hidden");
    document.getElementById("result-close-btn").addEventListener("click", hideResultOverlay);
}

function hideResultOverlay() {
    $resultOverlay.classList.add("hidden");
}

$resultBack.addEventListener("click", hideResultOverlay);

document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !$resultOverlay.classList.contains("hidden")) {
        hideResultOverlay();
    }
});


// ═══════════════════════════════════════════════════════════
//  RESET
// ═══════════════════════════════════════════════════════════
$btnReset.addEventListener("click", resetSession);

function resetSession() {
    if (isListening) stopListening();

    conversation      = [];
    speechBuffer      = "";
    interimText       = "";
    lastAnalyzeTime   = 0;
    lastAnalyzedLen   = 0;
    lastResult        = null;
    isAnalyzing       = false;

     removeInterimBubble();
    removeAnalyzingIndicator();
    renderAllMessages();
    hideResultOverlay();
    $verdictStrip.classList.add("hidden");
    shield.setRisk(0.0);
    if ($analysisPanel) {
        $analysisPanel.innerHTML = `
            <div class="ap-idle">
                <div class="ap-idle-icon">🛡️</div>
                <p>Awaiting conversation…</p>
            </div>`;
    }
    $input.value = "";
    $input.style.height = "auto";
    hideSpeechStatus();

    $btnReset.style.color = "var(--accent)";
    setTimeout(() => { $btnReset.style.color = ""; }, 400);

    console.log("[SCAMSHIELD] Session reset.");
}


// ═══════════════════════════════════════════════════════════
//  UTILITIES
// ═══════════════════════════════════════════════════════════
function esc(str) {
    return String(str)
        .replace(/&/g,  "&amp;")
        .replace(/</g,  "&lt;")
        .replace(/>/g,  "&gt;")
        .replace(/"/g,  "&quot;")
        .replace(/'/g,  "&#39;");
}


// ═══════════════════════════════════════════════════════════
//  SHADER — WebGL background, reacts to verdict
// ═══════════════════════════════════════════════════════════
const VERDICT_RISK = { SAFE: 0.05, SUSPICIOUS: 0.5, SCAM: 0.95 };

function verdictToRisk(verdict) {
    return VERDICT_RISK[verdict] ?? 0.05;
}

function initShader(canvasId) {
    const canvas = document.getElementById(canvasId);
    const gl = canvas && (canvas.getContext("webgl") || canvas.getContext("experimental-webgl"));
    if (!gl) { console.warn("[SHADER] WebGL unavailable"); return { setRisk: () => {} }; }

    const VERT = `
        attribute vec2 a_pos;
        void main(){gl_Position=vec4(a_pos,0.,1.);}
    `;
    const FRAG = `
        precision mediump float;
        uniform vec2  u_res;
        uniform float u_time;
        uniform float u_risk;
        float hash(vec2 p){return fract(sin(dot(p,vec2(127.1,311.7)))*43758.5453);}
        vec3 bgCol(float r){
            vec3 safe=vec3(.02,.07,.16),warn=vec3(.10,.07,.02),danger=vec3(.16,.02,.02);
            return r<.5?mix(safe,warn,r*2.):mix(warn,danger,(r-.5)*2.);
        }
        vec3 accCol(float r){
            vec3 safe=vec3(.15,.55,1.),warn=vec3(1.,.65,.1),danger=vec3(1.,.15,.1);
            return r<.5?mix(safe,warn,r*2.):mix(warn,danger,(r-.5)*2.);
        }
        void main(){
            vec2 uv=gl_FragCoord.xy/u_res;
            float ar=u_res.x/u_res.y;
            vec2 uvc=(uv-.5)*vec2(ar,1.);
            float t=u_time,r=u_risk;
            vec2 dv=vec2(sin(uv.y*(8.+r*22.)+t*(1.5+r*5.))*r*r*.018,
                         cos(uv.x*(5.6+r*15.4)+t*(1.2+r*4.))*r*r*.018);
            vec2 uvd=uv+dv, uvcd=(uvd-.5)*vec2(ar,1.);
            vec3 bg=bgCol(r)*(0.35+(1.-smoothstep(.25,.85,length(uvc)))*.65);
            vec3 ac=accCol(r);
            vec2 gf=fract(uvd*(20.+r*8.));
            float gl2=min(smoothstep(0.,.05,gf.x)*smoothstep(1.,.95,gf.x),
                          smoothstep(0.,.05,gf.y)*smoothstep(1.,.95,gf.y));
            bg=mix(bg,ac*.55,(1.-gl2)*(.07+r*.13));
            float d=length(uvcd);
            float rng=sin(d*(3.5+r*5.)*6.283-t*(.5+r*1.8)*2.);
            bg=mix(bg,ac,smoothstep(.5,1.,rng)*smoothstep(.85,.05,d)*(.1+r*.28));
            float sw=smoothstep(.25,.5,r);
            if(sw>.01){
                float sa=mod(t*(.9+r),6.2832);
                float ad=mod(sa-atan(uvcd.y,uvcd.x)+6.2832,6.2832);
                bg=mix(bg,ac*1.5,smoothstep(1.4,0.,ad)*smoothstep(.75,0.,d)*sw*.4);
            }
            bg*=1.-(.04+r*.04)*(sin(uv.y*u_res.y*.5)*.5+.5);
            for(int i=0;i<3;i++){
                float fi=float(i);
                float ly=fract(fi*.37+t*(.04+r*.16));
                float lx=uv.x*(2.5+fi*.6);
                float ld=abs(uv.y-ly+sin(lx*5.+t*(1.+fi*.4))*.025*(1.+r));
                float pl=sin(lx*4.-t*(3.+fi))*.5+.5;
                bg=mix(bg,ac*(.8+pl*.4),smoothstep(.005,0.,ld)*(.18+r*.22));
            }
            float gw=smoothstep(.65,.85,r);
            if(gw>.01){
                float bn=step(.97,hash(vec2(floor(uv.y*40.),floor(t*9.))));
                float sh=(hash(vec2(floor(t*9.),2.7))-.5)*.04;
                bg=mix(bg,vec3(hash((uv+vec2(sh,0.)*bn)*60.+t)*.4,0.,0.)+ac*.25,bn*gw*.55);
            }
            float cp=sin(t*(2.+r*5.))*.5+.5;
            bg=mix(bg,ac,smoothstep(.45,0.,d)*(.04+r*.22*cp));
            float ew=smoothstep(.6,1.,r);
            float ep=sin(t*(3.+r*6.))*.5+.5;
            bg=mix(bg,ac,smoothstep(.12,0.,min(min(uv.x,1.-uv.x),min(uv.y,1.-uv.y)))*ep*ew*.55);
            bg*=mix(1.,sin(t*55.)*.5+.5,smoothstep(.7,1.,r)*.07);
            gl_FragColor=vec4(bg,1.);
        }
    `;

    function compile(type, src) {
        const s = gl.createShader(type);
        gl.shaderSource(s, src); gl.compileShader(s);
        if (!gl.getShaderParameter(s, gl.COMPILE_STATUS))
            console.error("[SHADER]", gl.getShaderInfoLog(s));
        return s;
    }
    const prog = gl.createProgram();
    gl.attachShader(prog, compile(gl.VERTEX_SHADER,   VERT));
    gl.attachShader(prog, compile(gl.FRAGMENT_SHADER, FRAG));
    gl.linkProgram(prog); gl.useProgram(prog);

    const buf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1,-1,1,-1,-1,1,-1,1,1,-1,1,1]), gl.STATIC_DRAW);
    const ap = gl.getAttribLocation(prog, "a_pos");
    gl.enableVertexAttribArray(ap);
    gl.vertexAttribPointer(ap, 2, gl.FLOAT, false, 0, 0);

    const uRes  = gl.getUniformLocation(prog, "u_res");
    const uTime = gl.getUniformLocation(prog, "u_time");
    const uRisk = gl.getUniformLocation(prog, "u_risk");

    const t0 = performance.now();
    let cur = 0.0, tgt = 0.0;

    (function loop() {
        cur += (tgt - cur) * 0.04;
        const dpr = devicePixelRatio || 1;
        const w = canvas.clientWidth * dpr | 0, h = canvas.clientHeight * dpr | 0;
        if (canvas.width !== w || canvas.height !== h) {
            canvas.width = w; canvas.height = h; gl.viewport(0, 0, w, h);
        }
        gl.uniform2f(uRes, canvas.width, canvas.height);
        gl.uniform1f(uTime, (performance.now() - t0) / 1000);
        gl.uniform1f(uRisk, cur);
        gl.drawArrays(gl.TRIANGLES, 0, 6);
        requestAnimationFrame(loop);
    })();

    return { setRisk: v => { tgt = Math.max(0, Math.min(1, v)); } };
}


// ═══════════════════════════════════════════════════════════
//  INIT
// ═══════════════════════════════════════════════════════════
const shield = initShader("shield-canvas");
console.log("[SCAMSHIELD] v4 loaded. API:", API_URL);