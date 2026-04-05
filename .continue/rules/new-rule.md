---
description: A description of your rule
---

# AIShield-X Coding Rules

## 🚨 CRITICAL RULES (DO NOT BREAK)

1. DO NOT change project structure
- Do NOT create new folders like src/aishield
- Use existing files only

2. DO NOT rename files
- Keep original file names (monitor.py, app.py, mitigation.py, etc.)

3. DO NOT redesign architecture
- This is a real-time event-driven system
- Do NOT convert it into a different framework or structure

4. DO NOT remove existing functionality
- Monitoring, logging, detection, and UI must remain intact

---

## 🧠 HOW TO WORK ON THIS PROJECT

5. Only MODIFY existing functions
- Extend logic safely
- Do not rewrite full modules unless explicitly asked

6. Keep changes MINIMAL and SAFE
- Avoid large refactors
- Focus on small improvements

7. Respect current pipeline:

Event → Feature Extraction → Risk → Detection → Logging → UI

DO NOT break this flow

---

## 📊 FEATURE RULES

8. Severity system:
- LOW (risk < 30)
- MEDIUM (30–59)
- HIGH (>= 60)

9. Timeline:
- Log events with timestamp
- Format: "time → event → file"

10. Mitigation message:
- Use: "Threat contained → file quarantined"

---

## 🌐 UI RULES

11. DO NOT change UI architecture
- UI uses Flask + JS polling
- DO NOT convert to server-rendered templates

12. Only ADD UI elements
- timeline panel
- severity labels

---

## ⚙️ CODE STYLE

13. Always return FULL updated file
- No partial snippets

14. Code must run without errors

15. If unsure:
- KEEP ORIGINAL CODE
- ADD minimal changes

---

## 🎯 GOAL

Extend the system safely into a complete product without breaking functionality.