#!/usr/bin/env python3
"""
Trivy Weekly Summary — Generates an executive summary after each scan.
Saves to reports/summary.json for the dashboard banner.

Usage:
  python3 trivy-summary.py              # Generate with Claude CLI
  python3 trivy-summary.py --no-ai      # Generate without AI (stats only)
"""
import json, os, sys, subprocess
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPORT = os.path.join(SCRIPT_DIR, "..", "reports", "latest.json")
HISTORY = os.path.join(SCRIPT_DIR, "..", "reports", "history.json")
RESOLVED = os.path.join(SCRIPT_DIR, "..", "reports", "resolved.json")
SUMMARY = os.path.join(SCRIPT_DIR, "..", "reports", "summary.json")
NO_AI = "--no-ai" in sys.argv

def main():
    print("📋 Trivy Weekly Summary")

    with open(REPORT) as f:
        data = json.load(f)
    with open(HISTORY) as f:
        history = json.load(f)
    with open(RESOLVED) as f:
        resolved = json.load(f)

    vulns = data["vulnerabilities"]
    curr = history[-1] if history else {}
    prev = history[-2] if len(history) > 1 else {}

    # Stats
    total = curr.get("total", 0)
    critical = curr.get("critical", 0)
    high = curr.get("high", 0)
    medium = curr.get("medium", 0)
    prev_total = prev.get("total", 0)
    prev_critical = prev.get("critical", 0)
    diff_total = total - prev_total
    diff_crit = critical - prev_critical
    exposed = len([v for v in vulns if v.get("exposed")])
    conflicts = len([v for v in vulns if v.get("hasConflict")])
    resolved_count = len(resolved)
    machines = len(data.get("machines_scanned", []))

    # Top 3 most urgent (critical + exposed)
    urgent = [v for v in vulns if v.get("exposed") and v["severity"] == "CRITICAL"]
    urgent_pkgs = list(set(v["pkg"] for v in urgent))[:3]

    # Detailed breakdown
    actionable = len([v for v in vulns if v.get("fixed") and not v.get("hasConflict")])
    no_fix = len([v for v in vulns if not v.get("fixed")])
    
    # New CVEs (not in previous scan)
    if len(history) >= 2:
        prev_date = history[-2].get("date", "")
    else:
        prev_date = ""
    
    # Resolved details
    resolved_pkgs = [f"{r['pkg']} ({r['severity']})" for r in resolved[:5]]
    
    # Exposed critical
    exposed_crit = [v for v in vulns if v.get("exposed") and v["severity"] == "CRITICAL" and v.get("fixed") and not v.get("hasConflict")]
    exposed_crit_pkgs = list(set(v["pkg"] for v in exposed_crit))[:5]
    
    # Conflict breakdown
    conflict_types = {}
    for v in vulns:
        if v.get("conflictType"):
            ct = v["conflictType"]["label"]
            conflict_types[ct] = conflict_types.get(ct, 0) + 1

    # Packages updated in staging (from resolved)
    resolved_details = []
    for r in resolved:
        resolved_details.append({"pkg": r["pkg"], "severity": r["severity"], "date": r.get("resolved_date", "")[:10]})

    stats = {
        "date": datetime.now().strftime("%Y-%m-%d"),
        "scan_date": data.get("timestamp", ""),
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "diff_total": diff_total,
        "diff_critical": diff_crit,
        "exposed": exposed,
        "conflicts": conflicts,
        "resolved": resolved_count,
        "machines": machines,
        "urgent_pkgs": urgent_pkgs,
        "actionable": actionable,
        "no_fix": no_fix,
        "exposed_crit_pkgs": exposed_crit_pkgs,
        "conflict_types": conflict_types,
        "resolved_details": resolved_details,
    }

    print(f"  Total: {total} ({'+' if diff_total >= 0 else ''}{diff_total})")
    print(f"  Críticos: {critical} ({'+' if diff_crit >= 0 else ''}{diff_crit})")
    print(f"  Expuestos: {exposed}")
    print(f"  Resueltas: {resolved_count}")

    # Generate AI summary
    ai_summary = ""
    if not NO_AI:
        resolved_text = ", ".join(resolved_pkgs) if resolved_pkgs else "ninguna"
        exposed_crit_text = ", ".join(exposed_crit_pkgs) if exposed_crit_pkgs else "ninguno"
        conflict_text = ", ".join(f"{k}: {v}" for k, v in conflict_types.items()) if conflict_types else "ninguno"
        
        prompt = f"""Genera un resumen ejecutivo de seguridad en español, completo pero conciso (4-6 frases).
Datos del escaneo semanal:
- Total: {total} vulnerabilidades ({'+' if diff_total >= 0 else ''}{diff_total} vs semana anterior)
- Críticas: {critical} ({'+' if diff_crit >= 0 else ''}{diff_crit} vs anterior)
- Altas: {high}
- Actualizables sin riesgo: {actionable}
- Conflictos de actualización: {conflicts} ({conflict_text})
- Sin solución disponible: {no_fix}
- Expuestas a internet: {exposed}
- Paquetes críticos expuestos actualizables: {exposed_crit_text}
- Resueltas esta semana: {resolved_count} ({resolved_text})
- Máquinas escaneadas: {machines}

Incluye:
1. Si hubo cambios vs la semana anterior o si está estable
2. Cuántas se resolvieron y cuáles (si hay)
3. Cuántas son actualizables sin riesgo (animar a actualizar)
4. Qué priorizar primero (críticos expuestos)
5. Estado de los conflictos
Tono profesional, directo, orientado a acción.
Responde SOLO con texto plano. No incluyas título, encabezado, fecha, ni línea introductoria. Empieza directamente con el análisis. Sin markdown, sin asteriscos, sin negritas."""

        try:
            result = subprocess.run(
                ["claude", "--print"],
                input=prompt,
                capture_output=True, text=True, timeout=60
            )
            ai_summary = result.stdout.strip()
            print(f"  IA: {ai_summary[:80]}...")
        except Exception as e:
            print(f"  IA no disponible: {e}")

    if not ai_summary:
        # Fallback without AI
        parts = []
        if diff_total == 0 and diff_crit == 0:
            parts.append(f"Sin cambios respecto a la semana anterior.")
        elif diff_total > 0:
            parts.append(f"{diff_total} nuevas vulnerabilidades detectadas ({diff_crit} críticas).")
        else:
            parts.append(f"{abs(diff_total)} vulnerabilidades menos que la semana anterior.")
        
        parts.append(f"Total: {total} en {machines} máquinas — {critical} críticas, {high} altas, {medium} medias.")
        
        if resolved_count > 0:
            parts.append(f"Resueltas: {resolved_count} ({', '.join(resolved_pkgs)}).")
        else:
            parts.append("No se resolvió ninguna vulnerabilidad esta semana.")
        
        parts.append(f"{actionable} son actualizables sin riesgo. {exposed} expuestas a internet.")
        
        if exposed_crit_pkgs:
            parts.append(f"Prioridad: actualizar {', '.join(exposed_crit_pkgs)} (críticos + expuestos).")
        
        ai_summary = " ".join(parts)

    stats["summary"] = ai_summary
    stats["summary_en"] = ""  # For future i18n

    with open(SUMMARY, "w") as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)
    print(f"  ✅ Guardado en: {SUMMARY}")

if __name__ == "__main__":
    main()
