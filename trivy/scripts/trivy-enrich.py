#!/usr/bin/env python3
"""
Trivy CVE Enrichment — Genera what/why/howToFix para cada vulnerabilidad
Usa Claude CLI para analizar CVEs en lotes

Features:
- Retries con backoff exponencial (3 intentos por batch)
- Guardado incremental (cada batch exitoso se guarda)
- Skip automático de CVEs ya enriquecidos
- Timeout progresivo (180s → 240s → 300s)
"""
import json, subprocess, sys, time, os, signal

REPORT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reports", "latest.json")
BATCH_SIZE = 10
SLEEP_BETWEEN = 2
MAX_RETRIES = 3
BASE_TIMEOUT = 180


def enrich_batch(vulns_batch, attempt=1):
    """Envía un lote de CVEs a Claude y devuelve las explicaciones"""

    cves_text = ""
    for v in vulns_batch:
        cves_text += f"- {v['id']} | {v['severity']} | pkg: {v['pkg']} | {v['installed']} → {v['fixed'] or 'sin fix'} | {v['title']} | machines: {','.join(v.get('machines',[]))}\n"

    prompt = f"""Analiza estas vulnerabilidades de seguridad y devuelve SOLO un JSON array (sin markdown, sin backticks, sin texto extra) con un objeto por cada CVE.

Cada objeto debe tener exactamente estos campos:
- "id": el CVE-ID exacto
- "what": explicación en español sencillo de qué hace esta vulnerabilidad (2-3 frases, sin jerga técnica)
- "why": por qué es grave para tu infraestructura, mencionando el impacto real (2-3 frases)
- "howToFix": pasos exactos para arreglarlo (comando o instrucción concreta)

Vulnerabilidades:
{cves_text}
Responde SOLO con el JSON array. Sin ```json, sin explicaciones, solo el array JSON."""

    timeout = BASE_TIMEOUT + (attempt - 1) * 60  # 180s, 240s, 300s

    try:
        result = subprocess.run(
            ["claude", "--print"],
            input=prompt,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        if result.returncode != 0:
            return None, f"Claude exit code {result.returncode}: {result.stderr[:100]}"

        text = result.stdout.strip()
        # Limpiar backticks si los pone
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()

        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            # Intentar extraer JSON del texto
            start = text.index("[")
            end = text.rindex("]") + 1
            parsed = json.loads(text[start:end])

        if isinstance(parsed, list) and len(parsed) > 0:
            return parsed, None
        else:
            return None, "Empty or invalid response"

    except subprocess.TimeoutExpired:
        return None, f"Timeout ({timeout}s)"
    except (json.JSONDecodeError, ValueError) as e:
        return None, f"JSON parse error: {e}"
    except Exception as e:
        return None, f"Error: {e}"


def save_progress(data, report_path):
    """Guarda el JSON con los datos enriquecidos hasta el momento"""
    with open(report_path, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def main():
    print("🔍 Trivy CVE Enrichment")
    print(f"  Reporte: {REPORT}")

    with open(REPORT) as f:
        data = json.load(f)

    vulns = data["vulnerabilities"]

    # Filtrar las que ya tienen explicación
    to_enrich = [v for v in vulns if not v.get("what")]
    already = len(vulns) - len(to_enrich)

    print(f"  Total: {len(vulns)} vulnerabilidades")
    print(f"  Ya enriquecidas: {already}")
    print(f"  Pendientes: {len(to_enrich)}")

    if not to_enrich:
        print("✅ Todas las vulnerabilidades ya tienen explicación")
        return

    # Agrupar por CVE único (no repetir análisis)
    by_cve = {}
    for v in to_enrich:
        if v["id"] not in by_cve:
            by_cve[v["id"]] = v

    unique_cves = list(by_cve.values())
    total_batches = (len(unique_cves) + BATCH_SIZE - 1) // BATCH_SIZE

    print(f"  CVEs únicos a analizar: {len(unique_cves)}")
    print(f"  Batches de {BATCH_SIZE}: {total_batches}")
    print(f"  Reintentos por batch: {MAX_RETRIES}")
    print(f"  Timeout base: {BASE_TIMEOUT}s (incrementa {60}s por reintento)")
    print()

    enriched = {}  # id -> {what, why, howToFix}
    errors = 0
    saved_count = 0

    for i in range(0, len(unique_cves), BATCH_SIZE):
        batch = unique_cves[i:i+BATCH_SIZE]
        batch_num = i // BATCH_SIZE + 1

        success = False
        for attempt in range(1, MAX_RETRIES + 1):
            if attempt == 1:
                print(f"  [{batch_num}/{total_batches}] Analizando {len(batch)} CVEs...", end=" ", flush=True)
            else:
                print(f"    ↻ Reintento {attempt}/{MAX_RETRIES}...", end=" ", flush=True)

            results, error = enrich_batch(batch, attempt)

            if results:
                for r in results:
                    cve_id = r.get("id", "")
                    if cve_id:
                        enriched[cve_id] = {
                            "what": r.get("what", ""),
                            "why": r.get("why", ""),
                            "howToFix": r.get("howToFix", "")
                        }
                print(f"✓ {len(results)} OK")
                success = True

                # Aplicar y guardar incrementalmente
                applied_batch = 0
                for v in vulns:
                    if v["id"] in enriched and not v.get("what"):
                        e = enriched[v["id"]]
                        v["what"] = e["what"]
                        v["why"] = e["why"]
                        v["howToFix"] = e["howToFix"]
                        applied_batch += 1

                if applied_batch > 0:
                    save_progress(data, REPORT)
                    saved_count += applied_batch

                break  # No más reintentos
            else:
                print(f"⚠ {error}")
                if attempt < MAX_RETRIES:
                    wait = attempt * 5  # 5s, 10s
                    print(f"    Esperando {wait}s antes de reintentar...")
                    time.sleep(wait)

        if not success:
            errors += 1
            failed_ids = [v["id"] for v in batch]
            print(f"    ✗ Batch fallido tras {MAX_RETRIES} intentos: {', '.join(failed_ids[:3])}...")

        if i + BATCH_SIZE < len(unique_cves):
            time.sleep(SLEEP_BETWEEN)

    total_enriched = sum(1 for v in vulns if v.get("what"))

    print()
    print(f"✅ Enriquecimiento completado:")
    print(f"  CVEs analizados: {len(enriched)}")
    print(f"  Guardados incrementalmente: {saved_count}")
    print(f"  Total enriquecidas: {total_enriched}/{len(vulns)}")
    print(f"  Batches fallidos: {errors}")
    print(f"  Guardado en: {REPORT}")

    # Also enrich resolved.json with AI data from latest.json
    resolved_path = os.path.join(os.path.dirname(REPORT), "resolved.json")
    if os.path.exists(resolved_path):
        with open(resolved_path) as f:
            resolved = json.load(f)
        # Build lookup from all enriched vulns (latest + just enriched)
        ai_lookup = {}
        for v in vulns:
            if v.get("what"):
                ai_lookup[v["id"]] = {"what": v["what"], "why": v["why"], "howToFix": v["howToFix"]}
        updated = 0
        for r in resolved:
            if not r.get("what") and r["id"] in ai_lookup:
                r.update(ai_lookup[r["id"]])
                updated += 1
        if updated > 0:
            with open(resolved_path, "w") as f:
                json.dump(resolved, f, indent=2, ensure_ascii=False)
            print(f"  Resueltas actualizadas con IA: {updated}")


if __name__ == "__main__":
    main()
