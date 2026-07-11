#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request

import core_report
import core_utils

G, R, C, Y, RESET = "\033[92m", "\033[91m", "\033[96m", "\033[93m", "\033[0m"
USER_AGENT = "CyberSec-Recon-Console/1.0"


class JwksResolutionError(ValueError):
    def __init__(self, message, attempts=None, tls_notes=None):
        super().__init__(message)
        self.attempts = attempts or []
        self.tls_notes = tls_notes or []


def normalize_target(raw_target):
    raw_target = (raw_target or "").strip()
    if not raw_target:
        raise ValueError("No target was provided.")

    if "://" not in raw_target:
        raw_target = f"https://{raw_target}"

    parsed = urllib.parse.urlparse(raw_target)
    if not parsed.hostname:
        raise ValueError("Invalid URL.")

    core_utils.validate_host(parsed.hostname)
    return parsed


def fetch_json(url, verify_tls=True):
    ssl_ctx = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json, application/jwk-set+json, */*;q=0.8",
        },
    )

    with urllib.request.urlopen(request, timeout=8, context=ssl_ctx) as response:
        body = response.read().decode("utf-8", errors="replace")
        headers = dict(response.headers.items())
        status = response.status
        final_url = response.geturl()

    parsed_body = json.loads(body)
    if not isinstance(parsed_body, dict):
        raise ValueError("The endpoint did not return a JSON object.")

    return {
        "status": status,
        "final_url": final_url,
        "headers": headers,
        "body": parsed_body,
        "tls_verified": verify_tls,
    }


def build_discovery_candidates(parsed_target):
    origin = f"{parsed_target.scheme}://{parsed_target.netloc}"
    path = parsed_target.path.rstrip("/")
    candidates = []

    def add_candidate(url, label):
        if url not in [item["url"] for item in candidates]:
            candidates.append({"url": url, "label": label})

    add_candidate(f"{origin}/.well-known/openid-configuration", "OIDC discovery")
    add_candidate(f"{origin}/.well-known/oauth-authorization-server", "OAuth authorization server metadata")

    if path:
        add_candidate(f"{origin}{path}/.well-known/openid-configuration", "OIDC path-based discovery")
        add_candidate(
            f"{origin}{path}/.well-known/oauth-authorization-server",
            "OAuth path-based metadata",
        )
        add_candidate(
            f"{origin}/.well-known/openid-configuration{path}",
            "OIDC alternate path discovery",
        )
        add_candidate(
            f"{origin}/.well-known/oauth-authorization-server{path}",
            "OAuth alternate path metadata",
        )

    return candidates


def discover_jwks_uri(parsed_target):
    tls_notes = []
    attempts = []

    for candidate in build_discovery_candidates(parsed_target):
        try:
            result = fetch_json(candidate["url"], verify_tls=True)
            jwks_uri = result["body"].get("jwks_uri")
            if jwks_uri:
                return {
                    "jwks_uri": jwks_uri,
                    "source_type": candidate["label"],
                    "source_url": candidate["url"],
                    "tls_verified": True,
                }, attempts, tls_notes
            attempts.append((candidate["label"], candidate["url"], "NO-JWKS", "Metadata did not advertise jwks_uri"))
        except urllib.error.HTTPError as exc:
            attempts.append((candidate["label"], candidate["url"], exc.code, str(exc.reason or "")))
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", "")
            if isinstance(reason, ssl.SSLCertVerificationError):
                tls_notes.append(f"TLS validation failed for {candidate['url']}: {reason}")
                try:
                    result = fetch_json(candidate["url"], verify_tls=False)
                    jwks_uri = result["body"].get("jwks_uri")
                    if jwks_uri:
                        return {
                            "jwks_uri": jwks_uri,
                            "source_type": candidate["label"],
                            "source_url": candidate["url"],
                            "tls_verified": False,
                        }, attempts, tls_notes
                    attempts.append((candidate["label"], candidate["url"], "NO-JWKS", "Metadata did not advertise jwks_uri"))
                except urllib.error.HTTPError as inner_exc:
                    attempts.append((candidate["label"], candidate["url"], inner_exc.code, str(inner_exc.reason or "")))
                except Exception as inner_exc:
                    attempts.append((candidate["label"], candidate["url"], "ERROR", str(inner_exc)))
            else:
                attempts.append((candidate["label"], candidate["url"], "ERROR", str(reason or exc)))
        except Exception as exc:
            attempts.append((candidate["label"], candidate["url"], "ERROR", str(exc)))

    return None, attempts, tls_notes


def resolve_jwks_target(parsed_target):
    origin = f"{parsed_target.scheme}://{parsed_target.netloc}"
    direct_candidates = [
        (parsed_target.geturl(), "Direct target"),
        (f"{origin}/.well-known/jwks.json", "Common JWKS path"),
        (f"{origin}/jwks.json", "Root jwks.json"),
        (f"{origin}/.well-known/jwks", "Common JWKS endpoint"),
    ]

    path = parsed_target.path.rstrip("/")
    if not path or path == "":
        discovery, attempts, tls_notes = discover_jwks_uri(parsed_target)
        if discovery:
            return discovery, attempts, tls_notes
    elif path.endswith(".json") or "jwks" in path.lower():
        return {
            "jwks_uri": parsed_target.geturl(),
            "source_type": "Direct JWKS URL",
            "source_url": parsed_target.geturl(),
            "tls_verified": True,
        }, [], []

    attempts = []
    tls_notes = []
    for url, label in direct_candidates:
        try:
            fetch_json(url, verify_tls=True)
            return {
                "jwks_uri": url,
                "source_type": label,
                "source_url": url,
                "tls_verified": True,
            }, attempts, tls_notes
        except urllib.error.HTTPError as exc:
            attempts.append((label, url, exc.code, str(exc.reason or "")))
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", "")
            if isinstance(reason, ssl.SSLCertVerificationError):
                tls_notes.append(f"TLS validation failed for {url}: {reason}")
                try:
                    fetch_json(url, verify_tls=False)
                    return {
                        "jwks_uri": url,
                        "source_type": label,
                        "source_url": url,
                        "tls_verified": False,
                    }, attempts, tls_notes
                except urllib.error.HTTPError as inner_exc:
                    attempts.append((label, url, inner_exc.code, str(inner_exc.reason or "")))
                except Exception as inner_exc:
                    attempts.append((label, url, "ERROR", str(inner_exc)))
            else:
                attempts.append((label, url, "ERROR", str(reason or exc)))
        except Exception as exc:
            attempts.append((label, url, "ERROR", str(exc)))

    discovery, discovery_attempts, discovery_tls_notes = discover_jwks_uri(parsed_target)
    attempts.extend(discovery_attempts)
    tls_notes.extend(discovery_tls_notes)
    if discovery:
        return discovery, attempts, tls_notes

    raise JwksResolutionError(
        "No JWKS endpoint could be resolved from the target.",
        attempts=attempts,
        tls_notes=tls_notes,
    )


def fetch_keyset(target_info):
    try:
        result = fetch_json(target_info["jwks_uri"], verify_tls=True)
        target_info["tls_verified"] = True
        return result, []
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", "")
        if isinstance(reason, ssl.SSLCertVerificationError):
            result = fetch_json(target_info["jwks_uri"], verify_tls=False)
            target_info["tls_verified"] = False
            return result, [f"TLS validation failed for {target_info['jwks_uri']}: {reason}"]
        raise


def summarize_key(key):
    material = "No public material"
    if key.get("n"):
        material = f"RSA modulus len={len(str(key.get('n')))}"
    elif key.get("x"):
        material = f"EC/OKP x len={len(str(key.get('x')))}"
    elif key.get("x5c"):
        material = f"x5c chain len={len(key.get('x5c') or [])}"

    return {
        "kid": key.get("kid", "Missing"),
        "kty": key.get("kty", "No data"),
        "use": key.get("use", "No data"),
        "alg": key.get("alg", "No data"),
        "ops": ",".join(key.get("key_ops", [])) if isinstance(key.get("key_ops"), list) else "No data",
        "material": material,
    }


def score_keyset(payload):
    keys = payload.get("keys")
    if not isinstance(keys, list):
        raise ValueError("JWKS payload does not contain a valid keys array.")

    findings = []
    recommendations = []
    score = 100

    if not keys:
        findings.append("[MISS] JWKS contains zero keys.")
        recommendations.append("Publish at least one active public key for signature verification.")
        score = 0
        return score, "Weak", findings, recommendations, []

    sig_keys = 0
    enc_keys = 0
    missing_kid = 0
    weak_alg = 0
    seen_kids = set()
    duplicate_kids = set()
    key_summaries = []

    for key in keys:
        summary = summarize_key(key)
        key_summaries.append(summary)

        kid = key.get("kid")
        if kid:
            if kid in seen_kids:
                duplicate_kids.add(kid)
            seen_kids.add(kid)
        else:
            missing_kid += 1

        use = str(key.get("use", "") or "").lower()
        alg = str(key.get("alg", "") or "").lower()
        if use == "sig":
            sig_keys += 1
        elif use == "enc":
            enc_keys += 1

        if alg in ("none", "hs256", "hs384", "hs512"):
            weak_alg += 1

    findings.append(f"[OK] JWKS exposes {len(keys)} key(s).")

    if sig_keys:
        findings.append(f"[OK] {sig_keys} key(s) are marked for signing.")
    else:
        findings.append("[WARN] No key is explicitly marked with use=sig.")
        recommendations.append("Label signing keys with use=sig for clearer client validation.")
        score -= 15

    if enc_keys:
        findings.append(f"[INFO] {enc_keys} key(s) are marked for encryption.")

    if missing_kid:
        findings.append(f"[WARN] {missing_kid} key(s) are missing kid.")
        recommendations.append("Assign kid values to all published keys to support safe rotation.")
        score -= min(25, missing_kid * 8)
    else:
        findings.append("[OK] Every key includes kid.")

    if duplicate_kids:
        findings.append(f"[WEAK] Duplicate kid values detected: {', '.join(sorted(duplicate_kids))}")
        recommendations.append("Ensure every published key has a unique kid value.")
        score -= 30

    if weak_alg:
        findings.append(f"[WEAK] {weak_alg} key(s) advertise weak or inappropriate algorithms.")
        recommendations.append("Avoid weak or symmetric algorithm markers in public JWKS documents.")
        score -= min(30, weak_alg * 10)

    if len(keys) > 5:
        findings.append("[INFO] Large keyset observed. Review whether old keys should be retired.")
        recommendations.append("Retire stale public keys after rotation windows close.")
        score -= 5

    score = max(0, min(score, 100))
    if score >= 85:
        verdict = "Strong"
    elif score >= 60:
        verdict = "Moderate"
    else:
        verdict = "Weak"

    unique_recommendations = []
    for item in recommendations:
        if item not in unique_recommendations:
            unique_recommendations.append(item)

    return score, verdict, findings, unique_recommendations, key_summaries


def build_report(parsed_target, target_info, result, score, verdict, findings, recommendations, attempts, key_summaries):
    recommendation_lines = [f"- {item}" for item in recommendations] or ["- No hardening recommendations generated."]
    attempt_lines = (
        [f"- {label}: {status} ({url})" for label, url, status, _reason in attempts]
        or ["- Primary JWKS source responded successfully on first attempt."]
    )
    lines = [
        "JWKS KEYSET INSPECTOR",
        "",
        f"Initial target: {parsed_target.geturl()}",
        f"Source type: {target_info['source_type']}",
        f"Source URL: {target_info['source_url']}",
        f"JWKS URL: {target_info['jwks_uri']}",
        f"Final URL: {result['final_url']}",
        f"Status: {result['status']}",
        f"Score: {score}/100",
        f"Verdict: {verdict}",
        "",
        "[Keys]",
        *(
            f"- kid={item['kid']} | kty={item['kty']} | use={item['use']} | alg={item['alg']} | material={item['material']}"
            for item in key_summaries
        ),
        "",
        "[Findings]",
        *(f"- {item}" for item in findings),
        "",
        "[Recommendations]",
        *recommendation_lines,
        "",
        "[Attempted Endpoints]",
        *attempt_lines,
    ]
    return "\n".join(lines)


def run():
    while True:
        print(f"{C}================================================================{RESET}")
        print(f"                    {Y}JWKS KEYSET INSPECTOR{RESET}")
        print(f"{C}================================================================{RESET}")
        target = input("\n URL or host (for example https://example.com or example.com) [0=back]: ").strip()

        if target in ("", "0"):
            break

        try:
            parsed_target = normalize_target(target)
            print(f"\n [i] Resolving JWKS source for {parsed_target.netloc}...")
            target_info, attempts, tls_notes = resolve_jwks_target(parsed_target)
            result, fetch_tls_notes = fetch_keyset(target_info)
            tls_notes.extend(fetch_tls_notes)

            score, verdict, findings, recommendations, key_summaries = score_keyset(result["body"])

            sig_keys = sum(1 for item in key_summaries if item["use"].lower() == "sig")
            enc_keys = sum(1 for item in key_summaries if item["use"].lower() == "enc")
            unique_kids = len({item["kid"] for item in key_summaries if item["kid"] != "Missing"})

            print(f"\n {G}>>> JWKS SUMMARY{RESET}")
            print(" ----------------------------------------------------------------")
            print(f" INITIAL URL:    {parsed_target.geturl()}")
            print(f" SOURCE TYPE:    {target_info['source_type']}")
            print(f" SOURCE URL:     {target_info['source_url']}")
            print(f" JWKS URL:       {target_info['jwks_uri']}")
            print(f" FINAL URL:      {result['final_url']}")
            print(f" STATUS:         {result['status']}")
            print(f" SCORE:          {score}/100")
            print(f" VERDICT:        {verdict}")
            print(f" KEY COUNT:      {len(key_summaries)}")
            print(f" UNIQUE KIDS:    {unique_kids}")
            print(f" SIG KEYS:       {sig_keys}")
            print(f" ENC KEYS:       {enc_keys}")
            print(f" TLS VERIFY:     {G + 'OK' + RESET if result['tls_verified'] else Y + 'BYPASS / UNVERIFIED' + RESET}")
            print(" ----------------------------------------------------------------")
            for note in tls_notes:
                print(f" {Y}[TLS NOTICE]{RESET} {note}")
                print(f" {Y}[TLS NOTICE]{RESET} JWKS collection continued in unverified certificate mode.")

            print(f"\n {Y}KEY DETAILS:{RESET}")
            for index, item in enumerate(key_summaries, 1):
                print(f"  [{index}] kid={item['kid']} | kty={item['kty']} | use={item['use']} | alg={item['alg']}")
                print(f"      key_ops={item['ops']} | material={item['material']}")

            print(f"\n {Y}FINDINGS:{RESET}")
            for finding in findings:
                print(f"  {finding}")

            print(f"\n {Y}ATTEMPTED ENDPOINTS:{RESET}")
            if attempts:
                for label, url, status, reason in attempts:
                    reason_suffix = f" | {reason}" if reason else ""
                    print(f"  - [{status}] {label}: {url}{reason_suffix}")
            else:
                print("  - Primary JWKS source responded successfully on first attempt.")

            print(f"\n {Y}HARDENING RECOMMENDATIONS:{RESET}")
            if recommendations:
                for item in recommendations:
                    print(f"  - {item}")
            else:
                print("  - No additional hardening guidance was generated.")

            report = build_report(parsed_target, target_info, result, score, verdict, findings, recommendations, attempts, key_summaries)
            if input("\n [?] Save results to file? (y/n): ").strip().lower() == "y":
                core_report.save(report, "JWKS_Keyset_Inspector")
        except JwksResolutionError as exc:
            print(f"\n {Y}>>> JWKS SUMMARY{RESET}")
            print(" ----------------------------------------------------------------")
            print(f" INITIAL URL:    {parsed_target.geturl()}")
            print(f" STATUS:         No JWKS source found")
            print(" ----------------------------------------------------------------")
            for note in exc.tls_notes:
                print(f" {Y}[TLS NOTICE]{RESET} {note}")
                print(f" {Y}[TLS NOTICE]{RESET} JWKS discovery continued in unverified certificate mode.")

            print(f"\n {Y}FINDINGS:{RESET}")
            print("  - No OIDC metadata or direct JWKS endpoint was discovered for this target.")
            print("  - This is common for standard marketing sites or applications that do not expose federated authentication metadata.")

            print(f"\n {Y}ATTEMPTED ENDPOINTS:{RESET}")
            if exc.attempts:
                for label, url, status, reason in exc.attempts:
                    reason_suffix = f" | {reason}" if reason else ""
                    print(f"  - [{status}] {label}: {url}{reason_suffix}")
            else:
                print("  - No candidate endpoints were generated.")

            print(f"\n {Y}NEXT STEPS:{RESET}")
            print("  - Try a direct JWKS URL if you know it, for example https://target/.well-known/jwks.json")
            print("  - Run OI first to check whether the target exposes OIDC discovery metadata")
        except Exception as exc:
            print(f"\n {R}[ERROR]{RESET} {exc}")

        input("\n Enter...")
