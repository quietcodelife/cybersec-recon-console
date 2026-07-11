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


class OidcDiscoveryError(ValueError):
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


def build_candidates(parsed_target):
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
        raise ValueError("Discovery endpoint did not return a JSON object.")

    return {
        "status": status,
        "final_url": final_url,
        "headers": headers,
        "body": parsed_body,
        "tls_verified": verify_tls,
    }


def collect_discovery(parsed_target):
    tls_notes = []
    attempts = []

    for candidate in build_candidates(parsed_target):
        try:
            result = fetch_json(candidate["url"], verify_tls=True)
            result["source_label"] = candidate["label"]
            result["source_url"] = candidate["url"]
            return result, attempts, tls_notes
        except urllib.error.HTTPError as exc:
            attempts.append((candidate["label"], candidate["url"], exc.code, str(exc.reason or "")))
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", "")
            if isinstance(reason, ssl.SSLCertVerificationError):
                tls_notes.append(f"TLS validation failed for {candidate['url']}: {reason}")
                try:
                    result = fetch_json(candidate["url"], verify_tls=False)
                    result["source_label"] = candidate["label"]
                    result["source_url"] = candidate["url"]
                    return result, attempts, tls_notes
                except urllib.error.HTTPError as inner_exc:
                    attempts.append((candidate["label"], candidate["url"], inner_exc.code, str(inner_exc.reason or "")))
                except Exception as inner_exc:
                    attempts.append((candidate["label"], candidate["url"], "ERROR", str(inner_exc)))
            else:
                attempts.append((candidate["label"], candidate["url"], "ERROR", str(reason or exc)))
        except json.JSONDecodeError:
            attempts.append((candidate["label"], candidate["url"], "INVALID", "Response was not valid JSON"))
        except Exception as exc:
            attempts.append((candidate["label"], candidate["url"], "ERROR", str(exc)))

    raise OidcDiscoveryError(
        "No OIDC or OAuth discovery document could be collected from the tested well-known endpoints.",
        attempts=attempts,
        tls_notes=tls_notes,
    )


def summarize_values(values, limit=6):
    if not values:
        return "No data"
    if isinstance(values, str):
        return values
    flattened = [str(item) for item in values if str(item).strip()]
    if not flattened:
        return "No data"
    if len(flattened) <= limit:
        return ", ".join(flattened)
    return ", ".join(flattened[:limit]) + f" ... (+{len(flattened) - limit} more)"


def score_document(document):
    findings = []
    recommendations = []
    score = 0

    if document.get("issuer"):
        score += 15
        findings.append("[OK] Issuer metadata is present.")
    else:
        findings.append("[MISS] issuer is missing.")
        recommendations.append("Publish the issuer field to align with OIDC/OAuth metadata expectations.")

    if document.get("authorization_endpoint"):
        score += 15
        findings.append("[OK] authorization_endpoint is present.")
    else:
        findings.append("[MISS] authorization_endpoint is missing.")

    if document.get("token_endpoint"):
        score += 15
        findings.append("[OK] token_endpoint is present.")
    else:
        findings.append("[MISS] token_endpoint is missing.")

    if document.get("jwks_uri"):
        score += 20
        findings.append("[OK] jwks_uri is advertised.")
    else:
        findings.append("[MISS] jwks_uri is missing.")
        recommendations.append("Expose jwks_uri so clients can validate token signatures.")

    response_types = document.get("response_types_supported") or []
    if response_types:
        score += 10
        findings.append(f"[OK] response_types_supported includes {len(response_types)} value(s).")
    else:
        findings.append("[WARN] response_types_supported is not declared.")

    grant_types = document.get("grant_types_supported") or []
    if grant_types:
        score += 10
        findings.append(f"[OK] grant_types_supported includes {len(grant_types)} value(s).")
    else:
        findings.append("[WARN] grant_types_supported is not declared.")

    signing_algs = document.get("id_token_signing_alg_values_supported") or document.get("token_endpoint_auth_signing_alg_values_supported") or []
    if signing_algs:
        score += 10
        findings.append("[OK] Signing algorithm metadata is published.")
        lowered = [str(item).lower() for item in signing_algs]
        if "none" in lowered:
            findings.append("[WEAK] The metadata advertises alg=none.")
            recommendations.append("Do not advertise or accept alg=none for signed tokens.")
            score -= 25
    else:
        findings.append("[WARN] No token signing algorithm metadata was declared.")

    methods = document.get("token_endpoint_auth_methods_supported") or []
    if methods:
        score += 10
        findings.append("[OK] token_endpoint_auth_methods_supported is published.")
        if "client_secret_post" in methods:
            recommendations.append("Review whether client_secret_post is necessary or if stronger client authentication methods are preferred.")
    else:
        findings.append("[WARN] token_endpoint_auth_methods_supported is not declared.")

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

    return score, verdict, findings, unique_recommendations


def print_list_section(title, values, limit=8):
    print(f"\n {Y}{title}:{RESET}")
    if not values:
        print("  none")
        return
    for value in values[:limit]:
        print(f"  - {value}")
    if len(values) > limit:
        print(f"  ... {len(values) - limit} more")


def build_report(parsed_target, result, score, verdict, findings, recommendations, attempts):
    document = result["body"]
    recommendation_lines = [f"- {item}" for item in recommendations] or ["- No hardening recommendations generated."]
    attempt_lines = (
        [f"- {label}: {status} ({url})" for label, url, status, _reason in attempts]
        or ["- Primary discovery endpoint responded successfully on first attempt."]
    )
    lines = [
        "OAUTH / OIDC DISCOVERY RECON",
        "",
        f"Initial target: {parsed_target.geturl()}",
        f"Discovery source: {result['source_label']}",
        f"Source URL: {result['source_url']}",
        f"Final URL: {result['final_url']}",
        f"Status: {result['status']}",
        f"Score: {score}/100",
        f"Verdict: {verdict}",
        "",
        "[Core Metadata]",
        f"- issuer: {document.get('issuer', 'No data')}",
        f"- authorization_endpoint: {document.get('authorization_endpoint', 'No data')}",
        f"- token_endpoint: {document.get('token_endpoint', 'No data')}",
        f"- jwks_uri: {document.get('jwks_uri', 'No data')}",
        f"- userinfo_endpoint: {document.get('userinfo_endpoint', 'No data')}",
        f"- registration_endpoint: {document.get('registration_endpoint', 'No data')}",
        f"- introspection_endpoint: {document.get('introspection_endpoint', 'No data')}",
        f"- revocation_endpoint: {document.get('revocation_endpoint', 'No data')}",
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
        print(f"                  {Y}OAUTH / OIDC DISCOVERY RECON{RESET}")
        print(f"{C}================================================================{RESET}")
        target = input("\n URL or host (for example https://example.com or example.com) [0=back]: ").strip()

        if target in ("", "0"):
            break

        try:
            parsed_target = normalize_target(target)
            print(f"\n [i] Probing well-known OAuth / OIDC metadata on {parsed_target.netloc}...")
            result, attempts, tls_notes = collect_discovery(parsed_target)
            document = result["body"]
            score, verdict, findings, recommendations = score_document(document)

            print(f"\n {G}>>> DISCOVERY SUMMARY{RESET}")
            print(" ----------------------------------------------------------------")
            print(f" INITIAL URL:    {parsed_target.geturl()}")
            print(f" SOURCE TYPE:    {result['source_label']}")
            print(f" SOURCE URL:     {result['source_url']}")
            print(f" FINAL URL:      {result['final_url']}")
            print(f" STATUS:         {result['status']}")
            print(f" SCORE:          {score}/100")
            print(f" VERDICT:        {verdict}")
            print(f" TLS VERIFY:     {G + 'OK' + RESET if result['tls_verified'] else Y + 'BYPASS / UNVERIFIED' + RESET}")
            print(" ----------------------------------------------------------------")
            for note in tls_notes:
                print(f" {Y}[TLS NOTICE]{RESET} {note}")
                print(f" {Y}[TLS NOTICE]{RESET} Metadata collection continued in unverified certificate mode.")

            print(f"\n {Y}CORE ENDPOINTS:{RESET}")
            print(f"  Issuer:                {document.get('issuer', 'No data')}")
            print(f"  Authorization:         {document.get('authorization_endpoint', 'No data')}")
            print(f"  Token:                 {document.get('token_endpoint', 'No data')}")
            print(f"  JWKS:                  {document.get('jwks_uri', 'No data')}")
            print(f"  UserInfo:              {document.get('userinfo_endpoint', 'No data')}")
            print(f"  Registration:          {document.get('registration_endpoint', 'No data')}")
            print(f"  Introspection:         {document.get('introspection_endpoint', 'No data')}")
            print(f"  Revocation:            {document.get('revocation_endpoint', 'No data')}")

            print_list_section("SUPPORTED RESPONSE TYPES", document.get("response_types_supported") or [])
            print_list_section("SUPPORTED GRANT TYPES", document.get("grant_types_supported") or [])
            print_list_section(
                "TOKEN ENDPOINT AUTH METHODS",
                document.get("token_endpoint_auth_methods_supported") or [],
            )
            print_list_section(
                "ID TOKEN SIGNING ALGORITHMS",
                document.get("id_token_signing_alg_values_supported") or [],
            )
            print_list_section("SCOPES", document.get("scopes_supported") or [])

            print(f"\n {Y}FINDINGS:{RESET}")
            for finding in findings:
                print(f"  {finding}")

            print(f"\n {Y}ATTEMPTED ENDPOINTS:{RESET}")
            if attempts:
                for label, url, status, reason in attempts:
                    reason_suffix = f" | {reason}" if reason else ""
                    print(f"  - [{status}] {label}: {url}{reason_suffix}")
            else:
                print("  - Primary discovery endpoint responded successfully on first attempt.")

            print(f"\n {Y}HARDENING RECOMMENDATIONS:{RESET}")
            if recommendations:
                for item in recommendations:
                    print(f"  - {item}")
            else:
                print("  - No additional hardening guidance was generated.")

            report = build_report(parsed_target, result, score, verdict, findings, recommendations, attempts)
            if input("\n [?] Save results to file? (y/n): ").strip().lower() == "y":
                core_report.save(report, "OAuth_OIDC_Discovery_Recon")
        except OidcDiscoveryError as exc:
            print(f"\n {Y}>>> DISCOVERY SUMMARY{RESET}")
            print(" ----------------------------------------------------------------")
            print(f" INITIAL URL:    {parsed_target.geturl()}")
            print(" STATUS:         No discovery document found")
            print(" ----------------------------------------------------------------")
            for note in exc.tls_notes:
                print(f" {Y}[TLS NOTICE]{RESET} {note}")
                print(f" {Y}[TLS NOTICE]{RESET} Metadata discovery continued in unverified certificate mode.")

            print(f"\n {Y}FINDINGS:{RESET}")
            print("  - No OIDC or OAuth well-known metadata was discovered for this target.")
            print("  - This is normal for standard sites that do not expose identity provider or authorization server metadata.")

            print(f"\n {Y}ATTEMPTED ENDPOINTS:{RESET}")
            if exc.attempts:
                for label, url, status, reason in exc.attempts:
                    reason_suffix = f" | {reason}" if reason else ""
                    print(f"  - [{status}] {label}: {url}{reason_suffix}")
            else:
                print("  - No candidate endpoints were generated.")

            print(f"\n {Y}NEXT STEPS:{RESET}")
            print("  - If this application uses federated login, test the actual identity provider domain instead of the public website")
            print("  - If you know the provider, try the issuer URL directly")
        except Exception as exc:
            print(f"\n {R}[ERROR]{RESET} {exc}")

        input("\n Enter...")
