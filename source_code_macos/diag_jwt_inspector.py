#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
import json
import time
from datetime import datetime, timezone

import core_report

G, R, C, Y, RESET = "\033[92m", "\033[91m", "\033[96m", "\033[93m", "\033[0m"

SENSITIVE_CLAIMS = {"sub", "email", "upn", "preferred_username", "name"}


def normalize_token(raw_value):
    raw_value = (raw_value or "").strip()
    if not raw_value:
        raise ValueError("No token was provided.")
    if raw_value.lower().startswith("authorization:"):
        raw_value = raw_value.split(":", 1)[1].strip()
    if raw_value.lower().startswith("bearer "):
        raw_value = raw_value[7:].strip()
    if not raw_value:
        raise ValueError("No token was provided after stripping the Authorization prefix.")
    return raw_value


def decode_base64url(value):
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def parse_json_segment(segment, label):
    try:
        decoded = decode_base64url(segment).decode("utf-8")
        return json.loads(decoded), decoded
    except Exception as exc:
        raise ValueError(f"Unable to decode the {label} segment: {exc}") from exc


def format_unix_timestamp(raw_value):
    try:
        timestamp = int(raw_value)
        dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC"), timestamp
    except Exception:
        return "Invalid timestamp", None


def describe_ttl(exp_ts, iat_ts, now_ts):
    if exp_ts is None:
        return "No expiration"
    seconds_left = exp_ts - now_ts
    if seconds_left < 0:
        return f"Expired {abs(seconds_left)} seconds ago"
    if iat_ts is not None and exp_ts >= iat_ts:
        ttl = exp_ts - iat_ts
        return f"{ttl} seconds total lifetime / {seconds_left} seconds remaining"
    return f"{seconds_left} seconds remaining"


def classify_claims(payload):
    claims = []
    for key in sorted(payload.keys()):
        value = payload[key]
        rendered = json.dumps(value, ensure_ascii=True) if isinstance(value, (dict, list)) else str(value)
        if key in SENSITIVE_CLAIMS and len(rendered) > 24:
            rendered = rendered[:24] + "..."
        claims.append((key, rendered))
    return claims


def evaluate_token(header, payload, signature_present, token_parts):
    issues = []
    recommendations = []
    score = 100
    now_ts = int(time.time())

    alg = str(header.get("alg", "") or "").strip()
    token_type = str(header.get("typ", "") or "").strip()
    kid = str(header.get("kid", "") or "").strip()

    exp_fmt, exp_ts = format_unix_timestamp(payload.get("exp")) if "exp" in payload else ("Missing", None)
    nbf_fmt, nbf_ts = format_unix_timestamp(payload.get("nbf")) if "nbf" in payload else ("Not set", None)
    iat_fmt, iat_ts = format_unix_timestamp(payload.get("iat")) if "iat" in payload else ("Not set", None)

    if len(token_parts) == 5:
        issues.append("Token appears to be JWE (encrypted). Payload inspection is limited.")
        score -= 10

    if not alg:
        issues.append("Missing alg header.")
        recommendations.append("Publish an explicit signing algorithm in the protected header.")
        score -= 25
    elif alg.lower() == "none":
        issues.append("alg=none indicates an unsigned token.")
        recommendations.append("Reject unsigned JWTs and require a signed algorithm such as RS256 or ES256.")
        score -= 70
    elif alg.upper().startswith("HS"):
        recommendations.append("Ensure the shared HMAC secret is strong and rotated regularly.")
    elif alg.upper().startswith(("RS", "ES", "PS", "ED")):
        score += 0

    if not signature_present and len(token_parts) == 3:
        issues.append("Signature segment is empty.")
        recommendations.append("Reject tokens with an empty signature segment.")
        score -= 60

    if not token_type:
        issues.append("Missing typ header.")
        score -= 5
    if not kid:
        recommendations.append("Consider publishing kid when using rotating signing keys.")

    if exp_ts is None:
        issues.append("Missing exp claim.")
        recommendations.append("Add exp to limit token lifetime.")
        score -= 25
    else:
        if exp_ts <= now_ts:
            issues.append("Token is expired.")
            recommendations.append("Reject expired tokens and refresh them through the identity provider.")
            score -= 35
        elif exp_ts - now_ts > 86400:
            issues.append("Token has more than 24 hours remaining.")
            recommendations.append("Review whether the token lifetime is longer than necessary.")
            score -= 10

    if iat_ts is None:
        issues.append("Missing iat claim.")
        score -= 8
    if nbf_ts is not None and nbf_ts > now_ts:
        issues.append("Token is not yet valid (nbf in the future).")
        score -= 20
    if iat_ts is not None and exp_ts is not None and exp_ts > iat_ts and (exp_ts - iat_ts) > 86400:
        issues.append("Token lifetime exceeds 24 hours.")
        recommendations.append("Reduce token lifetime for user-facing access tokens.")
        score -= 12

    if "iss" not in payload:
        issues.append("Missing iss claim.")
        recommendations.append("Publish issuer information and validate it server-side.")
        score -= 8
    if "aud" not in payload:
        issues.append("Missing aud claim.")
        recommendations.append("Bind tokens to an intended audience and verify it server-side.")
        score -= 8
    if "jti" not in payload:
        recommendations.append("Consider adding jti if replay detection is required.")

    if "scope" in payload or "scp" in payload:
        recommendations.append("Review scope values for least-privilege access.")
    if "roles" in payload:
        recommendations.append("Review role claims for privilege creep.")

    score = max(0, min(score, 100))
    if score >= 85:
        grade = "A"
        posture = "Strong"
    elif score >= 70:
        grade = "B"
        posture = "Good"
    elif score >= 55:
        grade = "C"
        posture = "Moderate"
    elif score >= 35:
        grade = "D"
        posture = "Weak"
    else:
        grade = "F"
        posture = "High Risk"

    return {
        "score": score,
        "grade": grade,
        "posture": posture,
        "alg": alg or "No data",
        "typ": token_type or "No data",
        "kid": kid or "No data",
        "exp": exp_fmt,
        "nbf": nbf_fmt,
        "iat": iat_fmt,
        "ttl": describe_ttl(exp_ts, iat_ts, now_ts),
        "issues": issues,
        "recommendations": recommendations,
    }


def build_report(token_kind, token_parts, header, payload, evaluation):
    claim_lines = [f"- {key}: {value}" for key, value in classify_claims(payload)]
    header_lines = [f"- {key}: {value}" for key, value in sorted(header.items())]
    issue_lines = [f"- {item}" for item in evaluation["issues"]] or ["- No issues detected"]
    recommendation_lines = [f"- {item}" for item in evaluation["recommendations"]] or ["- No recommendations"]
    lines = [
        "JWT / AUTH TOKEN INSPECTOR",
        "",
        f"Token kind: {token_kind}",
        f"Segment count: {len(token_parts)}",
        f"Score: {evaluation['score']}/100",
        f"Grade: {evaluation['grade']}",
        f"Posture: {evaluation['posture']}",
        "",
        "[Header]",
        *(header_lines or ["- No decodable header"]),
        "",
        "[Payload Claims]",
        *(claim_lines or ["- No decodable payload"]),
        "",
        "[Issues]",
        *issue_lines,
        "",
        "[Recommendations]",
        *recommendation_lines,
    ]
    return "\n".join(lines)


def run():
    while True:
        print(f"{C}================================================================{RESET}")
        print(f"                {Y}JWT / AUTH TOKEN INSPECTOR{RESET}")
        print(f"{C}================================================================{RESET}")
        print(" [i] Paste a JWT or an Authorization header to inspect claims and posture.\n")

        raw_value = input(" JWT or Authorization header [0=back]: ").strip()
        if raw_value in ("", "0"):
            break

        try:
            token = normalize_token(raw_value)
            parts = token.split(".")
            if len(parts) not in (3, 5):
                raise ValueError("A JWT should contain 3 segments (JWS) or 5 segments (JWE).")

            header, _ = parse_json_segment(parts[0], "header")
            token_kind = "JWE / Encrypted token" if len(parts) == 5 else "JWS / Signed token"

            if len(parts) == 3:
                payload, _ = parse_json_segment(parts[1], "payload")
                signature_present = bool(parts[2].strip())
            else:
                payload = {
                    "_notice": "Encrypted token. Payload claims are not readable without decryption.",
                    "_encrypted_key_length": len(parts[1]),
                    "_iv_length": len(parts[2]),
                    "_ciphertext_length": len(parts[3]),
                    "_tag_length": len(parts[4]),
                }
                signature_present = True

            evaluation = evaluate_token(header, payload, signature_present, parts)

            print(f"\n {G}>>> TOKEN SUMMARY{RESET}")
            print(" ----------------------------------------------------------------")
            print(f" TOKEN TYPE:     {token_kind}")
            print(f" SEGMENTS:       {len(parts)}")
            print(f" SCORE:          {evaluation['score']}/100")
            print(f" GRADE:          {evaluation['grade']}")
            print(f" POSTURE:        {evaluation['posture']}")
            print(f" ALGORITHM:      {evaluation['alg']}")
            print(f" TOKEN HEADER:   {evaluation['typ']}")
            print(f" KEY ID:         {evaluation['kid']}")
            print(" ----------------------------------------------------------------")
            print(f" ISSUED AT:      {evaluation['iat']}")
            print(f" NOT BEFORE:     {evaluation['nbf']}")
            print(f" EXPIRES:        {evaluation['exp']}")
            print(f" LIFETIME:       {evaluation['ttl']}")

            print(f"\n {G}>>> HEADER FIELDS{RESET}")
            print(" ----------------------------------------------------------------")
            for key, value in sorted(header.items()):
                print(f" {key:<15} {value}")

            print(f"\n {G}>>> PAYLOAD CLAIMS{RESET}")
            print(" ----------------------------------------------------------------")
            for key, value in classify_claims(payload):
                print(f" {key:<15} {value}")

            print(f"\n {G}>>> FINDINGS{RESET}")
            print(" ----------------------------------------------------------------")
            if evaluation["issues"]:
                for issue in evaluation["issues"]:
                    print(f" - {issue}")
            else:
                print(" No obvious token hygiene issues were detected.")

            print(f"\n {G}>>> HARDENING NOTES{RESET}")
            print(" ----------------------------------------------------------------")
            if evaluation["recommendations"]:
                for note in evaluation["recommendations"]:
                    print(f" - {note}")
            else:
                print(" No additional hardening guidance was generated.")

            report_text = build_report(token_kind, parts, header, payload, evaluation)
            if input("\n [?] Save report? (y/n): ").strip().lower() == "y":
                core_report.save(report_text, "JWT_Token_Inspector")
        except ValueError as exc:
            print(f"\n [ERROR] {exc}")
        except Exception as exc:
            print(f"\n [ERROR] Token inspection failed: {exc}")

        input("\n Enter...")
