# Validation Checklist

This checklist is intended for live validation on an operator workstation after the local environment has been prepared.

## Core Runtime

- Launch the Linux build with `bash run_linux.sh`
- Launch the macOS build with `bash run_macos.sh`
- Confirm the console opens without missing-module errors
- Confirm the runtime panel shows the expected module count
- Confirm the active interface table renders cleanly in a full-screen terminal
- Confirm active interface counts are shown as `active / total`

## Web Security Workflow

Use one controlled domain and one public-known domain for comparison.

### HTTP and TLS

- `V` HTTP Surface Recon
- `HT` HTTP Tech Fingerprint
- `SH` Security Headers Audit
- `TI` TLS / Certificate Inspector
- `Y` TLS Deep Audit
- `CR` CORS Misconfiguration Review

Validate:

- TLS fallback behaves correctly when certificate trust is incomplete
- Redirect chains are readable
- Headers and stack hints are plausible
- Reports save correctly

### Web Exposure

- `HC` HTTP Capture
- `RS` Robots / Sitemap Recon
- `DE` Directory Exposure Recon
- `CS` Cookie Security Audit
- `CE` Client Exposure Recon

Validate:

- Title capture works
- Screenshot capture behaves correctly when a renderer is present or absent
- Standard path exposure findings are readable and not overly noisy
- Cookie parsing handles multiple `Set-Cookie` headers correctly
- public JavaScript sampling stays readable and useful

### Email and Ownership

- `EA` Email Security Audit
- `AS` ASN / BGP Recon

Validate:

- DNS-based mail records resolve correctly
- DKIM selector detection is reasonable for known targets
- ASN, owner, and provider hints match the visible infrastructure
- Report output is useful for follow-up analysis

### Identity and Metadata

- `OI` OAuth / OIDC Discovery Recon
- `JK` JWKS Keyset Inspector
- `JT` JWT / Auth Token Inspector

Validate:

- missing discovery endpoints fail clearly instead of noisily
- JWKS collection handles absent well-known metadata cleanly
- JWT inspection is readable even without a live production token

## Platform-Specific Checks

### Linux

- `S` LAN Recon
- `O` WiFi Telemetry
- `Q` DNS Benchmark
- `Z` Network Repair

Validate:

- missing system dependencies are reported clearly
- privileged actions fail gracefully when not running as root

### macOS

- `W` WiFi Audit
- `U` Connection Settings
- `I` Interface Census
- `LA` Local Host Audit

Validate:

- macOS-native tools return output cleanly
- WiFi workflow is understandable for the operator
- system panels open correctly when expected

## UI Review

- Confirm column alignment at normal full-screen width
- Confirm the header width matches the body layout
- Confirm long module labels do not create chaotic spacing
- Confirm the `WEB SECURITY` section remains readable after recent additions
- Confirm `TELEMETRY` still looks balanced after the latest module additions

## Final Review

- Save at least one report from each major category
- Confirm `Reports/` output stays organized
- Capture one screenshot of the final UI for future README use
- Remove local reports and Finder metadata before pushing repository changes
