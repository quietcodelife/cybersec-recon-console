# Contributing

CyberSec Recon Console is maintained as a practical operator toolkit. Contributions should improve reliability, clarity, platform fit, or evidence quality.

## Principles

- Keep the interface terminal-first and operator-friendly
- Prefer predictable workflows over clever abstractions
- Treat Linux and macOS as first-class but separate targets
- Fail clearly when dependencies are missing
- Keep reports useful for follow-up review

## Development Notes

- Python dependencies are installed through `setup_python_env.sh`
- Linux system packages are handled by `bootstrap_linux.sh`
- macOS system packages are handled by `bootstrap_macos.sh`
- New modules should be integrated into both platform variants when possible
- User-facing software text should stay in English

## Before Opening a Change

- Run syntax validation for touched Python files
- Check module importability after integration
- Verify menu placement and shortcut consistency
- Test on the target platform when the change depends on live system tools or network behavior

## Good Contribution Areas

- platform reliability fixes
- web security recon improvements
- cleaner reporting and artifact handling
- UI readability improvements for wide terminal layouts
- documentation that helps operators get productive faster
