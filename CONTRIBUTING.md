# Contributing to MCPGate

Thanks for helping harden the Model Context Protocol ecosystem!

## Development Requirements
- Go 1.24+ (`CGO_ENABLED=0` pure Go — no CGo dependencies)
- Run `go vet ./...` and `go test -race -count=1 ./...` before submitting a PR.
- Security rules, DLP signatures, and SSRF checks must include adversarial regression tests.
- Keep `install.sh` strictly LF (`\n`) and `install.ps1` zero-cmdlet `.NET`-native.

