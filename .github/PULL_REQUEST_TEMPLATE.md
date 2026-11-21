## Summary
Describe the changes in this pull request and link any related issues.

## Checklist
- [ ] Pure Go (`CGO_ENABLED=0`) — no CGo dependencies introduced
- [ ] `go vet ./...` passes cleanly
- [ ] `go test -race -count=1 ./...` passes cleanly
- [ ] Security rules, DLP patterns, SSRF checks, or poisoning detectors include adversarial unit tests
- [ ] `install.sh` remains strictly LF (`\n`) and `install.ps1` uses pure `.NET` with zero PowerShell cmdlets
- [ ] Documentation / example policies updated where applicable
