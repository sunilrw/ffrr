#!/usr/bin/env bash
set -euo pipefail

BIN="${1:-./target/debug/ffrr}"
echo "================================================================================"
echo " Running FFRR Automated Smoke Test Suite using binary: $BIN"
echo "================================================================================"

PASS=0
FAIL=0

assert_contains() {
  local label="$1"
  local haystack="$2"
  local needle="$3"
  if echo "$haystack" | grep -Fq "$needle"; then
    echo "  [PASS] $label"
    PASS=$((PASS + 1))
  else
    echo "  [FAIL] $label (expected to find '$needle')"
    FAIL=$((FAIL + 1))
  fi
}

# 1. Generate fresh sample workspace
rm -rf samples .ffrr_backups
"$BIN" samples -d samples

# 2. Multi-source & Multi-archive search (.zip, .rar, .tar.gz, .gz, .zst, UTF-16LE, Disk)
OUT_SEARCH=$("$BIN" -f "http://" -d samples -o json -q)
assert_contains "Searches inside .zip archive" "$OUT_SEARCH" "bundle.zip::zip_inner/gateway.json"
assert_contains "Searches inside .rar archive" "$OUT_SEARCH" "legacy_pack.rar::rar_inner/legacy_client.cs"
assert_contains "Searches inside .tar.gz archive" "$OUT_SEARCH" "release.tar.gz::tar_inner/manifest.yaml"
assert_contains "Searches inside .gz file" "$OUT_SEARCH" "app.log.gz::app.log"
assert_contains "Searches inside .zst file" "$OUT_SEARCH" "audit.log.zst::audit.log"
assert_contains "Detects & decodes UTF-16LE file" "$OUT_SEARCH" "UTF-16LE"

# 3. Classic fnr.exe drop-in command-line compatibility
OUT_FNR=$("$BIN" --cl --dir "samples" --fileMask "*.json,*.cs" --includeSubDirectories --useRegEx --find "http://([a-z0-9.-]+)" --replace "https://\$1" --dry-run -o json)
assert_contains "Classic fnr.exe syntax works" "$OUT_FNR" "https://api.internal-payments.example.com"
assert_contains "Classic fnr.exe matches .cs inside .rar" "$OUT_FNR" "https://rar-api.example.com"

# 4. Smart Case-Preserving Replace (-P) & Lexical Scope Filtering (--scope code)
OUT_SCOPE=$("$BIN" -f "legacy_user_id" -r "account_id" -P --scope code -d samples/src_code/auth_service.rs --dry-run -o json -q)
assert_contains "Preserves snake_case (legacy_user_id -> account_id)" "$OUT_SCOPE" "pub account_id: String"
assert_contains "Preserves PascalCase (LegacyUserId -> AccountId)" "$OUT_SCOPE" "pub AccountId: u64"
assert_contains "Preserves SCREAMING_SNAKE_CASE (LEGACY_USER_ID -> ACCOUNT_ID)" "$OUT_SCOPE" "pub ACCOUNT_ID:"

# 5. Dynamic Replacement Macros ({{REDACT}}, {{SHA256}}, {{UPPER}})
OUT_MACRO=$("$BIN" -f "sk-[a-zA-Z0-9]+" -r "{{REDACT}}" -E -d samples/config/appsettings.json --dry-run -o json -q)
assert_contains "Dynamic {{REDACT}} macro masks secret" "$OUT_MACRO" "sk-****************"

# 6. File Grouping across folders and archives
OUT_GRP=$("$BIN" group -d samples --by language --json)
assert_contains "File Grouping detects Rust" "$OUT_GRP" "Rust"
assert_contains "File Grouping detects Configuration" "$OUT_GRP" "Configuration"

OUT_ENC=$("$BIN" group -d samples --by encoding --json)
assert_contains "File Grouping detects UTF-16LE encoding" "$OUT_ENC" "UTF-16LE"

# 7. Exact, CRLF-Normalized & Fuzzy Near-Duplicate Detection (including inside .zip)
OUT_DUP=$("$BIN" dupes -d samples --normalized --near --json)
assert_contains "Detects duplicate across disk and .zip" "$OUT_DUP" "bundle.zip::zip_inner/node_config_in_zip.conf"
assert_contains "Detects CRLF normalized duplicate" "$OUT_DUP" "Normalized (Whitespace/CRLF)"
assert_contains "Detects fuzzy near-duplicate code clones" "$OUT_DUP" "Near-Duplicate"

# 8. Context & Intent Analyzer
OUT_INTENT=$("$BIN" intent -d samples --json)
assert_contains "Intent analyzer detects hardcoded secrets" "$OUT_INTENT" "secrets"
assert_contains "Intent analyzer detects PII emails" "$OUT_INTENT" "pii"
assert_contains "Intent analyzer detects insecure-http" "$OUT_INTENT" "insecure-http"
assert_contains "Intent analyzer detects TODOs in comments" "$OUT_INTENT" "todos"

# 9. Live Replace + Transactional Backup + Undo Rollback
"$BIN" -f "http://orders.internal.example.com/api" -r "https://orders.internal.example.com/api" -d samples/config/deployment.yaml -q
MOD_CONTENT=$(cat samples/config/deployment.yaml)
assert_contains "Live replacement written to disk" "$MOD_CONTENT" "https://orders.internal.example.com/api"

"$BIN" undo
RESTORED_CONTENT=$(cat samples/config/deployment.yaml)
assert_contains "Transactional undo restored original file" "$RESTORED_CONTENT" "http://orders.internal.example.com/api"

# 10. Command Line Generator (`gen-cmd`) & MCP Server (`mcp`)
OUT_GEN=$("$BIN" gen-cmd -f "old" -r "new" -d src -m "*.rs" -P)
assert_contains "GenCmd outputs fnr.exe command" "$OUT_GEN" "fnr.exe --cl"
assert_contains "GenCmd outputs ffrr command" "$OUT_GEN" "ffrr -f"

OUT_MCP=$(printf '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}\n' | "$BIN" mcp)
assert_contains "MCP server lists ffrr_find_replace tool" "$OUT_MCP" "ffrr_find_replace"
assert_contains "MCP server lists ffrr_find_duplicates tool" "$OUT_MCP" "ffrr_find_duplicates"

echo "================================================================================"
echo " Smoke Test Summary: $PASS passed, $FAIL failed"
echo "================================================================================"
if [ "$FAIL" -ne 0 ]; then
  exit 1
fi
