#!/usr/bin/env bash
set -euo pipefail

CONFIG_DIR="$HOME/.config/cc-permission-handler"
CONFIG_FILE="$CONFIG_DIR/config.txtpb"
SETTINGS_FILE="$HOME/.claude/settings.json"
BINARY_NAME="cc-permission-handler"

bold="\033[1m"
dim="\033[2m"
green="\033[32m"
yellow="\033[33m"
reset="\033[0m"

info()  { printf "  ${bold}%s${reset}\n" "$*"; }
note()  { printf "  ${dim}%s${reset}\n" "$*"; }
ok()    { printf "  ${green}%s${reset}\n" "$*"; }
skip()  { printf "  ${yellow}%s${reset}\n" "$*"; }

confirm() {
    printf "  %s [Y/n] " "$1"
    read -r reply
    [[ -z "$reply" || "$reply" =~ ^[Yy] ]]
}

# --- Step 1: Install binary ---

info "Step 1: Install binary"
if command -v "$BINARY_NAME" &>/dev/null; then
    note "$(command -v "$BINARY_NAME") already on PATH"
    if confirm "Reinstall (go install)?"; then
        go install "./cmd/$BINARY_NAME"
        ok "Installed."
    else
        skip "Skipped."
    fi
else
    note "Will run: go install ./cmd/$BINARY_NAME"
    if confirm "Install?"; then
        go install "./cmd/$BINARY_NAME"
        ok "Installed to $(go env GOPATH)/bin/$BINARY_NAME"
    else
        skip "Skipped."
    fi
fi
echo

# --- Step 2: Create starter config ---

info "Step 2: Create config"
if [[ -f "$CONFIG_FILE" ]]; then
    skip "$CONFIG_FILE already exists. Skipped."
else
    note "Will create $CONFIG_FILE with default rules + prefer native tools."
    cat <<'PREVIEW'

    projects {
      path_patterns: "/**"
      allow_write_patterns: "/tmp/**"
      use_default_rules {}
      prefer_native_tools: true
    }

PREVIEW
    if confirm "Create config?"; then
        mkdir -p "$CONFIG_DIR"
        cat > "$CONFIG_FILE" <<'EOF'
# (Global) any project:
# - Can write to /tmp
# - Will use default approval rules
# - Will steer Claude toward native tools
projects {
  path_patterns: "/**"
  allow_write_patterns: "/tmp/**"
  use_default_rules {}
  prefer_native_tools: true
}
EOF
        ok "Created $CONFIG_FILE"
    else
        skip "Skipped."
    fi
fi
echo

# --- Step 3: Register hook in Claude Code settings ---

info "Step 3: Register hook in Claude Code settings"

# Resolve the binary path for the hook command.
if command -v "$BINARY_NAME" &>/dev/null; then
    hook_cmd="$BINARY_NAME"
else
    hook_cmd="$(go env GOPATH)/bin/$BINARY_NAME"
fi

# Check if jq is available (needed for JSON editing).
if ! command -v jq &>/dev/null; then
    skip "jq not found. Please manually add the hook to $SETTINGS_FILE:"
    note ""
    note '  "hooks": { "PermissionRequest": [{ "matcher": "Bash", "hooks": [{ "type": "command", "command": "'"$hook_cmd"'" }] }] }'
    echo
    exit 0
fi

# Check if hook is already registered.
hook_already_installed() {
    [[ -f "$SETTINGS_FILE" ]] && \
        jq -e '.hooks.PermissionRequest[]? | .hooks[]? | select(.command == "'"$hook_cmd"'" or .command == "cc-permission-handler")' "$SETTINGS_FILE" &>/dev/null
}

if hook_already_installed; then
    skip "Hook already registered in $SETTINGS_FILE. Skipped."
else
    note "Will add PermissionRequest hook to $SETTINGS_FILE"
    note "  command: $hook_cmd"

    if confirm "Register hook?"; then
        # Create settings file if it doesn't exist.
        if [[ ! -f "$SETTINGS_FILE" ]]; then
            mkdir -p "$(dirname "$SETTINGS_FILE")"
            echo '{}' > "$SETTINGS_FILE"
        fi

        # Build the hook entry.
        hook_entry='{"matcher":"Bash","hooks":[{"type":"command","command":"'"$hook_cmd"'"}]}'

        # Add hook to settings, creating the hooks.PermissionRequest array if needed.
        jq --argjson entry "$hook_entry" '
            .hooks //= {} |
            .hooks.PermissionRequest //= [] |
            .hooks.PermissionRequest += [$entry]
        ' "$SETTINGS_FILE" > "${SETTINGS_FILE}.tmp" && mv "${SETTINGS_FILE}.tmp" "$SETTINGS_FILE"

        ok "Registered hook in $SETTINGS_FILE"
    else
        skip "Skipped."
    fi
fi
echo

ok "Done!"
