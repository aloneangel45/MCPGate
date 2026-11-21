#!/bin/sh
# MCPGate POSIX Installer (Linux & macOS)
# Usage: curl -fsSL https://raw.githubusercontent.com/aloneangel45/MCPGate/main/install.sh | sh
set -eu

REPO="${MCPGATE_REPO:-aloneangel45/MCPGate}"
VERSION="${MCPGATE_VERSION:-latest}"
BASE_URL="${MCPGATE_BASE_URL:-https://github.com/${REPO}/releases}"
API_URL="${MCPGATE_API_URL:-https://api.github.com/repos/${REPO}/releases/latest}"
FALLBACK_VERSION="v1.0.0"

detect_os() {
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    case "$os" in
        linux*)  echo "linux" ;;
        darwin*) echo "darwin" ;;
        *)
            echo "[mcpgate] unsupported OS: $os" >&2
            exit 1
            ;;
    esac
}

detect_arch() {
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64)   echo "amd64" ;;
        aarch64|arm64)  echo "arm64" ;;
        *)
            echo "[mcpgate] unsupported architecture: $arch" >&2
            exit 1
            ;;
    esac
}

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$1" | awk '{print $NF}'
    else
        echo "[mcpgate] error: sha256sum, shasum, or openssl is required for checksum verification" >&2
        exit 1
    fi
}

fetch_file() {
    url="$1"
    dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$dest"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$dest" "$url"
    else
        echo "[mcpgate] error: curl or wget is required" >&2
        exit 1
    fi
}

resolve_latest_tag() {
    json=""
    if command -v curl >/dev/null 2>&1; then
        json="$(curl -fsSL -H "Accept: application/vnd.github+json" -H "User-Agent: mcpgate-installer" "$API_URL" 2>/dev/null || true)"
    elif command -v wget >/dev/null 2>&1; then
        json="$(wget -qO- --header="Accept: application/vnd.github+json" --header="User-Agent: mcpgate-installer" "$API_URL" 2>/dev/null || true)"
    fi
    tag="$(printf '%s\n' "$json" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
    if [ -n "$tag" ]; then
        echo "$tag"
    else
        echo "$FALLBACK_VERSION"
    fi
}

OS="${MCPGATE_OS_OVERRIDE:-$(detect_os)}"
ARCH="${MCPGATE_ARCH_OVERRIDE:-$(detect_arch)}"
ARCHIVE="mcpgate-${OS}-${ARCH}.tar.gz"

if [ "$VERSION" = "latest" ]; then
    if [ -n "${MCPGATE_BASE_URL:-}" ]; then
        DL_PREFIX="${BASE_URL}/latest/download"
    else
        TAG="$(resolve_latest_tag)"
        DL_PREFIX="${BASE_URL}/download/${TAG}"
    fi
else
    case "$VERSION" in
        v*) TAG="$VERSION" ;;
        *)  TAG="v$VERSION" ;;
    esac
    DL_PREFIX="${BASE_URL}/download/${TAG}"
fi

TMP_DIR="$(mktemp -d)"
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

echo "[mcpgate] Downloading ${ARCHIVE} from ${DL_PREFIX}..."
fetch_file "${DL_PREFIX}/${ARCHIVE}" "${TMP_DIR}/${ARCHIVE}"
fetch_file "${DL_PREFIX}/checksums.txt" "${TMP_DIR}/checksums.txt"

EXPECTED="$(awk -v f="$ARCHIVE" '$2 == f || $2 == "*"f {print tolower($1); exit}' "${TMP_DIR}/checksums.txt")"
if [ -z "$EXPECTED" ]; then
    echo "[mcpgate] error: ${ARCHIVE} entry not found in checksums.txt" >&2
    exit 1
fi

ACTUAL="$(sha256_file "${TMP_DIR}/${ARCHIVE}" | tr '[:upper:]' '[:lower:]')"
if [ "$EXPECTED" != "$ACTUAL" ]; then
    echo "[mcpgate] error: SHA-256 mismatch for ${ARCHIVE} (expected ${EXPECTED}, got ${ACTUAL})" >&2
    exit 1
fi

tar -xzf "${TMP_DIR}/${ARCHIVE}" -C "${TMP_DIR}"
if [ ! -f "${TMP_DIR}/mcpgate" ]; then
    echo "[mcpgate] error: extracted archive did not contain mcpgate binary" >&2
    exit 1
fi
chmod 0755 "${TMP_DIR}/mcpgate"

INSTALL_DIR="${MCPGATE_INSTALL_DIR:-}"
USE_SUDO=0
if [ -z "$INSTALL_DIR" ]; then
    if [ -w "/usr/local/bin" ]; then
        INSTALL_DIR="/usr/local/bin"
    elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
        INSTALL_DIR="/usr/local/bin"
        USE_SUDO=1
    else
        INSTALL_DIR="${HOME}/.local/bin"
    fi
fi

if [ "$USE_SUDO" -eq 1 ]; then
    sudo mkdir -p "$INSTALL_DIR"
    STAGE="${INSTALL_DIR}/.mcpgate.tmp.$$"
    sudo cp "${TMP_DIR}/mcpgate" "$STAGE"
    sudo chmod 0755 "$STAGE"
    sudo mv -f "$STAGE" "${INSTALL_DIR}/mcpgate"
else
    mkdir -p "$INSTALL_DIR"
    STAGE="${INSTALL_DIR}/.mcpgate.tmp.$$"
    cp "${TMP_DIR}/mcpgate" "$STAGE"
    chmod 0755 "$STAGE"
    mv -f "$STAGE" "${INSTALL_DIR}/mcpgate"
fi

echo "[mcpgate] Installed successfully to ${INSTALL_DIR}/mcpgate"
case ":${PATH:-}:" in
    *":${INSTALL_DIR}:"*) ;;
    *) echo "[mcpgate] Note: add ${INSTALL_DIR} to your PATH if not already configured." ;;
esac
