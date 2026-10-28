#!/usr/bin/env bash
# ==============================================================================
# KMNS Validate Official Installer
# https://validate.kmns.io/install.sh
#
# Usage:
#   curl -fsSL __KMNS_VALIDATE_BASE_URL__/install.sh | bash
#   curl -fsSL __KMNS_VALIDATE_BASE_URL__/install.sh | bash -s -- --dir /usr/local/bin
# ==============================================================================

set -euo pipefail

NAME="kmns-validate"
ALIAS="validate"
REPO="${KMNS_VALIDATE_REPO:-kmns-io/kmns-validate}"
BASE_URL="${KMNS_VALIDATE_BASE_URL:-https://validate.kmns.io}"
DL_DOMAIN="${KMNS_VALIDATE_DL_DOMAIN:-validate.kmns.io}"
DL_BASE_URL="${KMNS_VALIDATE_DL_URL:-${DL_DOMAIN:+https://$DL_DOMAIN}}"
DL_BASE_URL="${DL_BASE_URL:-$BASE_URL}"

# Smart default directory detection (Standard CLI tool pattern: Homebrew, Docker, Rustup)
# If running as root, or /usr/local/bin is writable, default to /usr/local/bin (system-wide).
# Otherwise, default to ~/.local/bin (standard XDG user binary path) with fallback to ~/bin.
SUDO=""
if [ -n "${KMNS_VALIDATE_INSTALL_DIR:-}" ]; then
  INSTALL_DIR="$KMNS_VALIDATE_INSTALL_DIR"
elif [ "$(id -u)" -eq 0 ]; then
  INSTALL_DIR="/usr/local/bin"
elif [ -w "/usr/local/bin" ]; then
  INSTALL_DIR="/usr/local/bin"
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
  # Non-interactive passwordless sudo available (e.g. CI/CD or dev container)
  INSTALL_DIR="/usr/local/bin"
  SUDO="sudo"
else
  # Unprivileged non-root user without passwordless sudo: install user-locally
  INSTALL_DIR="${HOME}/.local/bin"
  [ -d "$INSTALL_DIR" ] || INSTALL_DIR="${HOME}/bin"
fi

# 1. Parse command line options
while [ $# -gt 0 ]; do
  case "$1" in
    --dir)
      INSTALL_DIR="$2"
      SUDO=""
      shift 2
      ;;
    --global)
      INSTALL_DIR="/usr/local/bin"
      [ "$(id -u)" -ne 0 ] && SUDO="sudo"
      shift
      ;;
    --local)
      INSTALL_DIR="${HOME}/.local/bin"
      SUDO=""
      shift
      ;;
    --base-url)
      BASE_URL="$2"
      DL_BASE_URL="${KMNS_VALIDATE_DL_URL:-$2}"
      shift 2
      ;;
    --help|-h)
      echo "KMNS Validate Installer"
      echo "Usage: install.sh [--global | --local | --dir <target_directory>] [--base-url <url>]"
      echo ""
      echo "Options:"
      echo "  --global                   Install system-wide to /usr/local/bin (uses sudo if needed)"
      echo "  --local                    Install user-locally to ~/.local/bin"
      echo "  --dir <path>               Install to custom directory"
      echo "  --base-url <url>           Base URL for release assets"
      echo ""
      echo "Environment variables:"
      echo "  KMNS_VALIDATE_BASE_URL     Base URL for releases (default: __KMNS_VALIDATE_BASE_URL__)"
      echo "  KMNS_VALIDATE_INSTALL_DIR  Target install directory"
      echo "  KMNS_VALIDATE_VERSION      Pin specific version (e.g. v0.1.0)"
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

# 2. Detect OS and Architecture
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

ALT_ARCH_SUFFIX=""
case "$OS" in
  linux)
    case "$ARCH" in
      x86_64|amd64)
        ARCH_SUFFIX="x86_64-unknown-linux-musl"
        ALT_ARCH_SUFFIX="x86_64-unknown-linux-gnu"
        ;;
      aarch64|arm64)
        ARCH_SUFFIX="aarch64-unknown-linux-musl"
        ALT_ARCH_SUFFIX="aarch64-unknown-linux-gnu"
        ;;
      *)
        echo "Error: Unsupported Linux architecture '$ARCH'." >&2
        exit 1
        ;;
    esac
    ;;
  darwin)
    case "$ARCH" in
      arm64|aarch64)
        ARCH_SUFFIX="aarch64-apple-darwin"
        ;;
      x86_64|amd64)
        ARCH_SUFFIX="x86_64-apple-darwin"
        ;;
      *)
        echo "Error: Unsupported macOS architecture '$ARCH'." >&2
        exit 1
        ;;
    esac
    ;;
  *)
    echo "Error: Operating system '$OS' is not currently supported." >&2
    exit 1
    ;;
esac

echo "🚀 Installing ${NAME} to ${INSTALL_DIR}..."

# 3. Create target directory
if [ -n "$SUDO" ]; then
  $SUDO mkdir -p "$INSTALL_DIR"
else
  mkdir -p "$INSTALL_DIR"
fi

# 4. Fetch latest release version
VERSION="${KMNS_VALIDATE_VERSION:-}"
if [ -z "$VERSION" ]; then
  # 4a. Check distribution site manifest directly (Single Source of Truth)
  VERSION="$(curl -fsSL "${DL_BASE_URL}/dl/latest-version.txt" 2>/dev/null | tr -d '\r\n' || true)"
fi
if [ -z "$VERSION" ] || [ "$VERSION" = "__KMNS_VALIDATE_VERSION__" ]; then
  # 4b. Fallback to embedded version or GitHub releases
  EMBEDDED_VER="__KMNS_VALIDATE_VERSION__"
  if [ "$EMBEDDED_VER" != "__KMNS_VALIDATE_VERSION__" ]; then
    VERSION="$EMBEDDED_VER"
  else
    VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' || echo "v0.1.1")"
  fi
fi

TARBALL="${NAME}-${VERSION}-${ARCH_SUFFIX}.tar.gz"
DOWNLOAD_URL="${DL_BASE_URL}/dl/${TARBALL}"

echo "⬇️ Downloading ${TARBALL} from ${DL_BASE_URL}..."

TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t 'kmns-vld')"
trap 'rm -rf "$TMP_DIR"' EXIT

DOWNLOAD_OK=false
if curl -fsSL "$DOWNLOAD_URL" -o "${TMP_DIR}/${TARBALL}" 2>/dev/null; then
  DOWNLOAD_OK=true
elif [ -n "$ALT_ARCH_SUFFIX" ]; then
  ALT_TARBALL="${NAME}-${VERSION}-${ALT_ARCH_SUFFIX}.tar.gz"
  ALT_DOWNLOAD_URL="${DL_BASE_URL}/dl/${ALT_TARBALL}"
  echo "ℹ️ Retrying with alternate target ${ALT_TARBALL}..."
  if curl -fsSL "$ALT_DOWNLOAD_URL" -o "${TMP_DIR}/${ALT_TARBALL}" 2>/dev/null; then
    TARBALL="$ALT_TARBALL"
    DOWNLOAD_OK=true
  fi
fi

# Fallback: if VERSION had an environment suffix (e.g. -stage), try base version (e.g. v0.1.1)
if [ "$DOWNLOAD_OK" = false ] && [[ "$VERSION" == *-* ]]; then
  BASE_VER="${VERSION%%-*}"
  BASE_TARBALL="${NAME}-${BASE_VER}-${ARCH_SUFFIX}.tar.gz"
  echo "ℹ️ Retrying with base version ${BASE_TARBALL}..."
  if curl -fsSL "${DL_BASE_URL}/dl/${BASE_TARBALL}" -o "${TMP_DIR}/${BASE_TARBALL}" 2>/dev/null; then
    TARBALL="$BASE_TARBALL"
    DOWNLOAD_OK=true
  elif [ -n "$ALT_ARCH_SUFFIX" ]; then
    BASE_ALT_TARBALL="${NAME}-${BASE_VER}-${ALT_ARCH_SUFFIX}.tar.gz"
    if curl -fsSL "${DL_BASE_URL}/dl/${BASE_ALT_TARBALL}" -o "${TMP_DIR}/${BASE_ALT_TARBALL}" 2>/dev/null; then
      TARBALL="$BASE_ALT_TARBALL"
      DOWNLOAD_OK=true
    fi
  fi
fi

# Fallback: if VERSION lacked an environment suffix, try with tier suffixes (e.g. v0.1.1-stage)
if [ "$DOWNLOAD_OK" = false ] && [[ "$VERSION" != *-* ]]; then
  for TIER in stage dev test; do
    TIER_VER="${VERSION}-${TIER}"
    TIER_TARBALL="${NAME}-${TIER_VER}-${ARCH_SUFFIX}.tar.gz"
    echo "ℹ️ Retrying with tier-tagged release ${TIER_TARBALL}..."
    if curl -fsSL "${DL_BASE_URL}/dl/${TIER_TARBALL}" -o "${TMP_DIR}/${TIER_TARBALL}" 2>/dev/null; then
      TARBALL="$TIER_TARBALL"
      DOWNLOAD_OK=true
      break
    elif [ -n "$ALT_ARCH_SUFFIX" ]; then
      ALT_TIER_TARBALL="${NAME}-${TIER_VER}-${ALT_ARCH_SUFFIX}.tar.gz"
      if curl -fsSL "${DL_BASE_URL}/dl/${ALT_TIER_TARBALL}" -o "${TMP_DIR}/${ALT_TIER_TARBALL}" 2>/dev/null; then
        TARBALL="$ALT_TIER_TARBALL"
        DOWNLOAD_OK=true
        break
      fi
    fi
  done
fi

if [ "$DOWNLOAD_OK" = true ]; then
  tar -xzf "${TMP_DIR}/${TARBALL}" -C "$TMP_DIR"
  if [ -n "$SUDO" ]; then
    $SUDO cp "${TMP_DIR}/${NAME}" "${INSTALL_DIR}/${NAME}"
  else
    cp "${TMP_DIR}/${NAME}" "${INSTALL_DIR}/${NAME}"
  fi
else
  # Fallback to GitHub Releases if CDN asset is not yet cached
  echo "ℹ️ Falling back to GitHub Releases mirror..."
  GH_URL="https://github.com/${REPO}/releases/download/${VERSION}/${TARBALL}"
  if ! curl -fsSL "$GH_URL" -o "${TMP_DIR}/${TARBALL}" 2>/dev/null; then
    if [ -n "$ALT_ARCH_SUFFIX" ]; then
      ALT_TARBALL="${NAME}-${VERSION}-${ALT_ARCH_SUFFIX}.tar.gz"
      GH_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ALT_TARBALL}"
      curl -fsSL "$GH_URL" -o "${TMP_DIR}/${ALT_TARBALL}"
      TARBALL="$ALT_TARBALL"
    fi
  fi
  tar -xzf "${TMP_DIR}/${TARBALL}" -C "$TMP_DIR"
  if [ -n "$SUDO" ]; then
    $SUDO cp "${TMP_DIR}/${NAME}" "${INSTALL_DIR}/${NAME}"
  else
    cp "${TMP_DIR}/${NAME}" "${INSTALL_DIR}/${NAME}"
  fi
fi

if [ -n "$SUDO" ]; then
  $SUDO chmod +x "${INSTALL_DIR}/${NAME}"
  $SUDO ln -sf "${INSTALL_DIR}/${NAME}" "${INSTALL_DIR}/${ALIAS}"
else
  chmod +x "${INSTALL_DIR}/${NAME}"
  ln -sf "${INSTALL_DIR}/${NAME}" "${INSTALL_DIR}/${ALIAS}"
fi

echo "✓ Successfully installed ${NAME} and ${ALIAS} into ${INSTALL_DIR}!"
echo ""
"${INSTALL_DIR}/${NAME}" --version || true
echo ""
echo "Next step: Run '${NAME} --help' or visit https://validate.kmns.io for contracts documentation."
