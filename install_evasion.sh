#!/bin/bash
# Evasion module installer for Immersive Labs Kali machine
# Source: github.com/Karlivar21/metasploit-framework (evasion-enhancements branch)

set -e

REPO="https://raw.githubusercontent.com/Karlivar21/metasploit-framework/evasion-enhancements"

# Detect Metasploit install path
if [ -d "/usr/share/metasploit-framework" ]; then
  MSF="/usr/share/metasploit-framework"
elif [ -d "/opt/metasploit-framework" ]; then
  MSF="/opt/metasploit-framework"
else
  echo "[!] Could not find Metasploit installation. Exiting."
  exit 1
fi
echo "[*] Metasploit found at: $MSF"

# Create any missing directories
mkdir -p "$MSF/modules/encoders/x64"
mkdir -p "$MSF/modules/encoders/x86"
mkdir -p "$MSF/modules/auxiliary/generate"
mkdir -p "$MSF/modules/post/windows/manage"
mkdir -p "$MSF/lib/rex/proto/http"
mkdir -p "$MSF/lib/msf/core/exploit"
mkdir -p "$MSF/lib/msf/core/post/windows"
mkdir -p "$MSF/lib/msf/core/handler"

echo "[*] Downloading modules..."

wget -q "$REPO/modules/encoders/x64/poly_xor_feedback.rb" \
     -O "$MSF/modules/encoders/x64/poly_xor_feedback.rb" && echo "[+] x64 polymorphic XOR encoder"

wget -q "$REPO/modules/encoders/x86/rc4.rb" \
     -O "$MSF/modules/encoders/x86/rc4.rb" && echo "[+] x86 RC4 stream cipher encoder"

wget -q "$REPO/modules/auxiliary/generate/c2_profile.rb" \
     -O "$MSF/modules/auxiliary/generate/c2_profile.rb" && echo "[+] C2 profile generator module"

wget -q "$REPO/modules/post/windows/manage/edr_bypass.rb" \
     -O "$MSF/modules/post/windows/manage/edr_bypass.rb" && echo "[+] EDR bypass post module"

echo "[*] Downloading libraries..."

wget -q "$REPO/lib/rex/proto/http/c2_profile_generator.rb" \
     -O "$MSF/lib/rex/proto/http/c2_profile_generator.rb" && echo "[+] C2 profile generator library"

wget -q "$REPO/lib/msf/core/exploit/ps_obfuscator.rb" \
     -O "$MSF/lib/msf/core/exploit/ps_obfuscator.rb" && echo "[+] PowerShell obfuscator library"

wget -q "$REPO/lib/msf/core/exploit/amsi_bypass.rb" \
     -O "$MSF/lib/msf/core/exploit/amsi_bypass.rb" && echo "[+] AMSI bypass library"

wget -q "$REPO/lib/msf/core/post/windows/edr_evasion.rb" \
     -O "$MSF/lib/msf/core/post/windows/edr_evasion.rb" && echo "[+] EDR evasion library"

echo "[*] Patching reverse_http handler..."
wget -q "$REPO/lib/msf/core/handler/reverse_http.rb" \
     -O "$MSF/lib/msf/core/handler/reverse_http.rb" && echo "[+] reverse_http handler"

echo ""
echo "[*] Verifying downloads..."
FILES=(
  "$MSF/modules/encoders/x64/poly_xor_feedback.rb"
  "$MSF/modules/encoders/x86/rc4.rb"
  "$MSF/modules/auxiliary/generate/c2_profile.rb"
  "$MSF/modules/post/windows/manage/edr_bypass.rb"
  "$MSF/lib/rex/proto/http/c2_profile_generator.rb"
  "$MSF/lib/msf/core/exploit/ps_obfuscator.rb"
  "$MSF/lib/msf/core/exploit/amsi_bypass.rb"
  "$MSF/lib/msf/core/post/windows/edr_evasion.rb"
  "$MSF/lib/msf/core/handler/reverse_http.rb"
)

FAIL=0
for f in "${FILES[@]}"; do
  if [ -s "$f" ]; then
    echo "  [+] OK: $(basename $f)"
  else
    echo "  [!] MISSING: $f"
    FAIL=1
  fi
done

echo ""
if [ "$FAIL" -eq 0 ]; then
  echo "[+] All 9 files installed successfully."
  echo ""
  echo "Next steps:"
  echo "  1. msfconsole"
  echo "  2. msf6 > reload_all"
  echo "  3. msf6 > search poly_xor_feedback"
else
  echo "[!] Some files failed — check internet access and retry."
  exit 1
fi
