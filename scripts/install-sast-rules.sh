#!/bin/sh
# Install the reviewed GitLab rule snapshot used by the image and self-scan.
set -eu
destination=${1:?usage: install-sast-rules.sh DESTINATION}
commit=83144bd2ec7d3200cda96347fa923f81c8ad8413
digest=c18525ac1ec560c31ecd09c3b7e4cf47467ed7825c6234f64ac3ec187b536ad9
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
archive="$temporary/sast-rules-$commit.tar.gz"
curl -fsSL --max-time 120 "https://gitlab.com/gitlab-org/security-products/sast-rules/-/archive/$commit/sast-rules-$commit.tar.gz" -o "$archive"
printf '%s  %s\n' "$digest" "$archive" | sha256sum -c -
tar -xzf "$archive" -C "$temporary"
source="$temporary/sast-rules-$commit"
# OpenGrep parses this pattern as a lambda expression without a statement terminator.
rule="$source/csharp/crypto/rule-CertificateValidationDisabled.yml"
sed 's/"(...) => true;"/"(...) => true"/' "$rule" > "$temporary/csharp-rule.yml"
mv "$temporary/csharp-rule.yml" "$rule"
mkdir -p "$destination"
cp "$source/LICENSE" "$destination/"
for language in c csharp go java javascript python scala; do
    cp -R "$source/$language" "$destination/"
done
