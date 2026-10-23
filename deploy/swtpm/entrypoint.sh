#!/bin/sh
# Provisions a fresh swtpm (RSA-2048 EK + EK certificate from a throwaway
# local CA) and serves it over TCP: 2321 = TPM commands, 2322 = control.
# The local CA certificates are copied to /out so tests can treat them as a
# development EK root.
set -eu

mkdir -p /tpm /out
rm -f /out/ready

swtpm_setup --tpm2 --tpmstate /tpm --create-ek-cert --overwrite \
  --pcr-banks sha256 >/dev/null

cp /var/lib/swtpm-localca/swtpm-localca-rootca-cert.pem /out/ek-root.pem
cp /var/lib/swtpm-localca/issuercert.pem /out/ek-intermediate.pem
chmod 0644 /out/*.pem
touch /out/ready

exec swtpm socket --tpm2 --tpmstate dir=/tpm \
  --server type=tcp,port=2321,bindaddr=0.0.0.0 \
  --ctrl type=tcp,port=2322,bindaddr=0.0.0.0 \
  --flags not-need-init,startup-clear
