#!/usr/bin/env bash
# Microbenchmarks: ring buffer, CAS table, WAL fsync policies.
set -e
BUILD="${1:-build}"
echo "=== gatecrypt microbenchmarks (see gatecrypt_tests + loadgen --offline) ==="
echo "--- ring/table/wal covered by unit tests with timing; running offline verify bench ---"
"./$BUILD/gatecrypt-loadgen" --offline
