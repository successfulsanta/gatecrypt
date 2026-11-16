add_test([=[Smoke.ConfigDefaultsValid]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Smoke.ConfigDefaultsValid]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Smoke.ConfigDefaultsValid]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_smoke.cc:10]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Smoke.Ed25519RoundTrip]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Smoke.Ed25519RoundTrip]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Smoke.Ed25519RoundTrip]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_smoke.cc:17]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Crypto.Rfc8032Test1]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Crypto.Rfc8032Test1]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Crypto.Rfc8032Test1]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_crypto.cc:15]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Crypto.Rfc8032Test2]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Crypto.Rfc8032Test2]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Crypto.Rfc8032Test2]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_crypto.cc:44]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Crypto.Rfc8032Test3]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Crypto.Rfc8032Test3]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Crypto.Rfc8032Test3]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_crypto.cc:71]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Crypto.TamperedSigFails]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Crypto.TamperedSigFails]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Crypto.TamperedSigFails]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_crypto.cc:95]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Crypto.ConstantTimeEqual]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Crypto.ConstantTimeEqual]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Crypto.ConstantTimeEqual]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_crypto.cc:106]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Nonce.IssueConsumeOnce]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Nonce.IssueConsumeOnce]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Nonce.IssueConsumeOnce]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_crypto.cc:112]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Nonce.UnknownFails]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Nonce.UnknownFails]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Nonce.UnknownFails]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_crypto.cc:120]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Nonce.WrongSizeFails]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Nonce.WrongSizeFails]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Nonce.WrongSizeFails]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_crypto.cc:126]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Nonce.BoundedEviction]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Nonce.BoundedEviction]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Nonce.BoundedEviction]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_crypto.cc:132]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Protocol.FrameRoundTrip]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Protocol.FrameRoundTrip]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Protocol.FrameRoundTrip]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_protocol.cc:7]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Protocol.BadMagic]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Protocol.BadMagic]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Protocol.BadMagic]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_protocol.cc:17]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Protocol.Truncated]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Protocol.Truncated]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Protocol.Truncated]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_protocol.cc:25]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Protocol.OversizeRejected]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Protocol.OversizeRejected]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Protocol.OversizeRejected]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_protocol.cc:32]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Protocol.TrailingBytesRejected]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Protocol.TrailingBytesRejected]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Protocol.TrailingBytesRejected]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_protocol.cc:40]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Protocol.VersionMismatch]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Protocol.VersionMismatch]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Protocol.VersionMismatch]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_protocol.cc:48]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Protocol.VerifyRequestRoundTrip]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Protocol.VerifyRequestRoundTrip]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Protocol.VerifyRequestRoundTrip]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_protocol.cc:57]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Protocol.VerifyRequestBadNonce]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Protocol.VerifyRequestBadNonce]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Protocol.VerifyRequestBadNonce]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_protocol.cc:76]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Protocol.SignedMessageFormat]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Protocol.SignedMessageFormat]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Protocol.SignedMessageFormat]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_protocol.cc:87]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Ring.PushPopSingle]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Ring.PushPopSingle]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Ring.PushPopSingle]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_ring.cc:11]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Ring.FullReturnsFalse]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Ring.FullReturnsFalse]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Ring.FullReturnsFalse]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_ring.cc:20]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Ring.FifoOrder]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Ring.FifoOrder]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Ring.FifoOrder]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_ring.cc:26]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Ring.RoundsUpPowerOfTwo]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Ring.RoundsUpPowerOfTwo]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Ring.RoundsUpPowerOfTwo]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_ring.cc:36]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Ring.MpmcSoak]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Ring.MpmcSoak]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Ring.MpmcSoak]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_ring.cc:41]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Table.InsertFind]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Table.InsertFind]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Table.InsertFind]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_table.cc:11]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Table.ExactlyOnceUnderBurst]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Table.ExactlyOnceUnderBurst]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Table.ExactlyOnceUnderBurst]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_table.cc:21]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Table.RevokeTerminal]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Table.RevokeTerminal]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Table.RevokeTerminal]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_table.cc:37]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Table.DoubleScanBurstManyTickets]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Table.DoubleScanBurstManyTickets]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Table.DoubleScanBurstManyTickets]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_table.cc:46]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Wal.AppendReplay]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Wal.AppendReplay]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Wal.AppendReplay]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_wal.cc:17]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Wal.TornTailTruncated]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Wal.TornTailTruncated]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Wal.TornTailTruncated]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_wal.cc:37]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Wal.CrcMismatchTruncates]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Wal.CrcMismatchTruncates]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Wal.CrcMismatchTruncates]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_wal.cc:63]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Wal.Segments]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Wal.Segments]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Wal.Segments]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_wal.cc:91]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Merkle.EmptyRootZero]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Merkle.EmptyRootZero]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Merkle.EmptyRootZero]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_merkle.cc:12]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Merkle.ProveVerify]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Merkle.ProveVerify]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Merkle.ProveVerify]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_merkle.cc:17]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Merkle.RebuildDeterministic]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Merkle.RebuildDeterministic]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Merkle.RebuildDeterministic]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_merkle.cc:42]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Sync.MergeUnionNoConflict]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Sync.MergeUnionNoConflict]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Sync.MergeUnionNoConflict]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_merkle.cc:58]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Sync.ConflictLowestGateWins]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Sync.ConflictLowestGateWins]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Sync.ConflictLowestGateWins]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_merkle.cc:67]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Verify.HappyPath]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Verify.HappyPath]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Verify.HappyPath]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_verify.cc:55]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Verify.DoubleScanExactlyOnce]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Verify.DoubleScanExactlyOnce]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Verify.DoubleScanExactlyOnce]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_verify.cc:64]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Verify.ReplayRejected]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Verify.ReplayRejected]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Verify.ReplayRejected]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_verify.cc:74]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Verify.BadSigRejected]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Verify.BadSigRejected]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Verify.BadSigRejected]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_verify.cc:85]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Verify.WrongDeviceKeyRejected]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Verify.WrongDeviceKeyRejected]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Verify.WrongDeviceKeyRejected]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_verify.cc:94]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Verify.UnknownTicket]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Verify.UnknownTicket]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Verify.UnknownTicket]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_verify.cc:105]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Verify.RevokedRejected]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Verify.RevokedRejected]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Verify.RevokedRejected]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_verify.cc:111]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[Verify.OfflineLatencyUnder3ms]=]  /home/hari/gatecrypt/build-tsan/gatecrypt_tests [==[--gtest_filter=Verify.OfflineLatencyUnder3ms]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Verify.OfflineLatencyUnder3ms]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[/home/hari/gatecrypt/tests/test_verify.cc:119]==]
    WORKING_DIRECTORY [==[/home/hari/gatecrypt/build-tsan]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
set(gatecrypt_tests_TESTS [==[Smoke.ConfigDefaultsValid]==] [==[Smoke.Ed25519RoundTrip]==] [==[Crypto.Rfc8032Test1]==] [==[Crypto.Rfc8032Test2]==] [==[Crypto.Rfc8032Test3]==] [==[Crypto.TamperedSigFails]==] [==[Crypto.ConstantTimeEqual]==] [==[Nonce.IssueConsumeOnce]==] [==[Nonce.UnknownFails]==] [==[Nonce.WrongSizeFails]==] [==[Nonce.BoundedEviction]==] [==[Protocol.FrameRoundTrip]==] [==[Protocol.BadMagic]==] [==[Protocol.Truncated]==] [==[Protocol.OversizeRejected]==] [==[Protocol.TrailingBytesRejected]==] [==[Protocol.VersionMismatch]==] [==[Protocol.VerifyRequestRoundTrip]==] [==[Protocol.VerifyRequestBadNonce]==] [==[Protocol.SignedMessageFormat]==] [==[Ring.PushPopSingle]==] [==[Ring.FullReturnsFalse]==] [==[Ring.FifoOrder]==] [==[Ring.RoundsUpPowerOfTwo]==] [==[Ring.MpmcSoak]==] [==[Table.InsertFind]==] [==[Table.ExactlyOnceUnderBurst]==] [==[Table.RevokeTerminal]==] [==[Table.DoubleScanBurstManyTickets]==] [==[Wal.AppendReplay]==] [==[Wal.TornTailTruncated]==] [==[Wal.CrcMismatchTruncates]==] [==[Wal.Segments]==] [==[Merkle.EmptyRootZero]==] [==[Merkle.ProveVerify]==] [==[Merkle.RebuildDeterministic]==] [==[Sync.MergeUnionNoConflict]==] [==[Sync.ConflictLowestGateWins]==] [==[Verify.HappyPath]==] [==[Verify.DoubleScanExactlyOnce]==] [==[Verify.ReplayRejected]==] [==[Verify.BadSigRejected]==] [==[Verify.WrongDeviceKeyRejected]==] [==[Verify.UnknownTicket]==] [==[Verify.RevokedRejected]==] [==[Verify.OfflineLatencyUnder3ms]==])
