"""Reconciliacao de proveniencia das DLLs: regras de classificacao puras."""
from correlation.provenance_reconciliation import classify


def test_package_identical_requires_plaintext_region_and_full_match():
    assert classify(keyed=False, key_id=0xFFFF, disk_size=100, stored_size=100,
                    pct_equal=100.0, disk_exists=True, stored_exists=True) == "PACKAGE_IDENTICAL"


def test_encrypted_region_is_uncomparable_never_different():
    assert classify(keyed=True, key_id=0, disk_size=100, stored_size=100,
                    pct_equal=0.0, disk_exists=True, stored_exists=True) == "ENCRYPTED_UNCOMPARABLE"
    assert classify(keyed=True, key_id=0, disk_size=100, stored_size=100,
                    pct_equal=None, disk_exists=True, stored_exists=True) == "ENCRYPTED_UNCOMPARABLE"


def test_plaintext_region_with_divergence_is_different():
    assert classify(keyed=False, key_id=0xFFFF, disk_size=100, stored_size=100,
                    pct_equal=40.0, disk_exists=True, stored_exists=True) == "DIFFERENT"


def test_missing_pieces_are_unknown():
    assert classify(keyed=True, key_id=0, disk_size=None, stored_size=100,
                    pct_equal=None, disk_exists=False, stored_exists=True) == "UNKNOWN"
    assert classify(keyed=False, key_id=0xFFFF, disk_size=100, stored_size=None,
                    pct_equal=None, disk_exists=True, stored_exists=False) == "UNKNOWN"
