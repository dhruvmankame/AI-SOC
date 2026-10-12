from app.mitre import family_from_title, technique_conflict


def test_family_from_title():
    assert family_from_title("Credential brute-force activity") == "brute_force"
    assert family_from_title("Volumetric HTTP DDoS flood") == "flood"
    assert family_from_title("Ares botnet C2 beaconing") == "beacon"


def test_technique_conflict_is_fail_closed_for_known_families():
    assert technique_conflict("T1110", ["R-NET-FLOOD"]) is not None
    assert technique_conflict("T1110", ["R-NET-BRUTEFORCE"]) is None


def test_annotation_only_does_not_create_false_conflict():
    assert technique_conflict("T1110", []) is None
