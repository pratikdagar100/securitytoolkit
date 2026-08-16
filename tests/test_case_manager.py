def test_create_case_assigns_sequential_id(case_manager):
    c1 = case_manager.create_case("First")
    c2 = case_manager.create_case("Second")
    assert c1.case_id.startswith("CASE-")
    assert c1.case_id != c2.case_id
    assert case_manager.get_case(c1.case_id)["name"] == "First"


def test_add_target_classifies_and_scopes(case_manager):
    case = case_manager.create_case("Scope test")
    case_manager.add_target(case.case_id, "example.com", authorized=True)
    case_manager.add_target(case.case_id, "10.0.0.0/24", authorized=False)
    scopes = case_manager.authorized_scopes(case.case_id)
    assert "example.com" in scopes
    assert "10.0.0.0/24" not in scopes


def test_status_update(case_manager):
    case = case_manager.create_case("Status")
    assert case_manager.set_status(case.case_id, "closed")
    assert case_manager.get_case(case.case_id)["status"] == "CLOSED"
