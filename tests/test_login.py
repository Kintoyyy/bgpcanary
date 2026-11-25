from conftest import PASSWORD, new_client


def session_cookie(web, remember):
    c = new_client(web)
    data = {"username": "bob", "password": PASSWORD, "next": "/"}
    if remember:
        data["remember"] = "1"
    r = c.post("/login", data=data, follow_redirects=False)
    assert r.status_code == 303
    sc = [h for h in r.headers.get_list("set-cookie") if h.startswith("bgpcanary=")]
    assert len(sc) == 1
    assert c.get("/", follow_redirects=False).status_code == 200   # signed in either way
    return sc[0]


def test_keep_me_signed_in_sets_a_lasting_cookie(web):
    assert "Max-Age=2592000" in session_cookie(web, True)


def test_without_it_the_cookie_ends_with_the_browser(web):
    sc = session_cookie(web, False)
    assert "Max-Age" not in sc and "httponly" in sc
