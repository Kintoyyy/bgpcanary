"""Events › Export CSV: every event the page's filters match, as a spreadsheet; and the replay's JSON goes out
compressed."""
import csv
import io

from conftest import EVENTS


def rows(r):
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert r.headers["content-disposition"].startswith('attachment; filename="bgpcanary-events-')
    return list(csv.DictReader(io.StringIO(r.text)))


def test_export_follows_the_pages_filters(admin_client):
    got = rows(admin_client.get("/events/export.csv"))   # like the page: no info events unless asked for
    assert [int(r["id"]) for r in got] == [1, 3, 5]
    assert [int(r["id"]) for r in rows(admin_client.get("/events/export.csv?info=1"))] == [1, 2, 3, 4, 5]
    assert [int(r["id"]) for r in rows(admin_client.get("/events/export.csv?state=open"))] == [1]
    out = got[0]
    assert out["open"] == "1" and out["end_utc"] == "" and out["severity"] == "critical"
    assert out["title"] == EVENTS[0][6] and out["url"] == "https://canary.example.com/events/1"
    assert out["lowest_visible"] == "4" and out["baseline"] == "320"


def test_export_needs_a_sign_in(client):
    r = client.get("/events/export.csv", follow_redirects=False)
    assert r.status_code in (303, 401)


def test_a_title_cant_run_as_a_formula(web, admin_client):
    conn = web.svc.aconn
    conn.execute("INSERT INTO events(id,kind,severity,prefix,start_ts,end_ts,title,detail) "
                 "VALUES(99,'outage','critical',NULL,1,2,'=HYPERLINK(\"x\")','{}')")
    conn.commit()
    try:
        got = {r["id"]: r for r in rows(admin_client.get("/events/export.csv"))}
        assert got["99"]["title"] == "'=HYPERLINK(\"x\")"
    finally:
        conn.execute("DELETE FROM events WHERE id=99")
        conn.commit()


def test_large_answers_are_gzipped(admin_client):
    r = admin_client.get("/events", headers={"Accept-Encoding": "gzip"})
    assert r.headers.get("content-encoding") == "gzip"
