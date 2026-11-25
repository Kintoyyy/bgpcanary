"""db.state_at hops from peer to peer along the index instead of reading a prefix's whole history: it must give the
same rows the plain window-function query does, ties on the same second included."""
import random

from bgpcanary import db

PLAIN = ("SELECT collector, peer, peer_asn, kind, path, ts FROM ("
         " SELECT collector, peer, peer_asn, kind, path, ts,"
         "  ROW_NUMBER() OVER (PARTITION BY collector, peer ORDER BY ts DESC, id DESC) rn"
         " FROM updates WHERE prefix=? AND ts<=?) WHERE rn=1")


def test_state_at_matches_the_plain_query(tmp_path):
    conn = db.connect(str(tmp_path / "s.db"))
    conn.executescript(db.SCHEMA)
    rnd = random.Random(7)
    rows = []
    for prefix in ("192.0.2.0/24", "198.51.100.0/24"):
        for c in ("rrc00", "rrc01", "rrc10"):
            for i in range(12):
                peer = f"203.0.113.{i}"
                for _ in range(rnd.randint(1, 8)):
                    ts = float(rnd.randint(0, 40))   # (few distinct seconds: plenty of ties, broken by id)
                    kind = rnd.choice("AAW")
                    rows.append((ts, "ris-live", c, peer, 64500 + i, prefix, kind,
                                 f"{64500 + i} {rnd.randint(64496, 64499)} 64500" if kind == "A" else None))
    conn.executemany("INSERT INTO updates(ts,source,collector,peer,peer_asn,prefix,kind,path) VALUES(?,?,?,?,?,?,?,?)",
                     rows)
    for prefix in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"):
        for ts in (-1, 0, 7, 20, 39, 100):
            want = sorted(tuple(r) for r in conn.execute(PLAIN, (prefix, ts)))
            assert sorted(tuple(r) for r in db.state_at(conn, prefix, ts)) == want, (prefix, ts)
    assert db.state_at(conn, "192.0.2.0/24", 100)[0]["collector"] == "rrc00"   # (rows by name, as callers read them)
