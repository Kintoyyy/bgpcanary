"""The event page's "Possible causes": fixed rules over the routes and the other events of an event's window.

The network: AS64500 with transits AS64496 and AS64497 and an exchange peer AS64498 (conftest's settings)."""
import json
from types import SimpleNamespace

from conftest import P1, P2

from bgpcanary import evidence

CFG = SimpleNamespace(asn=64500, expected_upstreams=[64496, 64497], peers=[64498], prefixes=[P1, P2])
PEER = lambda a: a in CFG.peers   # noqa: E731
NM = lambda a: f"AS{a}"   # noqa: E731


def rows(*paths):
    return [{"kind": "A", "path": p} for p, n in paths for _ in range(n)]


def mix(before, during, visible=40):
    return {"moments": [{"visible": visible, "mix": before}, {"visible": visible, "mix": during}]}


BEFORE = rows(("65020 64498 64500", 2))   # the peer, seen next to you before the event


def run(moment, mixes=None, related=(), ev=None, before=BEFORE):
    mixes = mixes or {P1: mix({64496: 20, 64497: 20}, {64496: 20, 64497: 20})}
    f = evidence._findings(CFG, mixes, P1, [before, moment], PEER)
    d = {"prefix": P1, "related": list(related), "already_open": []}
    return f, evidence.causes(CFG, ev or {"detail": "{}", "title": "an outage"}, d, f, NM)


def test_a_peer_behind_your_upstream_is_a_leak_and_explains_that_upstreams_drop():
    f, cs = run(rows(("65010 64496 64498 64500", 5), ("65011 64497 64500", 30)),
                mixes={P1: mix({64496: 20, 64497: 20}, {64496: 0, 64497: 30}), P2: mix({64496: 20}, {64496: 20})})
    assert set(f["leaks"]) == {64498}
    (leak,) = [c for c in cs if c["kind"] == "leak"]
    assert leak["title"] == "Peer leak by AS64498" and "5 RIS peers" in leak["text"] and "no-export" in leak["text"]
    assert leak["path"] == "65010 64496 64498 64500"
    assert not [c for c in cs if c["kind"] in ("link", "announce")]   # (AS64496 took the leaked route instead)


def test_a_peer_passing_on_what_your_upstream_sent_counts_only_when_it_reaches_far():
    few = rows(("65010 64498 64496 64500", 3), ("65011 64496 64500", 37))   # its own customers, likely
    assert not run(few)[0]["leaks"]
    many = rows(("65010 64498 64496 64500", 6), ("65011 64496 64500", 34))   # over a tenth of the peers
    assert set(run(many)[0]["leaks"]) == {64498}


def test_an_exchange_member_never_seen_next_to_you_isnt_called_a_leaker():
    # (a big transit at your exchange that doesn't peer with you carries you as a transit does)
    assert not run(rows(("65010 64496 64498 64500", 0), ("65010 64497 64498 64496 64500", 8),
                        ("65011 64496 64500", 32)), before=[])[0]["leaks"]


def test_an_upstream_reaching_you_through_others():
    _f, cs = run(rows(("65010 64497 65030 64496 64500", 8), ("65011 64496 64500", 30), ("65012 64497 64500", 2)))
    (c,) = [c for c in cs if c["kind"] == "indirect"]
    assert c["title"] == f"AS64497 isn't taking {P1} straight from you"
    assert "8 RIS peers' paths" in c["text"] and "through AS65030 → AS64496" in c["text"] and "(2 straight" in c["text"]
    # ...not when most of its paths still come straight from you
    _f, cs = run(rows(("65010 64497 65030 64496 64500", 8), ("65012 64497 64500", 20)))
    assert not [c for c in cs if c["kind"] == "indirect"]


def test_an_upstream_dropping_every_prefix_points_at_the_link():
    m = {P1: mix({64496: 30, 64497: 10}, {64496: 2, 64497: 38}), P2: mix({64496: 25, 64497: 15}, {64496: 0, 64497: 40})}
    _f, cs = run(rows(("65011 64497 64500", 40)), mixes=m)
    (c,) = [c for c in cs if c["kind"] in ("link", "announce")]
    assert c["kind"] == "link" and c["title"] == "Your link or session with AS64496"
    assert "all your prefixes at once" in c["text"] and f"{P1} (30 → 2 RIS peers)" in c["text"] and P2 in c["text"]


def test_an_upstream_dropping_one_prefix_points_at_what_you_announce():
    m = {P1: mix({64496: 30, 64497: 10}, {64496: 2, 64497: 38}), P2: mix({64496: 25, 64497: 15}, {64496: 24, 64497: 16})}
    _f, cs = run(rows(("65011 64497 64500", 40)), mixes=m)
    (c,) = [c for c in cs if c["kind"] in ("link", "announce")]
    assert c["kind"] == "announce" and f"stopped carrying {P1}" in c["text"] and f"still carries {P2}" in c["text"]


def test_a_registry_change_in_the_window_and_one_too_late_to_start_it():
    rel = [{"kind": "asset_change", "title": "AS64500 removed from AS-EXAMPLE", "after": 90},
           {"kind": "irr_change", "title": "route object changed", "after": -300},
           {"kind": "chain_change", "title": "New upstream chain", "after": 0}]
    _f, cs = run(rows(("65011 64496 64500", 40)), related=rel)
    texts = [c["text"] for c in cs if c["kind"] == "filter"]
    assert texts == ["AS64500 removed from AS-EXAMPLE (began 1 min after this event; too late to have started it, "
                     "but it can keep that path closed).", "route object changed (began 5 min before this event)."]


def test_ripes_data_rather_than_your_network():
    ev = {"title": "an outage", "detail": json.dumps({"confirm": {"verdict": "contradicted", "why": "Route Views still sees it"}})}
    _f, cs = run(rows(("65011 64496 64500", 40)), ev=ev)
    assert [(c["kind"], c["text"]) for c in cs] == [("data", "Route Views still sees it.")]


def test_nothing_matches_on_a_quiet_event():
    assert run(rows(("65011 64496 64500", 20), ("65012 64497 64500", 20)))[1] == []


def test_the_event_page_shows_them(admin_client):
    t = admin_client.get("/events/2").text
    assert 'id="causes"' in t and "Possible causes" in t
