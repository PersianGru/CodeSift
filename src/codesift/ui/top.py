"""`sift top`: a live terminal view of the newest scan or fix, drawn like an action-game HUD.

Scanners are the party, findings are the monsters they turn up, the LLM gateway is the oracle tower
and the sandbox VM is the dungeon. Everything shown comes from the run's own events.jsonl - nothing is
simulated. Standard library only; it reads local files and never touches the network."""

from __future__ import annotations

import os
import shutil
import sys
import time
from collections import deque
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from itertools import accumulate
from pathlib import Path
from typing import Any, TextIO

from codesift.ui.state import Runs, StateError
from codesift.validate.events import read_events

# ------------------------------------------------------------------ the cast

CLASSES: dict[str, str] = {
    "gitleaks": "Rogue",
    "opengrep": "Mage",
    "trivy": "Ranger",
    "bandit": "Knight",
    "ruff": "Barbarian",
    "osv-scanner": "Scout",
    "zizmor": "Cleric",
    "pip-audit": "Alchemist",
    "composer-audit": "Bard",
    "govulncheck": "Monk",
}
SEVERITIES = ("critical", "high", "medium", "low", "info")
MONSTERS = {
    "critical": "Skeleton Lord",
    "high": "Skeleton Warrior",
    "medium": "Skeleton Rogue",
    "low": "Skeleton Minion",
    "info": "Bones",
}
OUTCOMES = {
    "fixed_verified": "slain",
    "fixed_unproven": "wounded",
    "inconclusive": "lost in fog",
}
STAGE_ACTIONS = {
    "triage": "scouted",
    "fix": "in battle",
    "policy": "judged",
    "sandbox": "in the dungeon",
    "verify": "proving",
    "judge": "judged",
}

# ------------------------------------------------------------------ colours

RESET = "\x1b[0m"
STYLES: dict[str, str] = {
    "dim": "\x1b[38;2;110;118;135m",
    "text": "\x1b[38;2;214;220;232m",
    "title": "\x1b[1;38;2;255;196;87m",
    "gold": "\x1b[38;2;255;196;87m",
    "border": "\x1b[38;2;70;82;110m",
    "hot": "\x1b[1;38;2;255;214;120m",
    "ok": "\x1b[38;2;94;214;140m",
    "bad": "\x1b[38;2;255;92;92m",
    "llm": "\x1b[38;2;170;140;255m",
    "vm": "\x1b[38;2;90;190;255m",
    "scan": "\x1b[38;2;120;230;200m",
    "critical": "\x1b[1;38;2;255;70;70m",
    "high": "\x1b[38;2;255;130;110m",
    "medium": "\x1b[38;2;245;165;36m",
    "low": "\x1b[38;2;122;162;255m",
    "info": "\x1b[38;2;154;160;170m",
    "invert": "\x1b[1;38;2;20;22;30;48;2;255;196;87m",
}
_ASCII = str.maketrans(
    {
        "─": "-", "│": "|", "┌": "+", "┐": "+", "└": "+", "┘": "+", "═": "=", "║": "|",
        "╔": "+", "╗": "+", "╚": "+", "╝": "+", "█": "#", "▓": "#", "▒": "+", "░": ".",
        "▁": "_", "▂": "_", "▃": "-", "▄": "-", "▅": "=", "▆": "=", "▇": "#", "●": "*",
        "○": "o", "◆": "*", "►": ">", "◄": "<", "·": ".", "✦": "*", "»": ">", "«": "<",
        "▲": "^", "▼": "v", "■": "#", "←": "<", "→": ">",
    }
)  # fmt: skip
SPARK = "▁▂▃▄▅▆▇█"
PULSE = "░▒▓█▓▒"

Seg = tuple[str, str]  # (text, style name or "")


@dataclass
class Hero:
    name: str
    status: str = "ready"  # ready, running, ok, skipped, error
    found: int = 0
    duration: float = 0.0
    reason: str = ""
    changed: float = 0.0


@dataclass
class Monster:
    id: str
    severity: str = "info"
    path: str = ""
    line: int = 0
    tool: str = ""
    stage: str = ""
    outcome: str = ""
    seen: float = 0.0


@dataclass
class Board:
    """Everything `sift top` shows, built only from a run's events."""

    run_id: str = ""
    kind: str = ""
    mode: str = ""
    project: str = ""
    started: str = ""
    ended: str = ""
    exit_code: int | None = None
    heroes: dict[str, Hero] = field(default_factory=dict)
    monsters: dict[str, Monster] = field(default_factory=dict)
    llm_host: str = ""
    llm_model: str = ""
    llm_fallback: str = ""
    llm_calls: int = 0
    llm_failed: int = 0
    llm_inflight: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    latencies: deque[float] = field(default_factory=lambda: deque(maxlen=60))
    vm_host: str = ""
    vm_runtime: str = ""
    vm_commands: int = 0
    vm_jobs: int = 0
    vm_failed: int = 0
    vm_inflight: int = 0
    vm_last: str = ""
    vm_durations: deque[float] = field(default_factory=lambda: deque(maxlen=60))
    budget_used: int = 0
    budget_limit: int = 0
    log: deque[tuple[str, list[Seg]]] = field(default_factory=lambda: deque(maxlen=200))
    flash: float = 0.0

    def apply(self, ev: dict[str, Any], now: float) -> None:
        kind = str(ev.get("type", ""))
        d = _dict(ev.get("data"))
        fid = ev.get("finding") if isinstance(ev.get("finding"), str) else None
        ts = str(ev.get("ts", ""))
        line = self._apply(kind, d, fid, ts, now)
        if line:
            self.log.appendleft((ts[11:19], line))

    def _apply(self, kind: str, d: dict[str, Any], fid: str | None, ts: str, now: float) -> list[Seg]:
        if kind == "run.start":
            self.started = ts
            self.kind = str(d.get("kind") or "fix")
            self.mode = str(d.get("mode", ""))
            self.project = str(d.get("project", ""))
            topo = _dict(d.get("topology"))
            scanners = topo.get("scanners")
            for name in scanners if isinstance(scanners, list) else []:
                self.hero(str(name))
            llm = _dict(topo.get("llm"))
            self.llm_host, self.llm_model = str(llm.get("host", "")), str(llm.get("model", ""))
            self.llm_fallback = str(llm.get("fallback", ""))
            vm = _dict(topo.get("vm"))
            self.vm_host, self.vm_runtime = str(vm.get("host", "")), str(vm.get("runtime", ""))
            return [("RAID BEGINS ", "title"), (f"{_what(self.kind, self.mode)} · {self.project}", "text")]
        if kind == "run.end":
            self.ended = ts
            code = d.get("exit_code")
            self.exit_code = code if isinstance(code, int) else None
            self.flash = now
            won = self.exit_code == 0
            return [("RAID OVER ", "title"), (f"exit {code}", "ok" if won else "bad")]
        if kind == "scanner.start":
            h = self.hero(str(d.get("name", "?")))
            h.status, h.changed = "running", now
            return [(f"{_class(h.name)} {h.name}", "scan"), (" sets out", "text")]
        if kind == "scanner.result":
            h = self.hero(str(d.get("name", "?")))
            h.status = str(d.get("status", "ok"))
            h.found = _int(d.get("findings"))
            h.duration = _float(d.get("duration_s"))
            h.reason = str(d.get("reason", ""))
            h.changed = now
            who = (f"{_class(h.name)} {h.name}", "scan")
            if h.status == "skipped":
                return [who, (" stays at camp · " + h.reason, "dim")]
            if h.status == "error":
                return [who, (" falls · " + h.reason, "bad")]
            return [who, (f" returns · {h.found} found · {h.duration:.1f}s", "text")]
        if kind == "finding.detected" and fid:
            m = self.monster(fid)
            m.severity = str(d.get("severity", "info"))
            m.path, m.line = str(d.get("path", "")), _int(d.get("line"))
            m.tool = str(d.get("tool", "")) or m.tool
            m.seen = now
            where = m.path + (f":{m.line}" if m.line else "")
            return [
                (f"{fid} ", "hot"),
                (MONSTERS.get(m.severity, "Bones"), m.severity),
                (f" ({m.severity}) appears · {where}", "text"),
            ]
        if kind == "llm.request":
            self.llm_inflight += 1
            what = (str(d.get("purpose", "")) + (f" {fid}" if fid else "")).strip() or "a question"
            est = max(1, _int(d.get("prompt_chars")) // 4)
            return [
                ("raven » ", "llm"),
                (_short(str(d.get("model", ""))), "llm"),
                (f" · {what} · ~{est} tok", "text"),
            ]
        if kind == "llm.response":
            self.llm_inflight = max(0, self.llm_inflight - 1)
            self.llm_calls += 1
            self.tokens_in += _int(d.get("tokens_in"))
            self.tokens_out += _int(d.get("tokens_out"))
            lat = _float(d.get("latency_s"))
            self.latencies.append(lat)
            model = _short(str(d.get("model", "")))
            if not d.get("ok"):
                self.llm_failed += 1
                return [("oracle ", "llm"), (model, "llm"), (f" is silent · {d.get('error', '?')}", "bad")]
            return [
                ("oracle ", "llm"),
                (model, "llm"),
                (f" answers · {_int(d.get('tokens_out'))} tok · {lat:.1f}s", "text"),
            ]
        if kind == "vm.command":
            self.vm_inflight += 1
            self.vm_commands += 1
            op = str(d.get("op", ""))
            if op == "job":
                self.vm_jobs += 1
            self.vm_last = op + (f" sift-{d.get('job')}" if d.get("job") else "")
            return [("dungeon ", "vm"), (self.vm_last, "text")]
        if kind == "vm.result":
            self.vm_inflight = max(0, self.vm_inflight - 1)
            rc = _int(d.get("rc"))
            dur = _float(d.get("duration_s"))
            self.vm_durations.append(dur)
            if rc != 0:
                self.vm_failed += 1
            label = str(d.get("op", "")) + (f" sift-{d.get('job')}" if d.get("job") else "")
            return [
                ("dungeon ", "vm"),
                (label, "text"),
                (f" · rc {rc} · {dur:.1f}s", "ok" if rc == 0 else "bad"),
            ]
        if kind == "stage.enter" and fid:
            self.monster(fid).stage = str(d.get("stage", ""))
            return []
        if kind == "fix.attempt" and fid:
            self.monster(fid).stage = "fix"
            return [
                (f"{fid} ", "hot"),
                (f"attacked with {d.get('backend', '?')} (try {d.get('attempt', 1)})", "text"),
            ]
        if kind == "sandbox.result" and fid:
            rc = _int(d.get("rc"))
            return [(f"{fid} ", "hot"), (f"dungeon trial {d.get('label', '')} · rc {rc}", "text")]
        if kind == "verify.result" and fid:
            status = str(d.get("status", ""))
            style = "ok" if status == "pass" else "bad" if status == "fail" else "dim"
            return [(f"{fid} ", "hot"), (f"proof {d.get('gate', '')}: ", "text"), (status, style)]
        if kind == "finding.outcome" and fid:
            m = self.monster(fid)
            m.outcome, m.stage = str(d.get("outcome", "")), "done"
            fate = _fate(m.outcome)
            return [
                (f"{fid} ", "hot"),
                (fate, "ok" if m.outcome.startswith("fixed") else "bad"),
                (f" · {m.outcome}", "dim"),
            ]
        if kind == "budget.update":
            self.budget_used, self.budget_limit = _int(d.get("tokens_used")), _int(d.get("tokens_limit"))
            return []
        if kind == "selftest.result":
            ok = bool(d.get("passed"))
            return [("dungeon wards ", "vm"), ("hold" if ok else "BROKEN", "ok" if ok else "bad")]
        if kind == "error":
            return [("error ", "bad"), (str(d.get("message", "")), "text")]
        return []

    def hero(self, name: str) -> Hero:
        if name not in self.heroes:
            self.heroes[name] = Hero(name)
        return self.heroes[name]

    def monster(self, fid: str) -> Monster:
        if fid not in self.monsters:
            self.monsters[fid] = Monster(fid)
        return self.monsters[fid]


def _fate(outcome: str) -> str:
    if outcome in OUTCOMES:
        return OUTCOMES[outcome]
    return "escaped" if outcome.startswith("rejected") else outcome.replace("_", " ")


def _what(kind: str, mode: str) -> str:
    """'scan full', 'fix' (not 'fix fix')."""
    return kind if mode in ("", kind) else f"{kind} {mode}"


def _class(name: str) -> str:
    return CLASSES.get(name, "Squire")


def _dict(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _int(v: Any) -> int:
    return v if isinstance(v, int) and not isinstance(v, bool) else 0


def _float(v: Any) -> float:
    return float(v) if isinstance(v, int | float) and not isinstance(v, bool) else 0.0


def _short(model: str) -> str:
    return model.split("/", 1)[-1] if "/" in model else model


def _secs(ts: str) -> float | None:
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).timestamp()
    except ValueError:
        return None


def _clock(seconds: float) -> str:
    s = max(0, int(seconds))
    return (
        f"{s // 3600:02d}:{s % 3600 // 60:02d}:{s % 60:02d}" if s >= 3600 else f"{s // 60:02d}:{s % 60:02d}"
    )


def _tok(n: int) -> str:
    return f"{n / 1000:.1f}k" if n >= 1000 else str(n)


# ------------------------------------------------------------------ drawing


def fit(segs: list[Seg], width: int) -> list[Seg]:
    """Cut or pad segments to exactly `width` visible characters (all glyphs used are one cell wide)."""
    out: list[Seg] = []
    left = width
    for text, style in segs:
        if left <= 0:
            break
        piece = text[:left]
        out.append((piece, style))
        left -= len(piece)
    if left > 0:
        out.append((" " * left, ""))
    return out


def bar(value: float, total: float, width: int) -> str:
    if width <= 0:
        return ""
    filled = 0 if total <= 0 else round(width * min(1.0, value / total))
    return "█" * filled + "░" * (width - filled)


def spark(values: list[float], width: int) -> str:
    vals = values[-width:]
    if not vals:
        return "·" * width
    top = max(vals) or 1.0
    s = "".join(SPARK[min(7, int(v / top * 7.999))] for v in vals)
    return s.rjust(width, "·")


@dataclass
class Panel:
    title: str
    rows: list[list[Seg]]
    accent: str = "gold"
    glow: bool = False


def draw_panel(p: Panel, width: int, height: int) -> list[list[Seg]]:
    inner = width - 2
    border = "hot" if p.glow else "border"
    title = f" {p.title} "
    top: list[Seg] = [("┌─", border), (title, p.accent), ("─" * max(0, inner - 1 - len(title)) + "┐", border)]
    lines = [fit(top, width)]
    body = p.rows[: max(0, height - 2)]
    for row in body:
        lines.append([("│", border), *fit(row, inner), ("│", border)])
    for _ in range(height - 2 - len(body)):
        lines.append([("│", border), (" " * inner, ""), ("│", border)])
    lines.append([("└" + "─" * inner + "┘", border)])
    return lines


def side_by_side(left: list[list[Seg]], right: list[list[Seg]], gap: int = 1) -> list[list[Seg]]:
    out = []
    for i in range(max(len(left), len(right))):
        a = left[i] if i < len(left) else []
        b = right[i] if i < len(right) else []
        out.append([*a, (" " * gap, ""), *b])
    return out


def _party(b: Board, now: float, width: int) -> Panel:
    rows: list[list[Seg]] = []
    tick = int(now * 6)
    rank = {"running": 0, "ok": 1, "error": 1, "ready": 2, "skipped": 3}
    for h in sorted(b.heroes.values(), key=lambda h: rank.get(h.status, 2)):  # the fighters on top
        if h.status == "running":
            icon, style, state = PULSE[tick % len(PULSE)], "hot", "fighting"
        elif h.status == "ok":
            icon, style, state = "●", "ok", f"{h.found} found  {h.duration:5.1f}s"
        elif h.status == "skipped":
            icon, style, state = "○", "dim", "at camp"
        elif h.status == "error":
            icon, style, state = "▼", "bad", "fallen"
        else:
            icon, style, state = "·", "dim", "ready"
        fresh = now - h.changed < 1.5 and h.status != "ready"
        name_style = "invert" if fresh else ("scan" if h.status != "skipped" else "dim")
        xp = bar(min(h.found, 10), 10, 6) if h.status == "ok" else "      "
        rows.append(
            [
                (f" {icon} ", style),
                (f"{_class(h.name):<10}", "gold" if h.status != "skipped" else "dim"),
                (f"{h.name:<15}", name_style),
                (xp + " ", "medium" if h.found else "dim"),
                (state, style if h.status != "ok" else "text"),
            ]
        )
    if not rows:
        rows.append([(" no party yet", "dim")])
    done = sum(1 for h in b.heroes.values() if h.status in ("ok", "error"))
    active = sum(1 for h in b.heroes.values() if h.status != "skipped")
    return Panel(
        f"PARTY {done}/{active}", rows, "scan", glow=any(h.status == "running" for h in b.heroes.values())
    )


def _bestiary(b: Board, now: float, width: int = 60) -> Panel:
    where_w = max(8, width - 2 - 3 - 6 - 17 - 6 - 14)
    rows: list[list[Seg]] = []
    order = {s: i for i, s in enumerate(SEVERITIES)}
    monsters = sorted(b.monsters.values(), key=lambda m: (order.get(m.severity, 9), m.id))
    for m in monsters:
        new = now - m.seen < 4 if m.seen else False
        hp = {"critical": 10, "high": 8, "medium": 6, "low": 4, "info": 2}.get(m.severity, 2)
        if m.outcome:
            state: Seg = (_fate(m.outcome), "ok" if m.outcome.startswith("fixed") else "bad")
            hp = 0 if m.outcome.startswith("fixed") else hp
        elif m.stage:
            state = (STAGE_ACTIONS.get(m.stage, m.stage), "hot")
        else:
            state = ("lurking", "dim")
        where = m.path.rsplit("/", 1)[-1] + (f":{m.line}" if m.line else "")
        rows.append(
            [
                ("NEW" if new else "   ", "invert" if new else ""),
                (f" {m.id:<5}", "hot"),
                (f"{MONSTERS.get(m.severity, 'Bones'):<17}", m.severity),
                (bar(hp, 10, 5) + " ", m.severity),
                (f"{where[:where_w]:<{where_w}} ", "text"),
                state,
            ]
        )
    if not rows:
        rows.append([(" no monsters sighted", "dim")])
    return Panel(
        f"BESTIARY {len(monsters)}", rows, "bad", glow=any(now - m.seen < 2 for m in monsters if m.seen)
    )


def _tower(b: Board, width: int) -> Panel:
    inner = width - 2
    lat = list(b.latencies)
    avg = sum(lat) / len(lat) if lat else 0.0
    rows: list[list[Seg]] = [
        [(" host  ", "dim"), (b.llm_host or "not set up", "text")],
        [(" oracle ", "dim"), (_short(b.llm_model) or "-", "llm")],
        [(" backup ", "dim"), (_short(b.llm_fallback) or "-", "dim")],
        [
            (" ravens ", "dim"),
            (str(b.llm_calls), "text"),
            ("  lost ", "dim"),
            (str(b.llm_failed), "bad" if b.llm_failed else "text"),
            ("  flying ", "dim"),
            (str(b.llm_inflight), "hot" if b.llm_inflight else "text"),
        ],
        [(" mana  ", "dim"), (f"{_tok(b.tokens_in)} in / {_tok(b.tokens_out)} out", "text")],
        [(" speed ", "dim"), (spark(lat, max(4, inner - 20)), "llm"), (f" {avg:4.1f}s avg", "dim")],
    ]
    if b.budget_limit:
        rows.append([(" budget ", "dim"), (bar(b.budget_used, b.budget_limit, max(4, inner - 22)), "gold"),
                     (f" {_tok(b.budget_used)}/{_tok(b.budget_limit)}", "dim")])  # fmt: skip
    return Panel("ORACLE TOWER · LLM", rows, "llm", glow=b.llm_inflight > 0)


def _dungeon(b: Board, width: int) -> Panel:
    inner = width - 2
    rows: list[list[Seg]] = [
        [
            (" host  ", "dim"),
            (b.vm_host or "not set up", "text"),
            (f"  {b.vm_runtime}" if b.vm_runtime else "", "dim"),
        ],
        [
            (" prisoners ", "dim"),
            (str(b.vm_jobs), "text"),
            ("  orders ", "dim"),
            (str(b.vm_commands), "text"),
            ("  failed ", "dim"),
            (str(b.vm_failed), "bad" if b.vm_failed else "text"),
        ],
        [
            (" now   ", "dim"),
            (b.vm_last or ("idle" if not b.vm_inflight else "..."), "hot" if b.vm_inflight else "dim"),
        ],
        [(" time  ", "dim"), (spark(list(b.vm_durations), max(4, inner - 8)), "vm")],
    ]
    if b.kind == "scan":
        rows.append([(" scans never enter the dungeon", "dim")])
    return Panel("DUNGEON · SANDBOX VM", rows, "vm", glow=b.vm_inflight > 0)


def _header(
    b: Board, now: float, width: int, runs: int, index: int, follow: bool, paused: bool
) -> list[list[Seg]]:
    start = _secs(b.started) if b.started else None
    end = _secs(b.ended) if b.ended else None
    took = ((end or now) - start) if start else 0.0
    live = not b.ended and bool(b.started)
    if live:
        status: Seg = ("● LIVE" if int(now * 2) % 2 else "○ LIVE", "bad")
    elif b.exit_code == 0:
        status = ("VICTORY", "ok")
    elif b.ended:
        status = ("MONSTERS REMAIN" if b.monsters else f"EXIT {b.exit_code}", "bad")
    else:
        status = ("waiting for a run", "dim")
    title: list[Seg] = [
        ("╔═ ", "border"),
        ("CODESIFT", "title"),
        (" ═ ", "border"),
        (f"{b.project or '-'} · {_what(b.kind, b.mode)}".strip(), "text"),
        (" ═ ", "border"),
        status,
        (f"  {_clock(took)}", "gold"),
    ]
    used = sum(len(t) for t, _ in title)
    tag = (
        f" run {index + 1}/{runs}"
        + (" · follow" if follow else " · pinned")
        + (" · PAUSED" if paused else "")
        + " ═╗"
    )
    title.append(("═" * max(0, width - used - len(tag)), "border"))
    title.append((tag, "border"))
    counts = {s: 0 for s in SEVERITIES}
    for m in b.monsters.values():
        if not m.outcome.startswith("fixed"):
            counts[m.severity if m.severity in counts else "info"] += 1
    total = sum(counts.values())
    threat: list[Seg] = [(" THREAT ", "gold")]
    meter = max(10, width - 60)
    if total:
        drawn = 0
        for i, sev in enumerate(SEVERITIES):
            n = round(meter * counts[sev] / total) if i < len(SEVERITIES) - 1 else meter - drawn
            n = max(0, min(n, meter - drawn))
            threat.append(("█" * n, sev))
            drawn += n
    else:
        threat.append(("░" * meter, "dim"))
    for sev in SEVERITIES:
        threat.append((f"  {sev} ", "dim"))
        threat.append((str(counts[sev]), sev if counts[sev] else "dim"))
    return [fit(title, width), fit(threat, width)]


def render(
    b: Board,
    width: int,
    height: int,
    now: float,
    *,
    runs: int = 1,
    index: int = 0,
    follow: bool = True,
    paused: bool = False,
) -> list[list[Seg]]:
    width, height = max(40, width), max(12, height)
    lines = _header(b, now, width, runs, index, follow, paused)
    footer: list[Seg] = [
        (" q", "gold"), (" quit  ", "dim"), ("←/→", "gold"), (" runs  ", "dim"), ("f", "gold"),
        (" follow live  ", "dim"), ("p", "gold"), (" pause", "dim"),
    ]  # fmt: skip
    avail = height - len(lines) - 1
    if width >= 100:
        half = (width - 1) // 2
        rest = width - 1 - half
        top_h = max(6, min(max(len(b.heroes), len(b.monsters), 1) + 2, avail // 2))
        lines += side_by_side(
            draw_panel(_party(b, now, half), half, top_h), draw_panel(_bestiary(b, now, rest), rest, top_h)
        )
        mid_h = 8
        lines += side_by_side(
            draw_panel(_tower(b, half), half, mid_h), draw_panel(_dungeon(b, rest), rest, mid_h)
        )
        log_h = avail - top_h - mid_h
    else:
        party_h = min(len(b.heroes) + 2, max(4, avail // 3))
        best_h = min(max(len(b.monsters), 1) + 2, max(3, avail // 4))
        lines += draw_panel(_party(b, now, width), width, party_h)
        lines += draw_panel(_bestiary(b, now, width), width, best_h)
        tower = _tower(b, width)
        tower.rows = tower.rows[3:5]
        lines += draw_panel(tower, width, 4)
        log_h = avail - party_h - best_h - 4
    if log_h >= 3:
        log_rows = [[(f" {ts} ", "dim"), *segs] for ts, segs in list(b.log)[: log_h - 2]]
        lines += draw_panel(Panel("BATTLE LOG", log_rows, "gold"), width, log_h)
    lines = lines[: height - 1]
    while len(lines) < height - 1:
        lines.append([(" " * width, "")])
    lines.append(fit(footer, width))
    return [fit(line, width) for line in lines]


def paint(lines: list[list[Seg]], color: bool, ascii_only: bool) -> str:
    out = []
    for line in lines:
        parts = []
        for text, style in line:
            if ascii_only:
                text = text.translate(_ASCII)
            parts.append(f"{STYLES[style]}{text}{RESET}" if color and style in STYLES else text)
        out.append("".join(parts))
    return "\n".join(out)


# ------------------------------------------------------------------ following runs


@dataclass
class Follower:
    """Tracks the run list and feeds the chosen run's new events into a Board."""

    runs: Runs
    clock: Callable[[], float] = time.time
    ids: list[str] = field(default_factory=list)
    current: str = ""
    follow: bool = True
    paused: bool = False
    board: Board = field(default_factory=Board)
    _offset: int = 0
    _path: Path | None = None
    _demo_start: float = 0.0
    _demo_seen: float = 0.0

    def refresh(self) -> None:
        if self.runs.demo is not None:  # `--demo`: only the synthetic run, played at its own pace
            if not self.current:
                self.ids = ["demo"]
                self.open("demo")
            return
        self.ids = [r["id"] for r in self.runs.list_runs() if r["id"] not in ("demo", "replay")]
        if self.ids and (not self.current or (self.follow and self.current != self.ids[0])):
            self.open(self.ids[0])

    def open(self, rid: str) -> None:
        self.current, self.board, self._offset = rid, Board(run_id=rid), 0
        if rid == "demo":
            self._path, self._demo_start, self._demo_seen = None, self.clock(), 0.0
            self.pump()
            return
        try:
            self._path = self.runs.resolve(rid) / "events.jsonl"
        except StateError:
            self._path = None
        self.pump(instant=True)

    def step(self, delta: int) -> None:
        if not self.ids:
            return
        i = self.ids.index(self.current) if self.current in self.ids else 0
        i = max(0, min(len(self.ids) - 1, i + delta))
        self.follow = i == 0  # back on the newest run means following it again
        self.open(self.ids[i])

    def pump(self, instant: bool = False) -> None:
        demo = self.runs.demo
        if self.current == "demo" and demo is not None:
            now = self.clock()
            if self.paused:  # a paused demo waits instead of jumping ahead afterwards
                self._demo_start += now - (self._demo_seen or now)
                self._demo_seen = now
                return
            self._demo_seen = now
            due = list(accumulate(demo.delays))
            while self._offset < len(demo.events) and due[self._offset] <= now - self._demo_start:
                stamped = dict(
                    demo.events[self._offset], ts=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                )
                self.board.apply(stamped, now)
                self._offset += 1
            return
        if self._path is None or (self.paused and not instant):
            return
        events, self._offset = read_events(self._path, self._offset)
        now = self.clock()
        for ev in events:
            # a run opened after the fact shows its history without "NEW" flashes
            self.board.apply(ev, 0.0 if instant else now)

    @property
    def index(self) -> int:
        return self.ids.index(self.current) if self.current in self.ids else 0


# ------------------------------------------------------------------ the terminal


@contextmanager
def _terminal(stream: TextIO) -> Iterator[Callable[[float], str]]:
    """Alternate screen, hidden cursor and unbuffered keys; always restored. Yields a key reader."""
    if sys.platform == "win32":
        import ctypes
        import msvcrt

        kernel = ctypes.windll.kernel32
        handle = kernel.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        kernel.GetConsoleMode(handle, ctypes.byref(mode))
        kernel.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING

        def read_key(timeout: float) -> str:
            end = time.monotonic() + timeout
            while time.monotonic() < end:
                if msvcrt.kbhit():
                    ch = msvcrt.getwch()
                    if ch in ("\x00", "\xe0"):
                        return {"K": "left", "M": "right"}.get(msvcrt.getwch(), "")
                    return ch
                time.sleep(0.02)
            return ""

        stream.write("\x1b[?1049h\x1b[?25l")
        try:
            yield read_key
        finally:
            stream.write(RESET + "\x1b[?25h\x1b[?1049l")
            stream.flush()
            kernel.SetConsoleMode(handle, mode.value)
    else:
        import select
        import termios
        import tty

        fd = sys.stdin.fileno()
        saved = termios.tcgetattr(fd)

        def read_key(timeout: float) -> str:
            ready, _, _ = select.select([sys.stdin], [], [], timeout)
            if not ready:
                return ""
            ch = os.read(fd, 1).decode("utf-8", "ignore")
            if ch == "\x1b":
                more, _, _ = select.select([sys.stdin], [], [], 0.01)
                if more:
                    seq = os.read(fd, 2).decode("utf-8", "ignore")
                    return {"[D": "left", "[C": "right"}.get(seq, "")
            return ch

        tty.setcbreak(fd)
        stream.write("\x1b[?1049h\x1b[?25l")
        try:
            yield read_key
        finally:
            stream.write(RESET + "\x1b[?25h\x1b[?1049l")
            stream.flush()
            termios.tcsetattr(fd, termios.TCSADRAIN, saved)


def run_top(runs: Runs, *, once: bool = False, ascii_only: bool = False, stream: TextIO | None = None) -> int:
    out = stream or sys.stdout
    if hasattr(out, "reconfigure"):
        try:  # ASCII mode still replaces anything a narrow code page cannot show, instead of crashing
            out.reconfigure(encoding="ascii" if ascii_only else "utf-8", errors="replace")
        except (OSError, ValueError):
            ascii_only = True
    color = "NO_COLOR" not in os.environ
    follower = Follower(runs)
    follower.refresh()
    if once:
        size = shutil.get_terminal_size((120, 40))
        frame = render(
            follower.board, size.columns - 1, size.lines, time.time(), runs=max(1, len(follower.ids))
        )
        out.write(paint(frame, color and out.isatty(), ascii_only) + "\n")
        return 0
    if not (out.isatty() and sys.stdin.isatty()):
        print("sift top: needs an interactive terminal (use --once to print a single frame)", file=sys.stderr)
        return 2
    last_list = 0.0
    with _terminal(out) as read_key:
        while True:
            now = time.time()
            if now - last_list > 2.0:
                follower.refresh()
                last_list = now
            follower.pump()
            size = shutil.get_terminal_size((120, 40))
            frame = render(
                follower.board,
                size.columns - 1,  # never write the last column: some terminals wrap there
                size.lines,
                now,
                runs=max(1, len(follower.ids)),
                index=follower.index,
                follow=follower.follow,
                paused=follower.paused,
            )
            body = paint(frame, color, ascii_only).replace("\n", "\x1b[K\n")
            out.write("\x1b[H" + body + "\x1b[K\x1b[J")
            out.flush()
            key = read_key(0.2)
            if key in ("q", "Q", "\x03", "\x1b"):
                return 0
            if key in ("left", "["):
                follower.step(1)  # older
            elif key in ("right", "]"):
                follower.step(-1)  # newer
            elif key in ("f", "F"):
                follower.follow = True
                follower.refresh()
            elif key in ("p", "P", " "):
                follower.paused = not follower.paused
