#!/usr/bin/env python3
"""
discord_notifier.py — Real-time + summary Discord alerts for BTC15 / ETH15 Kalshi.

Runs independently of kalshi_tracker.py. Every POLL_SECONDS it checks for:
  • newly executed trades (fills)            -> blue ping
  • newly resolved positions (settlements)   -> green (win) / red (loss) ping
Filtered to KXBTC15M / KXETH15M only.

It also posts roll-up summaries (record + net P&L + profit factor):
  • DAILY  — once a day, window = 24h ending at DAILY_SUMMARY_HOUR
  • WEEKLY — once a week, window = 7d ending at WEEKLY_SUMMARY_HOUR on the chosen weekday

Catch-up: summaries are anchored to fixed time windows, not "fire at this instant."
If the machine is asleep at the scheduled hour, the next time the script runs it
detects the missed period and sends that summary (covering the correct window).

Setup:
  1. Discord: Server Settings -> Integrations -> Webhooks -> New Webhook -> copy URL.
  2. Add to your .env:  DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/....
  3. Confirm KALSHI_API_HOST below matches the base URL kalshi_tracker.py uses.
  4. pip install requests cryptography python-dotenv   (add to requirements.txt)
  5. python discord_notifier.py
     (test summaries immediately:  python discord_notifier.py --test-daily )
"""

import os
import sys
import json
import time
import base64
from pathlib import Path
from collections import defaultdict
from datetime import datetime, date, timezone, timedelta

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ─────────────────────────── CONFIG ───────────────────────────
# IMPORTANT: match this to whatever base URL kalshi_tracker.py uses.
KALSHI_API_HOST = os.getenv("KALSHI_API_HOST", "https://api.elections.kalshi.com")
API_PREFIX      = "/trade-api/v2"

API_KEY_ID       = os.getenv("KALSHI_API_KEY")
PRIVATE_KEY_PATH = os.getenv("KALSHI_PRIVATE_KEY_PATH", "kalshi_private_key.pem")
WEBHOOK_URL      = os.getenv("DISCORD_WEBHOOK_URL")

MARKET_PREFIXES  = ("KXBTC15M", "KXETH15M")   # only these get pinged
POLL_SECONDS     = 20
STATE_FILE       = "notifier_state.json"      # separate from tracker_state.json

# Backfill: replay every missed period after an outage (oldest first).
MAX_BACKFILL_DAYS  = 31    # safety cap; older daily periods are skipped (with a note)
MAX_BACKFILL_WEEKS = 12    # safety cap on weekly periods
BACKFILL_SPACING   = 2.0   # seconds between backfill pings (Discord rate-limit safe)

# Summary timing (local machine time; Monday=0 ... Sunday=6)
DAILY_SUMMARY_HOUR     = 23   # window ends 11pm local
WEEKLY_SUMMARY_WEEKDAY = 6    # Sunday
WEEKLY_SUMMARY_HOUR    = 23

# Embed colors
C_TRADE = 0x3B82F6   # blue
C_WIN   = 0x22C55E   # green
C_LOSS  = 0xEF4444   # red
C_INFO  = 0x6B7280   # gray
# ───────────────────────────────────────────────────────────────


def _fail(msg):
    raise SystemExit(f"[config error] {msg}")


if not API_KEY_ID:
    _fail("KALSHI_API_KEY not set in environment/.env")
if not WEBHOOK_URL:
    _fail("DISCORD_WEBHOOK_URL not set in environment/.env")
if not Path(PRIVATE_KEY_PATH).exists():
    _fail(f"private key not found at {PRIVATE_KEY_PATH}")

with open(PRIVATE_KEY_PATH, "rb") as _f:
    PRIVATE_KEY = serialization.load_pem_private_key(_f.read(), password=None)


# ─────────────────────────── KALSHI AUTH ───────────────────────────
def _sign(message: str) -> str:
    """RSA-PSS / SHA256 signature, base64-encoded (Kalshi spec)."""
    sig = PRIVATE_KEY.sign(
        message.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.DIGEST_LENGTH,
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(sig).decode("utf-8")


def _auth_headers(method: str, path: str) -> dict:
    # Signature is over: timestamp(ms) + METHOD + path (no host, no query string)
    ts = str(int(time.time() * 1000))
    sig = _sign(ts + method.upper() + path)
    return {
        "KALSHI-ACCESS-KEY": API_KEY_ID,
        "KALSHI-ACCESS-SIGNATURE": sig,
        "KALSHI-ACCESS-TIMESTAMP": ts,
        "Content-Type": "application/json",
    }


def kalshi_get(endpoint: str, params: dict | None = None) -> dict:
    path = API_PREFIX + endpoint                 # signed path (no query string)
    url = KALSHI_API_HOST + path
    headers = _auth_headers("GET", path)
    r = requests.get(url, headers=headers, params=params, timeout=15)
    r.raise_for_status()
    return r.json()


# ─────────────────────────── HELPERS ───────────────────────────
def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_iso(ts: str | None):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def _coin(ticker: str) -> str:
    return "BTC" if ticker.startswith("KXBTC15M") else "ETH"


def _relevant(ticker: str) -> bool:
    return ticker.startswith(MARKET_PREFIXES)


def _f(v) -> float:
    """Parse a value that may be a number or a numeric string ('100.00')."""
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _cost_dollars(obj: dict, base: str) -> float:
    """Cost in dollars. API may give <base>_dollars (already $) or <base> (cents)."""
    if base + "_dollars" in obj:
        return _f(obj.get(base + "_dollars"))
    if base in obj:
        return _f(obj.get(base)) / 100.0
    return 0.0


def _price_cents(obj: dict, base: str) -> float:
    """Price in cents. API may give <base>_dollars (e.g. '0.947') or <base> (cents)."""
    if base + "_dollars" in obj:
        return _f(obj.get(base + "_dollars")) * 100.0
    if base in obj:
        return _f(obj.get(base))
    return 0.0


def parse_settlement(s: dict) -> dict:
    """Normalize a settlement across API field-name/unit variants.

    Counts: *_count_fp (strings). Costs: *_total_cost_dollars (dollar strings).
    Fee: fee_cost (dollar string). Payout is NOT taken from `revenue` (which reads
    as a constant and is unreliable for two-sided positions) — instead each winning
    contract pays exactly $1.00 on Kalshi, so payout = winning-side count x $1.
    """
    yes_c = _f(s.get("yes_count_fp", s.get("yes_count", 0)))
    no_c = _f(s.get("no_count_fp", s.get("no_count", 0)))
    yes_cost = _cost_dollars(s, "yes_total_cost")
    no_cost = _cost_dollars(s, "no_total_cost")
    fee = _f(s.get("fee_cost", 0))
    result = str(s.get("market_result", "")).lower()

    winning = no_c if result == "no" else yes_c
    payout = winning * 1.0
    cost = yes_cost + no_cost
    gross = payout - cost
    net = gross - fee
    return {
        "yes_c": yes_c, "no_c": no_c,
        "yes_cost": yes_cost, "no_cost": no_cost,
        "cost": cost, "payout": payout, "fee": fee,
        "gross": gross, "net": net,
        "two_sided": (yes_c > 0 and no_c > 0),
        "result": result.upper(),
    }


def _settlement_pnl(s: dict) -> float:
    """Net P&L (after fees) in dollars for a settlement."""
    return parse_settlement(s)["net"]


def _local_to_utc(date_obj, hour: int):
    """Naive local datetime (date_obj @ hour) -> aware UTC datetime."""
    return datetime(date_obj.year, date_obj.month, date_obj.day, hour).astimezone(timezone.utc)


def post_discord(embed: dict) -> None:
    try:
        r = requests.post(WEBHOOK_URL, json={"embeds": [embed]}, timeout=10)
        if r.status_code not in (200, 204):
            print(f"  ! Discord {r.status_code}: {r.text[:200]}")
    except Exception as e:
        print(f"  ! Discord post failed: {e}")


# ─────────────────────────── EVENT PINGS ───────────────────────────
def notify_fill(f: dict) -> None:
    ticker = f["ticker"]
    side = str(f.get("side", "")).upper()                 # YES / NO
    action = str(f.get("action", "buy")).upper()          # BUY / SELL
    count = _f(f.get("count_fp", f.get("count", 0)))
    base = "yes_price" if f.get("side") == "yes" else "no_price"
    price_c = _price_cents(f, base)
    fee = _f(f.get("fee_cost", 0))
    role = "Taker" if f.get("is_taker") else "Maker"
    post_discord({
        "title": f"Trade placed — {_coin(ticker)}15",
        "color": C_TRADE,
        "fields": [
            {"name": "Market", "value": f"`{ticker}`", "inline": False},
            {"name": "Side", "value": f"{action} {side}", "inline": True},
            {"name": "Count", "value": f"{count:g}", "inline": True},
            {"name": "Price", "value": f"{price_c:g}\u00a2", "inline": True},
            {"name": "Fill", "value": role, "inline": True},
            {"name": "Fee", "value": f"${fee:.2f}", "inline": True},
        ],
        "timestamp": _iso_now(),
    })


def notify_settlement(s: dict) -> None:
    ticker = s["ticker"]
    p = parse_settlement(s)
    win = p["net"] > 0
    two = p["two_sided"]

    if two:
        held_str = f"{p['yes_c']:g} YES + {p['no_c']:g} NO"
    else:
        side = "YES" if p["yes_c"] >= p["no_c"] else "NO"
        cnt = p["yes_c"] if side == "YES" else p["no_c"]
        cst = p["yes_cost"] if side == "YES" else p["no_cost"]
        avg_c = (cst / cnt * 100) if cnt else 0
        held_str = f"{cnt:g} {side} @ {avg_c:.0f}\u00a2"

    title = f"Position resolved — {_coin(ticker)}15  ({'WIN' if win else 'LOSS'})"
    if two:
        title += "  \u26a0 two-sided"

    sign = "+" if p["net"] >= 0 else "-"
    embed = {
        "title": title,
        "color": C_WIN if win else C_LOSS,
        "fields": [
            {"name": "Market", "value": f"`{ticker}`", "inline": False},
            {"name": "Result", "value": p["result"], "inline": True},
            {"name": "Held", "value": held_str, "inline": True},
            {"name": "Cost", "value": f"${p['cost']:.2f}", "inline": True},
            {"name": "Payout", "value": f"${p['payout']:.2f}", "inline": True},
            {"name": "Fee", "value": f"${p['fee']:.2f}", "inline": True},
            {"name": "Net P&L", "value": f"{sign}${abs(p['net']):.2f}", "inline": True},
        ],
        "timestamp": _iso_now(),
    }
    if two:
        embed["description"] = "Held both sides into expiry (the second-leg leak)."
    post_discord(embed)


# ─────────────────────────── SUMMARIES ───────────────────────────
def fetch_settlements_window(since_dt, until_dt, max_pages: int = 25) -> list:
    """Paginate BTC15/ETH15 settlements with since_dt <= settled_time < until_dt."""
    out, cursor, pages = [], None, 0
    while pages < max_pages:
        params = {"limit": 200}
        if cursor:
            params["cursor"] = cursor
        data = kalshi_get("/portfolio/settlements", params)
        setts = data.get("settlements", [])
        if not setts:
            break
        reached_old = False
        for s in setts:
            st = _parse_iso(s.get("settled_time"))
            if st is None:
                continue
            if st < since_dt:
                reached_old = True       # newest-first: optimization to stop early
                continue
            if st >= until_dt:
                continue                 # newer than this window's end
            if _relevant(s.get("ticker", "")):
                out.append(s)
        cursor = data.get("cursor")
        pages += 1
        if reached_old or not cursor:
            break
    return out


def send_summary(title: str, since_dt, until_dt) -> None:
    setts = fetch_settlements_window(since_dt, until_dt)

    agg = defaultdict(lambda: {"n": 0, "w": 0, "pnl": 0.0})
    gross_win = gross_loss = 0.0
    for s in setts:
        p = parse_settlement(s)
        if p["yes_c"] + p["no_c"] <= 0:
            continue                       # held nothing; not a real position
        c = _coin(s["ticker"])
        pnl = p["net"]
        a = agg[c]
        a["n"] += 1
        a["pnl"] += pnl
        if pnl > 0:
            a["w"] += 1
            gross_win += pnl
        else:
            gross_loss += abs(pnl)

    total_n = sum(a["n"] for a in agg.values())
    total_w = sum(a["w"] for a in agg.values())
    net = sum(a["pnl"] for a in agg.values())

    if total_n == 0:
        post_discord({
            "title": title,
            "description": "No BTC15 / ETH15 positions resolved in this window.",
            "color": C_INFO,
            "timestamp": _iso_now(),
        })
        return

    win_rate = 100 * total_w / total_n
    pf = (gross_win / gross_loss) if gross_loss > 0 else float("inf")
    pf_str = "\u221e" if pf == float("inf") else f"{pf:.2f}"

    fields = []
    for c in ("BTC", "ETH"):
        if c in agg:
            a = agg[c]
            wr = 100 * a["w"] / a["n"] if a["n"] else 0
            sgn = "+" if a["pnl"] >= 0 else "-"
            fields.append({
                "name": f"{c}15",
                "value": f"{a['w']}-{a['n']-a['w']}  ({wr:.0f}% win)  {sgn}${abs(a['pnl']):.2f}",
                "inline": False,
            })

    nsgn = "+" if net >= 0 else "-"
    fields += [
        {"name": "Resolved", "value": str(total_n), "inline": True},
        {"name": "Win rate", "value": f"{win_rate:.0f}%", "inline": True},
        {"name": "Profit factor", "value": pf_str, "inline": True},
        {"name": "Net P&L", "value": f"{nsgn}${abs(net):.2f}", "inline": True},
    ]

    post_discord({
        "title": title,
        "color": C_WIN if net >= 0 else C_LOSS,
        "fields": fields,
        "timestamp": _iso_now(),
    })


def _daily_windows_to_send(last_daily, now):
    """Date objects for every daily summary owed since last_daily, oldest first.
    Returns (dates, truncated_count)."""
    cur = daily_due_date(now)
    if last_daily is None:
        return [cur], 0
    last = date.fromisoformat(last_daily)
    out, d = [], last + timedelta(days=1)
    while d <= cur:
        out.append(d)
        d += timedelta(days=1)
    trunc = 0
    if len(out) > MAX_BACKFILL_DAYS:
        trunc = len(out) - MAX_BACKFILL_DAYS
        out = out[-MAX_BACKFILL_DAYS:]
    return out, trunc


def _weekly_windows_to_send(last_weekly, now):
    """Anchor dates for every weekly summary owed since last_weekly, oldest first.
    Returns (dates, truncated_count)."""
    cur = weekly_due_date(now)
    if last_weekly is None:
        return [cur], 0
    last = date.fromisoformat(last_weekly)
    out, w = [], last + timedelta(days=7)
    while w <= cur:
        out.append(w)
        w += timedelta(days=7)
    trunc = 0
    if len(out) > MAX_BACKFILL_WEEKS:
        trunc = len(out) - MAX_BACKFILL_WEEKS
        out = out[-MAX_BACKFILL_WEEKS:]
    return out, trunc


# ─── due-date logic (anchors summaries to fixed windows -> enables catch-up) ───
def daily_due_date(now):
    """Most recent date whose daily window has closed."""
    today = now.date()
    return today if now.hour >= DAILY_SUMMARY_HOUR else today - timedelta(days=1)


def weekly_due_date(now):
    """Most recent WEEKLY_SUMMARY_WEEKDAY whose weekly window has closed."""
    days_since = (now.weekday() - WEEKLY_SUMMARY_WEEKDAY) % 7
    anchor = now.date() - timedelta(days=days_since)
    if anchor == now.date() and now.hour < WEEKLY_SUMMARY_HOUR:
        anchor -= timedelta(days=7)
    return anchor


# ─────────────────────────── STATE ───────────────────────────
def load_state() -> dict:
    if Path(STATE_FILE).exists():
        try:
            d = json.loads(Path(STATE_FILE).read_text())
            d.setdefault("seen_fills", [])
            d.setdefault("seen_settlements", [])
            d.setdefault("last_daily", None)
            d.setdefault("last_weekly", None)
            return d
        except Exception:
            pass
    return {"seen_fills": [], "seen_settlements": [],
            "last_daily": None, "last_weekly": None}


def save_state(seen_fills, seen_setts, last_daily, last_weekly) -> None:
    Path(STATE_FILE).write_text(json.dumps({
        "seen_fills": list(seen_fills)[-3000:],
        "seen_settlements": list(seen_setts)[-3000:],
        "last_daily": last_daily,
        "last_weekly": last_weekly,
    }))


# ─────────────────────────── MAIN LOOP ───────────────────────────
def poll_once(seen_fills: set, seen_setts: set, notify: bool) -> int:
    """Fetch fills + settlements, ping new ones (if notify). Returns # new events."""
    new = 0

    fills = kalshi_get("/portfolio/fills", {"limit": 100}).get("fills", [])
    for f in fills:
        if not _relevant(f.get("ticker", "")):
            continue
        tid = f.get("trade_id")
        if tid in seen_fills:
            continue
        seen_fills.add(tid)
        new += 1
        if notify:
            notify_fill(f)
            time.sleep(0.4)            # stay under Discord webhook rate limits

    setts = kalshi_get("/portfolio/settlements", {"limit": 100}).get("settlements", [])
    for s in setts:
        if not _relevant(s.get("ticker", "")):
            continue
        key = s.get("ticker")          # one settlement per market
        if key in seen_setts:
            continue
        seen_setts.add(key)
        p = parse_settlement(s)
        if p["yes_c"] + p["no_c"] <= 0:
            continue                   # held nothing; skip junk ping
        new += 1
        if notify:
            notify_settlement(s)
            time.sleep(0.4)

    return new


def maybe_send_summaries(now, last_daily, last_weekly):
    """Fire all due/missed summaries (full backfill, oldest first).
    Returns (last_daily, last_weekly, fired)."""
    fired = 0

    # ---- daily backfill ----
    daily_dates, d_trunc = _daily_windows_to_send(last_daily, now)
    if d_trunc:
        post_discord({
            "title": "Daily backfill truncated",
            "description": f"Skipped {d_trunc} older daily period(s) beyond the "
                           f"{MAX_BACKFILL_DAYS}-day cap.",
            "color": C_INFO, "timestamp": _iso_now(),
        })
        time.sleep(BACKFILL_SPACING)
    for d in daily_dates:
        end = _local_to_utc(d, DAILY_SUMMARY_HOUR)
        start = end - timedelta(hours=24)
        on_time = (d == now.date() and now.hour >= DAILY_SUMMARY_HOUR)
        tag = "" if on_time else " (catch-up)"
        send_summary(f"Daily summary — {d:%b %d}{tag}", start, end)
        last_daily = d.isoformat()
        fired += 1
        if len(daily_dates) > 1 or d_trunc:
            time.sleep(BACKFILL_SPACING)

    # ---- weekly backfill ----
    weekly_dates, w_trunc = _weekly_windows_to_send(last_weekly, now)
    if w_trunc:
        post_discord({
            "title": "Weekly backfill truncated",
            "description": f"Skipped {w_trunc} older weekly period(s) beyond the "
                           f"{MAX_BACKFILL_WEEKS}-week cap.",
            "color": C_INFO, "timestamp": _iso_now(),
        })
        time.sleep(BACKFILL_SPACING)
    for w in weekly_dates:
        end = _local_to_utc(w, WEEKLY_SUMMARY_HOUR)
        start = end - timedelta(days=7)
        on_time = (w == now.date()
                   and now.weekday() == WEEKLY_SUMMARY_WEEKDAY
                   and now.hour >= WEEKLY_SUMMARY_HOUR)
        tag = "" if on_time else " (catch-up)"
        send_summary(f"Weekly summary — week ending {w:%b %d}{tag}", start, end)
        last_weekly = w.isoformat()
        fired += 1
        if len(weekly_dates) > 1 or w_trunc:
            time.sleep(BACKFILL_SPACING)

    return last_daily, last_weekly, fired


def main() -> None:
    state = load_state()
    seen_fills = set(state["seen_fills"])
    seen_setts = set(state["seen_settlements"])
    last_daily = state["last_daily"]
    last_weekly = state["last_weekly"]
    first_run = not seen_fills and not seen_setts

    print("Discord notifier started.")
    print(f"  Watching : {', '.join(MARKET_PREFIXES)}")
    print(f"  Polling  : every {POLL_SECONDS}s")
    print(f"  Summaries: daily @ {DAILY_SUMMARY_HOUR}:00, weekly wd{WEEKLY_SUMMARY_WEEKDAY} @ {WEEKLY_SUMMARY_HOUR}:00 (local, with catch-up)")

    if first_run:
        try:
            baseline = poll_once(seen_fills, seen_setts, notify=False)
            print(f"  Baselined {baseline} existing events (no pings sent).")
        except Exception as e:
            print(f"  ! baseline failed: {e}")
        # Mark current periods as already-summarized so we start fresh next cycle.
        now0 = datetime.now()
        last_daily = daily_due_date(now0).isoformat()
        last_weekly = weekly_due_date(now0).isoformat()
        save_state(seen_fills, seen_setts, last_daily, last_weekly)
        post_discord({
            "title": "Notifier online",
            "description": "Watching BTC15 / ETH15 — live trades, resolutions, and daily/weekly summaries.",
            "color": C_INFO,
            "timestamp": _iso_now(),
        })

    while True:
        try:
            n = poll_once(seen_fills, seen_setts, notify=True)

            now = datetime.now()
            last_daily, last_weekly, fired = maybe_send_summaries(now, last_daily, last_weekly)
            n += fired

            if n:
                save_state(seen_fills, seen_setts, last_daily, last_weekly)
                print(f"── {now:%m/%d %I:%M %p} — {n} event(s)/update(s)")

        except requests.HTTPError as e:
            print(f"  ! HTTP error: {e}")
        except Exception as e:
            print(f"  ! poll error: {e}")
        time.sleep(POLL_SECONDS)


def _run_debug() -> None:
    """Print raw JSON of one fill + one settlement so field names/types are visible."""
    print("=== RAW SAMPLES — copy the two JSON blocks below and send them back ===")
    try:
        data = kalshi_get("/portfolio/fills", {"limit": 5})
        fills = data.get("fills", [])
        print(f"\n--- top-level fills response keys: {list(data.keys())} ---")
        print(f"--- FILLS returned: {len(fills)} ---")
        for f in fills[:2]:
            print(json.dumps(f, indent=2))
    except Exception as e:
        print("fills error:", e)
    try:
        data = kalshi_get("/portfolio/settlements", {"limit": 5})
        setts = data.get("settlements", [])
        print(f"\n--- top-level settlements response keys: {list(data.keys())} ---")
        print(f"--- SETTLEMENTS returned: {len(setts)} ---")
        for s in setts[:2]:
            print(json.dumps(s, indent=2))
    except Exception as e:
        print("settlements error:", e)


def _run_test(which: str) -> None:
    now_utc = datetime.now(timezone.utc)
    if which == "--test-daily":
        send_summary("Daily summary [TEST]", now_utc - timedelta(hours=24), now_utc)
    elif which == "--test-weekly":
        send_summary("Weekly summary [TEST]", now_utc - timedelta(days=7), now_utc)
    print("Test summary sent.")


if __name__ == "__main__":
    try:
        arg = sys.argv[1] if len(sys.argv) > 1 else ""
        if arg in ("--dump", "--debug"):
            _run_debug()
        elif arg in ("--test-daily", "--test-weekly"):
            _run_test(arg)
        else:
            main()
    except KeyboardInterrupt:
        print("\nNotifier stopped.")