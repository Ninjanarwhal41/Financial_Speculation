import requests
import datetime
import base64
import os
import csv
import json
import time
import dotenv
from urllib.parse import urlparse
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding

dotenv.load_dotenv()

# ── Configuration ─────────────────────────────────────────────────────────────
API_KEY_ID       = os.getenv("KALSHI_API_KEY")
PRIVATE_KEY_PATH = os.getenv("KALSHI_PRIVATE_KEY_PATH")
BASE_URL         = 'https://external-api.kalshi.com/trade-api/v2'
INTERVAL_HOURS   = 2
STARTING_BALANCE = 50.00
HISTORY_DAYS     = 2

# Only track fills from these Reflex crypto markets
CRYPTO_PREFIXES = ('KXBTC15M', 'KXETH15M', 'KXSOL15M', 'KXXRP15M')

SUMMARY_CSV = 'portfolio_summary.csv'
STATE_FILE  = 'tracker_state.json'

SUMMARY_FIELDS = [
    'date', 'time', 'bot_status',
    'portfolio_value_usd', 'cumulative_pl_usd', 'pl_this_period_usd',
    'number_of_positions', 'total_trades',
    'win_rate_pct', 'biggest_win_usd', 'worst_loss_usd',
    'profit_factor', 'notes'
]

# ── Auth ──────────────────────────────────────────────────────────────────────
def load_private_key(key_path):
    with open(key_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

def create_signature(private_key, timestamp, method, path):
    path_without_query = path.split('?')[0]
    message = f"{timestamp}{method}{path_without_query}".encode('utf-8')
    signature = private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

def api_get(private_key, path):
    timestamp = str(int(datetime.datetime.now().timestamp() * 1000))
    sign_path = urlparse(BASE_URL + path).path
    signature = create_signature(private_key, timestamp, "GET", sign_path)
    headers = {
        'KALSHI-ACCESS-KEY': API_KEY_ID,
        'KALSHI-ACCESS-SIGNATURE': signature,
        'KALSHI-ACCESS-TIMESTAMP': timestamp,
    }
    response = requests.get(BASE_URL + path, headers=headers)
    response.raise_for_status()
    return response.json()

# ── State management ──────────────────────────────────────────────────────────
def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, 'r') as f:
            return json.load(f)
    lookback = datetime.datetime.now() - datetime.timedelta(days=HISTORY_DAYS)
    return {
        'last_balance_cents'  : int(STARTING_BALANCE * 100),
        'last_processed_time' : lookback.isoformat(),
        'open_positions'      : {},
        'completed_trades'    : [],
        'processed_fill_ids'  : [],
    }

def save_state(state):
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f, indent=2)

# ── Fills fetching (paginated) ────────────────────────────────────────────────
def fetch_all_fills(private_key, min_ts):
    all_fills = []
    cursor    = None
    while True:
        path = f'/portfolio/fills?min_ts={min_ts}'
        if cursor:
            path += f'&cursor={cursor}'
        data   = api_get(private_key, path)
        fills  = data.get('fills', [])
        all_fills.extend(fills)
        cursor = data.get('cursor')
        if not cursor or not fills:
            break
    return all_fills

# ── Fill processing ───────────────────────────────────────────────────────────
def process_fills(new_fills, state):
    for fill in sorted(new_fills, key=lambda x: x.get('created_time', '')):
        fill_id = fill.get('fill_id', fill.get('trade_id', ''))
        if fill_id in state['processed_fill_ids']:
            continue

        ticker = fill.get('ticker', '')

        # Only track Reflex crypto 15-min markets — ignore all other Kalshi trades
        if not any(ticker.startswith(p) for p in CRYPTO_PREFIXES):
            state['processed_fill_ids'].append(fill_id)
            continue

        action = fill.get('action', '')
        side   = fill.get('side', '')
        count  = float(fill.get('count_fp', '0'))
        yes_p  = float(fill.get('yes_price_dollars', '0'))

        if action == 'buy':
            # For NO positions, actual price paid is 1 - yes_p (the no_price)
            price_paid = yes_p if side == 'yes' else (1.0 - yes_p)
            if ticker not in state['open_positions']:
                state['open_positions'][ticker] = []
            state['open_positions'][ticker].append({
                'side'         : side,
                'price_dollars': price_paid,
                'count'        : count
            })

        elif action == 'sell':
            # For NO sells, actual price received is also 1 - yes_p
            sell_price = yes_p if side == 'yes' else (1.0 - yes_p)
            positions  = state['open_positions'].get(ticker, [])
            remaining  = count
            while remaining > 0 and positions:
                pos     = positions[0]
                matched = min(remaining, pos['count'])
                pnl     = (sell_price - pos['price_dollars']) * matched
                state['completed_trades'].append({
                    'ticker'   : ticker,
                    'pnl_usd'  : round(pnl, 4),
                    'timestamp': fill.get('created_time', '')
                })
                pos['count'] -= matched
                if pos['count'] == 0:
                    positions.pop(0)
                remaining -= matched
            if not positions:
                state['open_positions'].pop(ticker, None)

        state['processed_fill_ids'].append(fill_id)

    return state

# ── Resolution checking (auto-resolved positions) ─────────────────────────────
def resolve_open_positions(private_key, state):
    """
    For each open position, query the Kalshi market endpoint.
    If the market has resolved, calculate P/L from the result and record it.
    """
    resolved = []

    for ticker, positions in state['open_positions'].items():
        try:
            data   = api_get(private_key, f'/markets/{ticker}')
            market = data.get('market', {})
            result = market.get('result', '')

            if result not in ('yes', 'no'):
                continue  # not resolved yet

            for pos in positions:
                won = (pos['side'] == result)
                if won:
                    pnl = (1.0 - pos['price_dollars']) * pos['count']
                else:
                    pnl = -pos['price_dollars'] * pos['count']

                state['completed_trades'].append({
                    'ticker'   : ticker,
                    'pnl_usd'  : round(pnl, 4),
                    'timestamp': market.get('close_time', ''),
                })

            resolved.append(ticker)
            time.sleep(0.1)  # avoid rate limiting

        except Exception:
            pass  # market still active or temporary API error

    for ticker in resolved:
        del state['open_positions'][ticker]

    if resolved:
        print(f"  Resolved {len(resolved)} positions via market API")

    return state

# ── Metric calculations ───────────────────────────────────────────────────────
def _parse_ts(ts_str):
    """Parse an ISO timestamp string (with or without trailing Z) into a naive datetime."""
    return datetime.datetime.fromisoformat(ts_str.rstrip('Z').split('+')[0])

def compute_metrics(state, current_balance_cents, now=None):
    if now is None:
        now = datetime.datetime.now()

    all_trades = state['completed_trades']
    cutoff     = now - datetime.timedelta(hours=INTERVAL_HOURS)

    # Win-rate and related stats are computed over the last INTERVAL_HOURS only
    interval_trades = [
        t for t in all_trades
        if t.get('timestamp') and _parse_ts(t['timestamp']) >= cutoff
    ]

    wins   = [t['pnl_usd'] for t in interval_trades if t['pnl_usd'] > 0]
    losses = [t['pnl_usd'] for t in interval_trades if t['pnl_usd'] < 0]

    n_interval = len(interval_trades)
    win_rate   = round(len(wins) / n_interval * 100, 1) if n_interval > 0 else 0

    biggest_win = round(max(wins),   2) if wins   else 0.0
    worst_loss  = round(min(losses), 2) if losses else 0.0

    avg_win  = sum(wins)        / len(wins)   if wins   else 0
    avg_loss = abs(sum(losses)) / len(losses) if losses else 0

    if n_interval > 0 and avg_loss > 0:
        loss_rate     = len(losses) / n_interval
        profit_factor = round((win_rate / 100 * avg_win) / (loss_rate * avg_loss), 2)
    else:
        profit_factor = 0

    current_usd   = current_balance_cents / 100
    last_usd      = state['last_balance_cents'] / 100
    cumulative_pl = round(current_usd - STARTING_BALANCE, 2)
    pl_period     = round(current_usd - last_usd, 2)

    return {
        'portfolio_value_usd' : f"{current_usd:.2f}",
        'cumulative_pl_usd'   : f"{cumulative_pl:.2f}",
        'pl_this_period_usd'  : f"{pl_period:.2f}",
        'total_trades'        : n_interval,
        'win_rate_pct'        : win_rate,
        'biggest_win_usd'     : biggest_win,
        'worst_loss_usd'      : worst_loss,
        'profit_factor'       : profit_factor,
    }

# ── CSV writer ────────────────────────────────────────────────────────────────
def append_summary(row):
    file_exists = os.path.exists(SUMMARY_CSV)
    with open(SUMMARY_CSV, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=SUMMARY_FIELDS)
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)

# ── Snapshot ──────────────────────────────────────────────────────────────────
def run_snapshot(private_key, state):
    now = datetime.datetime.now()
    print(f"\n── Snapshot at {now.strftime('%m/%d/%Y %I:%M %p')} ──")

    balance_data   = api_get(private_key, '/portfolio/balance')
    positions_data = api_get(private_key, '/portfolio/positions')
    last_ts        = int(datetime.datetime.fromisoformat(state['last_processed_time']).timestamp())
    new_fills      = fetch_all_fills(private_key, last_ts)

    balance_cents = balance_data['balance']
    positions     = positions_data.get('market_positions', [])

    state   = process_fills(new_fills, state)
    state   = resolve_open_positions(private_key, state)
    metrics = compute_metrics(state, balance_cents, now=now)

    bot_status = 'On' if new_fills else 'Off'

    row = {
        'date'               : now.strftime('%m/%d/%Y'),
        'time'               : now.strftime('%I:%M %p'),
        'bot_status'         : bot_status,
        'number_of_positions': len(positions),
        'notes'              : '',
        **metrics,
    }

    append_summary(row)

    state['last_balance_cents']  = balance_cents
    state['last_processed_time'] = now.isoformat()
    save_state(state)

    print(f"  Portfolio   : ${metrics['portfolio_value_usd']}")
    print(f"  P/L Period  : ${metrics['pl_this_period_usd']}")
    print(f"  Cumulative  : ${metrics['cumulative_pl_usd']}")
    print(f"  Total Trades: {metrics['total_trades']}  |  Win Rate: {metrics['win_rate_pct']}%")
    print(f"  Profit Factor: {metrics['profit_factor']}")
    print(f"  Bot Status  : {bot_status}")

    return state

# ── Main loop ─────────────────────────────────────────────────────────────────
def main():
    private_key = load_private_key(PRIVATE_KEY_PATH)
    state       = load_state()

    print(f"Kalshi tracker started — snapshotting every {INTERVAL_HOURS} hours.")
    print(f"Summary log: {SUMMARY_CSV}")

    while True:
        try:
            state = run_snapshot(private_key, state)
        except Exception as e:
            print(f"  ERROR: {e}")
        print(f"  Next snapshot in {INTERVAL_HOURS} hours...")
        time.sleep(INTERVAL_HOURS * 3600)

if __name__ == '__main__':
    main()