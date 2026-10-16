"""Generate SSH auth logs: benign baseline traffic plus labelled multi-stage attacks.

Public auth datasets have no ground truth for spraying, stuffing or enumeration,
so we inject attacks with known IPs and types. Pass --real to merge the real
Loghub OpenSSH log (https://github.com/logpai/loghub) as background traffic;
its IPs are processed and graphed but left out of precision/recall.

Outputs
  data/raw/auth.log          sshd syslog lines sorted by time
  data/labels/ip_labels.csv  ground truth for every synthetic IP
"""
import argparse
import csv
import random
import re
from datetime import datetime, timedelta

import config

HOSTS = ["LabSZ", "web01", "web02", "db01", "vpn01"]
COMMON_TARGETS = ["root", "admin", "ubuntu", "test", "oracle", "postgres"]
FIRST = ["amit", "neha", "rahul", "priya", "vikram", "sneha", "arjun", "kavya", "rohan", "isha",
         "karan", "meera", "aditya", "pooja", "sahil", "tanvi", "nikhil", "riya", "varun", "anjali",
         "john", "maria", "david", "sara", "li", "omar", "elena", "kenji", "fatima", "lucas"]
LAST = ["sharma", "patel", "gupta", "singh", "rao", "iyer", "nair", "mehta", "joshi", "das",
        "smith", "garcia", "chen", "khan", "rossi", "tanaka", "silva", "muller", "kim", "ali"]
PUBLIC_OCTETS = [23, 31, 37, 45, 46, 58, 61, 77, 91, 103, 110, 112, 116, 121, 139, 177, 185,
                 187, 190, 195, 200, 201, 212, 218, 222]

_used_ips = set()


def rand_ip(prefix=None):
    while True:
        if prefix:
            ip = f"{prefix}.{random.randint(2, 254)}"
        else:
            ip = (f"{random.choice(PUBLIC_OCTETS)}.{random.randint(0, 255)}."
                  f"{random.randint(0, 255)}.{random.randint(2, 254)}")
        if ip not in _used_ips:
            _used_ips.add(ip)
            return ip


def rand_prefix():
    return f"{random.choice(PUBLIC_OCTETS)}.{random.randint(0, 255)}.{random.randint(0, 255)}"


class Log:
    """Collects (timestamp, line) pairs in sshd syslog format."""

    def __init__(self):
        self.rows = []

    def emit(self, ts, host, msg):
        pid = random.randint(1000, 65000)
        self.rows.append((ts, f"{ts:%b} {ts.day:2d} {ts:%H:%M:%S} {host} sshd[{pid}]: {msg}"))

    def failed(self, ts, host, user, ip, invalid=False):
        port = random.randint(30000, 65000)
        if invalid:
            self.emit(ts, host, f"Invalid user {user} from {ip}")
            ts += timedelta(seconds=random.uniform(1, 3))
            self.emit(ts, host, f"Failed password for invalid user {user} from {ip} port {port} ssh2")
        else:
            self.emit(ts, host, f"Failed password for {user} from {ip} port {port} ssh2")

    def accepted(self, ts, host, user, ip):
        port = random.randint(30000, 65000)
        self.emit(ts, host, f"Accepted password for {user} from {ip} port {port} ssh2")

    def probe(self, ts, host, user, ip, valid):
        port = random.randint(30000, 65000)
        if not valid:
            self.emit(ts, host, f"Invalid user {user} from {ip}")
        self.emit(ts + timedelta(seconds=1), host, f"Connection closed by {ip} port {port} [preauth]")


def label(labels, ip, attack_type, campaign):
    tech = config.MITRE.get(attack_type, ("", ""))[0]
    labels.append({"ip": ip, "label": "benign" if attack_type == "benign" else "attack",
                   "attack_type": attack_type, "campaign": campaign, "technique_id": tech})


def at(start, day, hour=None):
    hour = random.uniform(0, 24) if hour is None else hour
    return start + timedelta(days=day, hours=hour)


def gen_benign(log, labels, start, days, n_users):
    users = set()
    while len(users) < n_users:
        users.add(f"{random.choice(FIRST)}.{random.choice(LAST)}{random.randint(1, 99)}")
    users = sorted(users)
    for user in users:
        ips = [rand_ip() for _ in range(random.choice([1, 1, 2]))]
        hosts = random.sample(HOSTS[:3], random.choice([1, 2]))
        for ip in ips:
            label(labels, ip, "benign", "benign")
        for d in range(days):
            weekend = (start + timedelta(days=d)).weekday() >= 5
            for _ in range(random.randint(0, 1) if weekend else random.randint(1, 4)):
                hour = min(22, max(7, random.gauss(13, 3)))
                ts = at(start, d, hour)
                ip, host = random.choice(ips), random.choice(hosts)
                if random.random() < 0.05:  # typo, then success
                    log.failed(ts, host, user, ip)
                    ts += timedelta(seconds=random.uniform(5, 20))
                log.accepted(ts, host, user, ip)

    # Benign edge cases that fixed thresholds misfire on
    for user in random.sample(users, 3):  # forgot password after holiday
        ip = rand_ip()
        label(labels, ip, "benign", "benign")
        ts = at(start, random.randint(0, days - 1), random.uniform(9, 17))
        for _ in range(12):
            log.failed(ts, "web01", user, ip)
            ts += timedelta(seconds=random.uniform(8, 20))
        log.accepted(ts, "web01", user, ip)
    backup_ip = rand_ip()  # automation account, very high volume, always succeeds
    label(labels, backup_ip, "benign", "benign")
    for m in range(0, days * 24 * 60, 15):
        log.accepted(start + timedelta(minutes=m, seconds=random.uniform(0, 30)), "db01", "backup", backup_ip)
    return users


def gen_apt_campaign(log, labels, start, valid_users):
    """Multi-stage campaign: enumeration -> spraying botnet -> compromise + lateral movement."""
    campaign = "APT-SSH-1"
    found = random.sample(valid_users, 40)
    probe_list = found + [f"{random.choice(FIRST)}{random.randint(1, 999)}" for _ in range(110)]
    found_set = set(found)

    # Stage 1: user enumeration (3 fast, 3 slow scanners)
    for k in range(6):
        ip = rand_ip()
        label(labels, ip, "user_enumeration", campaign)
        ts = at(start, 2)
        for name in random.sample(probe_list, 100):
            log.probe(ts, "LabSZ", name, ip, valid=name in found_set)
            ts += timedelta(seconds=random.uniform(5, 25) if k < 3 else random.uniform(50, 90))

    # Stage 2: password spraying botnet, 20 bots in 3 subnets, one password per round
    prefixes = [rand_prefix() for _ in range(3)]
    bots = [rand_ip(random.choice(prefixes)) for _ in range(20)]
    for ip in bots:
        label(labels, ip, "password_spraying", campaign)
    for rnd in range(12):
        round_start = start + timedelta(days=4, hours=6 * rnd)
        for user in found:
            ts = round_start + timedelta(minutes=random.uniform(0, 120))
            log.failed(ts, random.choice(["LabSZ", "web01"]), user, random.choice(bots))

    # Stage 3: slow guessing from the botnet subnets, then success and lateral movement
    for victim in random.sample(found, 2):
        ip = rand_ip(random.choice(prefixes))
        label(labels, ip, "post_compromise", campaign)
        ts = at(start, 7, random.uniform(1, 5))
        for user in random.sample(found, 8):
            for _ in range(2):
                log.failed(ts, "LabSZ", user, ip)
                ts += timedelta(minutes=random.uniform(2, 4))
        log.accepted(ts, "LabSZ", victim, ip)
        for host in ["db01", "web02"]:
            ts += timedelta(minutes=random.uniform(20, 60))
            log.accepted(ts, host, victim, ip)


def gen_brute_force(log, labels, start, days, n=5):
    for _ in range(n):
        ip = rand_ip()
        label(labels, ip, "brute_force", "opportunistic")
        ts, user, host = at(start, random.randint(0, days - 1)), random.choice(["root", "admin"]), random.choice(HOSTS)
        for _ in range(random.randint(300, 800)):
            log.failed(ts, host, user, ip)
            ts += timedelta(seconds=random.uniform(1, 3))


def gen_low_and_slow(log, labels, start, days, n=6):
    for _ in range(n):
        ip = rand_ip()
        label(labels, ip, "low_and_slow", "opportunistic")
        ts = at(start, random.randint(0, days - 3))
        end = ts + timedelta(hours=random.uniform(36, 60))
        user, host = random.choice(COMMON_TARGETS[:3]), random.choice(HOSTS)
        while ts < end:
            log.failed(ts, host, user, ip)
            ts += timedelta(minutes=random.uniform(3, 9))


def gen_credential_stuffing(log, labels, start, valid_users, n=8):
    campaign = "STUFF-2"
    leaked = random.sample(valid_users, 15) + [
        f"{random.choice(FIRST)}{random.choice(LAST)}{random.randint(1, 99)}" for _ in range(385)]
    valid = set(valid_users)
    for _ in range(n):
        ip = rand_ip()
        label(labels, ip, "credential_stuffing", campaign)
        ts = at(start, random.choice([10, 11]))
        for user in random.sample(leaked, 150):
            log.failed(ts, random.choice(["web01", "web02", "vpn01"]), user, ip, invalid=user not in valid)
            ts += timedelta(seconds=random.uniform(10, 30))


def merge_real_log(log, path, start):
    """Shift the real Loghub log (no year, Dec-Jan) so it starts at our START_DATE."""
    line_re = re.compile(r"^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(.*)$")
    parsed = []
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            m = line_re.match(line.rstrip("\n"))
            if not m:
                continue
            mon, day, hms, rest = m.groups()
            year = config.LOG_YEAR - 1 if mon in ("Oct", "Nov", "Dec") else config.LOG_YEAR
            try:
                ts = datetime.strptime(f"{year} {mon} {day} {hms}", "%Y %b %d %H:%M:%S")
            except ValueError:
                continue
            parsed.append((ts, rest))
    if not parsed:
        return 0
    shift = start - min(ts for ts, _ in parsed)
    for ts, rest in parsed:
        ts += shift
        log.rows.append((ts, f"{ts:%b} {ts.day:2d} {ts:%H:%M:%S} {rest}"))
    return len(parsed)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--users", type=int, default=300, help="benign users")
    ap.add_argument("--days", type=int, default=14)
    ap.add_argument("--real", help="path to Loghub SSH.log to merge as background traffic")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()

    random.seed(args.seed)
    start = datetime.fromisoformat(config.START_DATE)
    log, labels = Log(), []

    users = gen_benign(log, labels, start, args.days, args.users)
    gen_apt_campaign(log, labels, start, users)
    gen_brute_force(log, labels, start, args.days)
    gen_low_and_slow(log, labels, start, args.days)
    gen_credential_stuffing(log, labels, start, users)
    n_real = merge_real_log(log, args.real, start) if args.real else 0

    log.rows.sort(key=lambda r: r[0])
    config.RAW_LOG.parent.mkdir(parents=True, exist_ok=True)
    config.LABELS_CSV.parent.mkdir(parents=True, exist_ok=True)
    with open(config.RAW_LOG, "w", encoding="utf-8", newline="\n") as fh:
        fh.writelines(line + "\n" for _, line in log.rows)
    with open(config.LABELS_CSV, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["ip", "label", "attack_type", "campaign", "technique_id"])
        w.writeheader()
        w.writerows(labels)

    attacks = {}
    for row in labels:
        attacks[row["attack_type"]] = attacks.get(row["attack_type"], 0) + 1
    print(f"Wrote {len(log.rows):,} log lines ({n_real:,} real Loghub) to {config.RAW_LOG}")
    print(f"Wrote {len(labels):,} labelled IPs to {config.LABELS_CSV}: {attacks}")


if __name__ == "__main__":
    main()
