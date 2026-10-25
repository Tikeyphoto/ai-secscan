import re
import os
from datetime import datetime, timedelta
from collections import Counter

NGINX_LOG = "/var/log/nginx/access.log"

LOG_PATTERN = re.compile(
    r'(\S+) - - \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d+) (\S+) "[^"]*" "([^"]*)"'
)

def parse_nginx_log(max_lines=10000):
    if not os.path.exists(NGINX_LOG):
        return {"error": f"Log not found: {NGINX_LOG}"}
    try:
        with open(NGINX_LOG, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()[-max_lines:]
    except PermissionError:
        return {"error": "Permission denied. Run: sudo chmod o+r /var/log/nginx/access.log"}

    total = 0
    ips = Counter()
    paths = Counter()
    statuses = Counter()
    browsers = Counter()
    per_day = Counter()

    for line in lines:
        m = LOG_PATTERN.match(line)
        if not m:
            continue
        ip, time_str, method, path, status, size, ua = m.groups()
        total += 1
        ips[ip] += 1
        paths[path] += 1
        statuses[status] += 1

        ua_l = ua.lower()
        if 'bot' in ua_l or 'crawler' in ua_l or 'spider' in ua_l or 'python' in ua_l:
            browsers['Bot/CLI'] += 1
        elif 'edg/' in ua_l:
            browsers['Edge'] += 1
        elif 'chrome/' in ua_l:
            browsers['Chrome'] += 1
        elif 'firefox/' in ua_l:
            browsers['Firefox'] += 1
        elif 'safari/' in ua_l:
            browsers['Safari'] += 1
        else:
            browsers['Other'] += 1

        try:
            dt = datetime.strptime(time_str.split()[0], "%d/%b/%Y:%H:%M:%S")
            per_day[dt.strftime("%Y-%m-%d")] += 1
        except ValueError:
            pass

    today = datetime.now().date()
    days = [(today - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(13, -1, -1)]
    timeline = [{"date": d, "count": per_day.get(d, 0)} for d in days]

    return {
        "total_requests": total,
        "unique_visitors": len(ips),
        "top_ips": ips.most_common(10),
        "top_paths": paths.most_common(10),
        "statuses": dict(statuses),
        "browsers": dict(browsers),
        "timeline": timeline,
    }
