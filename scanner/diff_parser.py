import re

def parse_unified_diff(diff_text):
    findings = []
    current_file = None
    current_line = 0

    for line in diff_text.splitlines():
        if line.startswith('+++ b/'):
            current_file = line[6:].strip()
        elif line.startswith('@@ '):
            match = re.search(r'\+(\d+)', line)
            if match:
                current_line = int(match.group(1))
        elif line.startswith('+') and not line.startswith('+++'):
            if current_file:
                findings.append({
                    "file": current_file,
                    "line": current_line,
                    "code": line[1:]
                })
            current_line += 1
        elif line.startswith(' '):
            current_line += 1

    return findings
