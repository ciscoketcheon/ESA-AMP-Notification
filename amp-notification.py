#!/usr/bin/python3
import re
import time
import smtplib
from email.mime.text import MIMEText

# -------------------------
# Configuration
# -------------------------
LOG_FILE = "/var/log/esa/mail.log"  # Path to the ESA log files
SMTP_SERVER = "x.x.x.x"  # Your SMTP relay
SMTP_PORT = 25
FROM_ADDR = "amp_notify@test.com"

# -------------------------
# Regex Patterns
# -------------------------
recipient_pat = re.compile(r"MID (\d+).*?To: <(\S+)>")
attachment_pat = re.compile(r"MID (\d+) attachment '(\S+)'")
rewrite_pat = re.compile(r"MID (\d+) rewritten to MID (\d+)")
quarantine_pat = re.compile(r'MID (\d+) quarantined to "File Analysis".*')

# -------------------------
# Data Structures
# -------------------------
mid_to_recipient = {}    # MID -> recipient
mid_to_attachment = {}   # MID -> attachment
mid_rewrite_map = {}     # original MID -> rewritten MID
notified = set()         # track notified MIDs

# -------------------------
# Email Sending Function
# -------------------------
def send_mail(to_addr, subject, body):
    msg = MIMEText(body)
    msg["From"] = FROM_ADDR
    msg["To"] = to_addr
    msg["Subject"] = subject
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as s:
            s.send_message(msg)
        print(f"✅ Notification sent to {to_addr}: {subject}")
    except Exception as e:
        print(f"❌ Failed to send email to {to_addr}: {e}")

# -------------------------
# Resolve final MID
# -------------------------
def resolve_mid(mid):
    return mid_rewrite_map.get(mid, mid)

# -------------------------
# Main Log Watching Loop
# -------------------------
def watch_log():
    print("Watching ESA logs for AMP File Analysis quarantines...")
    with open(LOG_FILE, "r") as f:
        f.seek(0, 2)  # move to end of file
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue

            # Track recipient
            r = recipient_pat.search(line)
            if r:
                mid, rcpt = r.groups()
                mid_to_recipient[mid] = rcpt
                continue

            # Track attachment
            a = attachment_pat.search(line)
            if a:
                mid, filename = a.groups()
                mid_to_attachment[mid] = filename
                continue

            # Track MID rewrites
            rw = rewrite_pat.search(line)
            if rw:
                old_mid, new_mid = rw.groups()
                mid_rewrite_map[old_mid] = new_mid
                # propagate recipient and attachment
                if old_mid in mid_to_recipient:
                    mid_to_recipient[new_mid] = mid_to_recipient[old_mid]
                if old_mid in mid_to_attachment:
                    mid_to_attachment[new_mid] = mid_to_attachment[old_mid]
                continue

            # Only act on quarantined line (second line trigger)
            q = quarantine_pat.search(line)
            if q:
                mid = q.group(1)
                final_mid = resolve_mid(mid)
                if final_mid in notified:
                    continue  # skip duplicates
                rcpt = mid_to_recipient.get(final_mid)
                filename = mid_to_attachment.get(final_mid, "Unknown attachment")
                if rcpt:
                    subject = f"Email Held for Security Analysis ({filename})"
                    body = (f"Dear {rcpt},\n\n"
                            f"Your message with attachment '{filename}' has been quarantined for AMP analysis.\n"
                            f"It will be delivered automatically if found safe.\n\n"
                            f"Thank you for your patience.")
                    send_mail(rcpt, subject, body)
                    notified.add(final_mid)
                    # optional: clean up mappings
                    mid_to_recipient.pop(final_mid, None)
                    mid_to_attachment.pop(final_mid, None)
                    mid_rewrite_map.pop(mid, None)

if __name__ == "__main__":
    watch_log()


