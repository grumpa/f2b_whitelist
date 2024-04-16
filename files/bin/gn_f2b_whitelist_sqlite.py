#!/usr/bin/env python3

"""Make whitelist for fail2ban

Read successful attempts login (imap, submission) and use their IPs
in fail2ban jail ignoreip.

Create file jail.d/gn-ignoreip.draft as source for gn-ignoreip.local
with ingoreip_local variable.

WorkFlow:
- read current mail log and write relevant data to sqlite DB
- read DB and make file ingoreip variable with usable IPs
- create comments to file explaining why those IPs are whitelisted

Externalities:
- /etc/rsyslog.d/gn_f2b_mail.conf
- /etc/logrotate.d/gn_f2b_mail
  - prerotate runs this script to update data for whitelisting
"""

from pathlib import Path
import sqlite3
import time
from datetime import datetime, timedelta
import subprocess

# Oldest records in journal db table
RECORDS_MAX_AGE = 30

DB_PATH = Path('/etc/fail2ban/jail.d/gn_whitelist.db')
LOG_FILENAME = '/var/log/gn_f2b_mail.log'
IGNORE_DRAFT_FNAME = '/etc/fail2ban/jail.d/gn-ignoreip.draft'

if not Path(LOG_FILENAME).exists():
    Path(LOG_FILENAME).touch(mode=0o640)

QUERY = """
SELECT ip, username, count(*) AS cnt
    FROM journal
    GROUP BY ip, username
    ORDER BY ip
    ;
"""

# What string to grep, what lines skip. (p=postfix, d=dovecot)
FINDERS = [
    {
        'fstring': 'sasl_username',
        'skip': 'authentication failed',
        'user_start': 'sasl_username=',
        'user_between': ('=', None),
        'ip_start': 'client=',
        'ip_between': ('[', ']'),
        'backend': 'p'
    },
    {
        'fstring': 'imap-login',
        'skip': 'auth failed',
        'user_start': 'user=',
        'user_between': ('<', '>'),
        'ip_start': 'rip=',
        'ip_between': ('=', ','),
        'backend': 'd'
    }
]

def convert_time(time_from_log):
    """Convert timestamp from log file format to DB format"""
    # time_from_log = 'Mar 25 14:27:47'
    curr_year = time.localtime().tm_year
    py_time = time.strptime(f'{curr_year} {time_from_log}', '%Y %b %d %H:%M:%S')
    return time.strftime('%Y-%m-%dT%H:%M:%S', py_time)

def extract_between(text, first, last):
    """Extract text between two chars - brackets i.e.

        If provided value None as first or last it results in start or end of text.
    """
    start = text.index(first) + 1 if first else None
    end = text.index(last) if last else None
    return text[start:end]

def whois_bits(ip):
    """Return string with country code and netname from whois"""
    sp = subprocess.run(('whois', ip), capture_output=True)
    if sp.returncode != 0:
        return ''
    lines = sp.stdout.decode().splitlines()
    country = ''
    netname = ''
    for line in lines:
        line = line.lower()
        if line.startswith('country'):
            country = line.split(':')[1].strip()
        elif line.startswith('netname:'):
            netname = line.split(':')[1].strip()
    return f'{country} {netname}'[:21]

class Whitelist:

    def __init__(self) -> None:

        self.db_conn = None
        self.db_cursor = None
        self.db_open()
        # IP -> (user, count) dict created from db records
        self.records = dict()
        # Text version of fail2ban ignore ips list
        self.ignores = ''
        # Text comments for fail2ban ignore ips. IP, list of users and their counts.
        self.comments = ''


    def _db_create(self):

        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        db_conn = sqlite3.connect(str(DB_PATH))
        db_cursor = db_conn.cursor()
        db_cursor.execute('CREATE TABLE journal (timestamp str, ip str, username str, backend str);')
        db_conn.commit()
        db_conn.close()

    def db_open(self):

        if not DB_PATH.exists():
            self._db_create()

        self.db_conn = sqlite3.connect(str(DB_PATH))
        self.db_cursor = self.db_conn.cursor()

    def process_new_log_records(self):
        """Read new records from mail.log and save relevant do database."""

        # Get maximum timestamp - we want to continue after that.
        self.db_cursor.execute('SELECT max(timestamp) FROM journal;')
        max_timestamp = self.db_cursor.fetchone()[0]
        if max_timestamp is None:
            max_timestamp = ''

        with open(LOG_FILENAME, 'r') as logfile:
            for line in logfile:

                timestamp = convert_time(line[0:15])
                # Skip lines already processed in previous run of this script.
                if timestamp <= max_timestamp:
                    continue

                # Is this line worth to bother with?
                bother_with_this_line = False
                for find_item in FINDERS:
                    # If reason to skip line read next line
                    if line.find(find_item['skip']) > 0:
                        break
                    # Is it wanted string?
                    if line.find(find_item['fstring']) < 0:
                        continue
                    else:
                        bother_with_this_line = True
                        break
                if not bother_with_this_line:
                    continue

                # This is "our" line :-) Let's get data.
                ip: str = ''
                user: str = ''
                for part in line.split():
                    if part.startswith(find_item['user_start']):
                        user = extract_between(part, find_item['user_between'][0], find_item['user_between'][1])
                    elif part.startswith(find_item['ip_start']):
                        # ip = extract_between(part, '=', ',')
                        ip = extract_between(part, find_item['ip_between'][0], find_item['ip_between'][1])
                if not (ip and user):
                    continue
                # IPv6 ? - use /64
                if ip.count(':') > 4:
                    ip = ':'.join(ip.split(':')[:4]) + '::/64'
                backend = find_item['backend']

                self.db_cursor.execute('INSERT INTO journal (timestamp, ip, username, backend) VALUES (?, ?, ?, ?)', (timestamp, ip, user, backend))
                self.db_conn.commit()

    def read_db_to_dict(self):
        """Read records from database to dictionary for easier processing"""

        for qq in self.db_cursor.execute(QUERY):
            ip, username, count = qq
            if not self.records.get(ip):
                self.records[ip] = list()
            self.records[ip].append((username, count))

    def create_f2b_whitelist(self):
        """Create file with ignore ip list for fail2ban."""

        rec_keys = list(self.records.keys())
        rec_keys.sort()

        # Use IPs with at least 2 users or individuals with more than 2 logins
        keys_reduced = list()
        for key in rec_keys:
            if len(self.records[key]) > 1:
                keys_reduced.append(key)
            elif self.records[key][0][1] > 2:
                keys_reduced.append(key)

        self.ignores = f'\n\n[DEFAULT]\n\nignoreip_local =\n'
        # Write maximally 10 IPs in one line
        nl = 0
        for nl in range(0, len(keys_reduced)//10):
            s = nl * 10
            e = s + 10
            self.ignores += f'                 {" ".join(keys_reduced[s:e])} \n'
        if len(keys_reduced) <= 10:
            s = 0
        else:
            s = (nl + 1) * 10
        if s <= len(keys_reduced):
            self.ignores += f'                 {" ".join(keys_reduced[s:])} \n'
        self.ignores +=  f'# IPs count: {len(keys_reduced)}\n'

    def create_f2b_comments(self):
        """Create comments text explaining why IPs are in ignore list."""

        rec_keys = list(self.records.keys())
        rec_keys.sort()

        self.comments = "# File generated from script /usr/local/bin/gn_f2b_whitelist_sqlite.py\n"
        self.comments += "# Check and copy IP adresses to gn-ignoreip.local.\n\n"
        self.comments += "# Hard whitelist\n\n"
        for key in rec_keys:
            if len(self.records[key]) > 3:
                self.comments += f'    # {key:25} - {whois_bits(key)} - {len(self.records[key]):2} {str(self.records[key])}\n'
        self.comments += "\n\n# soft whitelist\n\n"
        for key in rec_keys:
            if len(self.records[key]) > 1 and len(self.records[key]) <= 3 :
                self.comments += f'    # {key:25} - {whois_bits(key)} - {str(self.records[key])}\n'
        self.comments += "\n\n# individuals whitelist\n\n"
        for key in rec_keys:
            if len(self.records[key]) == 1 and self.records[key][0][1] >= 3:
                self.comments += f'    # {key:25} - {whois_bits(key)} - {self.records[key]}\n'
        self.comments += "\n\n# not used IPs to whitelist\n\n"
        for key in rec_keys:
            if len(self.records[key]) <= 1 and self.records[key][0][1] < 3:
                self.comments += f'    # {key:25} - {whois_bits(key)} - {self.records[key]}\n'

    def write_f2b_whitelist(self):
        """Save created comments and ignoreIPs settings to draft file."""

        # Backup existing file
        if Path(IGNORE_DRAFT_FNAME).exists():
            Path(IGNORE_DRAFT_FNAME).rename(f'{IGNORE_DRAFT_FNAME}.bak')

        with open(IGNORE_DRAFT_FNAME, 'w') as file:
            file.write(self.comments)
            file.write(self.ignores)

    def db_empty(self):
        """Delete all records form database - for debugging purposes only."""

        self.db_cursor.execute('DELETE FROM journal')
        self.db_conn.commit()

    def db_delete_old_records(self):

        delete_until = datetime.now() - timedelta(days=RECORDS_MAX_AGE)
        self.db_conn.execute('DELETE FROM journal WHERE timestamp < ?', (delete_until.strftime('%Y-%m-%dT%H:%M:%S'), ))
        self.db_conn.commit()


if __name__ == '__main__':

    wl = Whitelist()
    wl.db_delete_old_records()
    wl.process_new_log_records()
    wl.read_db_to_dict()
    wl.create_f2b_comments()
    wl.create_f2b_whitelist()
    wl.write_f2b_whitelist()
