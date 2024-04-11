# fail2ban auto whitelist

Automatic whitelist for fail2ban composed from successful logins.

## Why

Sometimes happens that we delete user account on mail server but admin forget
to delete this accout from mail client.

Mail client attempts to login into non-existent accout which reslutl in BAN IP by fail2ban.

Other users from this IP are cut off from their mail because they are not able to login.

## How does it work

- log login attempts in postfix/submission or imap-login into own log
- logrotate weekly
- run gn_f2b_whitelist_sqlite.py during logrotate and create draft file for fail2ban with ignore IPs

## installation

Copy:

- gh_f2b_whitelist_sqlite.py into /usr/local/bin/
- rsyslogd.d/gn_f2b_mail.conf into /etc/rsyslog.d/
- logrotate.d/gn_f2b_mail into /etc/logrotate.d

Restart logrotate and rsyslog services.

## Work Flow in detail

Rsyslog config file creates log file /var/log/gn_f2b_mail.log with imap and submission logins.

This log is read by gn_f2b_whitelist_sqlite.py script which:

- updates sqlite3 database saved in fail2ban/jail.d/gn_whitelist.db
- creates file gn-ignoreip.draft in jail.d/ directory.

This draft file conatains IP adresses suitable for whitelisting.
Draft file also contains comments explaining why particular IP was selected for whtielisting.

You can copy/paste IP list into your ignoreip.local config file. It is not done automatically.
Script provides a draft. It's up to you decide if IP list is OK for you.

## Whitelisting conditions

IP is taken as suitable if it filfull these conditions:

- Hard whitelist - IP is used by at least 3 users.
- Soft whitelist - IP is used by 2 users.
- Inidviduals - IP is used by 1 user with at least 3 sucessful logins

There is also part in draft file with IPs which didn't pass these conditions.
