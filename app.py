#!/usr/bin/env python3
"""
Mail Tester - A mail-tester.com analog
Generates dynamic email addresses, receives emails via SMTP, and analyzes them.
"""

import asyncio
import uuid
import json
import socket
import re
import os
import ssl
import smtplib
import aiohttp
from datetime import datetime, timedelta
from email import policy
from email.parser import BytesParser
from threading import Thread
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

from flask import Flask, render_template, jsonify, request
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP as SMTPServer
from pymongo import MongoClient
import requests
from requests.auth import HTTPBasicAuth
try:
    from requests_ntlm import HttpNtlmAuth
    NTLM_AVAILABLE = True
except ImportError:
    NTLM_AVAILABLE = False
import xml.etree.ElementTree as ET

# Try to import optional analysis libraries
try:
    import dns.resolver
    import dns.query
    import dns.message
    import dns.rdatatype
    import dns.name
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import dkim
    DKIM_AVAILABLE = True
except ImportError:
    DKIM_AVAILABLE = False


def create_resolver(use_cache=False):
    """Create a DNS resolver with optional caching disabled."""
    resolver = dns.resolver.Resolver()
    resolver.cache = dns.resolver.Cache() if use_cache else dns.resolver.LRUCache(0)
    resolver.lifetime = 10  # 10 second timeout
    return resolver


def get_authoritative_nameservers(domain):
    """Get the authoritative nameservers for a domain."""
    try:
        resolver = create_resolver()
        # Get the zone's NS records
        # First try to get NS for the exact domain
        try:
            ns_answers = resolver.resolve(domain, 'NS')
            nameservers = []
            for ns in ns_answers:
                ns_name = str(ns.target).rstrip('.')
                try:
                    # Resolve NS to IP
                    a_answers = resolver.resolve(ns_name, 'A')
                    for a in a_answers:
                        nameservers.append({'name': ns_name, 'ip': str(a)})
                        break  # Just need one IP per NS
                except:
                    pass
            return nameservers
        except dns.resolver.NoAnswer:
            # Try parent domain
            parts = domain.split('.')
            if len(parts) > 2:
                parent = '.'.join(parts[1:])
                return get_authoritative_nameservers(parent)
        except dns.resolver.NXDOMAIN:
            return []
    except Exception as e:
        print(f"[DNS] Error getting authoritative NS: {e}")
        return []
    return []


def query_authoritative(domain, rdtype, nameserver_ip):
    """Query a specific nameserver directly for DNS records."""
    try:
        qname = dns.name.from_text(domain)
        request = dns.message.make_query(qname, rdtype)
        response = dns.query.udp(request, nameserver_ip, timeout=5)

        records = []
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.from_text(rdtype):
                for rdata in rrset:
                    records.append({
                        'value': str(rdata),
                        'ttl': rrset.ttl
                    })
        return records
    except Exception as e:
        return {'error': str(e)}


def compare_dns_results(public_records, auth_records):
    """Compare public DNS results with authoritative NS results."""
    differences = []

    # Normalize records for comparison
    def normalize(records):
        if isinstance(records, dict) and 'error' in records:
            return set()
        return set(r.get('value', r.get('host', r.get('ip', str(r)))) for r in records if isinstance(r, dict))

    public_set = normalize(public_records) if public_records else set()
    auth_set = normalize(auth_records) if auth_records else set()

    only_in_public = public_set - auth_set
    only_in_auth = auth_set - public_set

    if only_in_public:
        differences.append({
            'type': 'public_only',
            'message': 'Records in public DNS but not in authoritative NS',
            'records': list(only_in_public)
        })

    if only_in_auth:
        differences.append({
            'type': 'auth_only',
            'message': 'Records in authoritative NS but not in public DNS (propagation pending)',
            'records': list(only_in_auth)
        })

    return differences

# Configuration from environment variables
SMTP_PORT = int(os.environ.get('SMTP_PORT', 25))
WEB_PORT = int(os.environ.get('WEB_PORT', 5000))
DOMAIN = os.environ.get('DOMAIN', 'localhost')

# Telegram notification configuration (optional - set via environment variables)
TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '')

# MongoDB configuration
MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/')
try:
    mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    mongo_client.server_info()  # Test connection
    db = mongo_client.mxlab
    reports_collection = db.reports
    MONGO_AVAILABLE = True
    print(f"[MONGO] Connected to MongoDB at {MONGO_URI}")
except Exception as e:
    MONGO_AVAILABLE = False
    reports_collection = None
    print(f"[MONGO] MongoDB not available: {e}")


async def send_telegram_notification(test_id, email_data, analysis):
    """Send silent notification to Telegram about received email."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return  # Telegram notifications disabled
    try:
        score = analysis.get('score', 0)
        sender = email_data.get('from', 'Unknown')
        subject = email_data.get('subject', '(No Subject)')
        peer = email_data.get('peer', [])
        sender_ip = peer[0] if peer else 'Unknown'
        sender_port = peer[1] if len(peer) > 1 else ''

        # Emoji based on score
        if score >= 9:
            emoji = "✅"
            status = "EXCELLENT"
        elif score >= 7:
            emoji = "👍"
            status = "GOOD"
        elif score >= 5:
            emoji = "⚠️"
            status = "FAIR"
        else:
            emoji = "❌"
            status = "POOR"

        # Count headers
        headers = email_data.get('headers', {})
        headers_count = len(headers)

        message = f"""{emoji} <b>MXtest Email Analysis</b>

<b>Score:</b> {score:.1f}/10 — {status}
<b>From:</b> <code>{sender}</code>
<b>Subject:</b> {subject}
<b>Sender IP:</b> <code>{sender_ip}</code>{f' (port {sender_port})' if sender_port else ''}
<b>Headers:</b> {headers_count} headers captured

🔗 <a href="https://{DOMAIN}/report/{test_id}">View Full Report</a>
<i>(includes headers + raw message)</i>"""

        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            'chat_id': TELEGRAM_CHAT_ID,
            'text': message,
            'parse_mode': 'HTML',
            'disable_notification': True,
            'disable_web_page_preview': True
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload) as response:
                if response.status == 200:
                    print(f"[TELEGRAM] Notification sent for test_id: {test_id}")
                else:
                    print(f"[TELEGRAM] Failed to send notification: {response.status}")
    except Exception as e:
        print(f"[TELEGRAM] Error sending notification: {e}")


async def send_telegram_report_notification(domain, summary, client_ip, report_id=None):
    """Send silent notification to Telegram about MXlab Lookup."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return  # Telegram notifications disabled
    try:
        score = summary.get('score', 0)
        passed = summary.get('passed', 0)
        warnings = summary.get('warnings', 0)
        errors = summary.get('errors', 0)

        # Emoji and status based on score
        if score >= 90:
            emoji = "✅"
            status = "EXCELLENT"
        elif score >= 75:
            emoji = "👍"
            status = "GOOD"
        elif score >= 60:
            emoji = "👌"
            status = "FAIR"
        elif score >= 40:
            emoji = "⚠️"
            status = "POOR"
        else:
            emoji = "❌"
            status = "CRITICAL"

        message = f"""{emoji} <b>MXlab Domain Report</b>

<b>Domain:</b> <code>{domain}</code>
<b>Score:</b> {score}/100 — {status}
<b>Results:</b> ✅ {passed} | ⚠️ {warnings} | ❌ {errors}
<b>Client IP:</b> <code>{client_ip}</code>"""

        if report_id:
            message += f"\n\n🔗 <a href=\"https://{DOMAIN}/report/{report_id}\">View Report</a>"

        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            'chat_id': TELEGRAM_CHAT_ID,
            'text': message,
            'parse_mode': 'HTML',
            'disable_notification': True,
            'disable_web_page_preview': True
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload) as response:
                if response.status == 200:
                    print(f"[TELEGRAM] Report notification sent for domain: {domain}")
                else:
                    print(f"[TELEGRAM] Failed to send report notification: {response.status}")
    except Exception as e:
        print(f"[TELEGRAM] Error sending report notification: {e}")

# Storage for emails and test addresses
emails_store = {}  # {test_id: {email_data, analysis, timestamp}}
test_addresses = {}  # {test_id: {email, created, expires}}

# Thread pool for async operations
executor = ThreadPoolExecutor(max_workers=10)

# RFC Tips and References
RFC_TIPS = {
    'mx': {
        'rfc': 'RFC 5321',
        'title': 'Simple Mail Transfer Protocol',
        'tip': 'MX records specify mail servers for your domain. Without MX records, mail servers will fall back to A records.',
        'fix': 'Add MX records pointing to your mail server(s) with appropriate priorities (lower = higher priority).'
    },
    'spf': {
        'rfc': 'RFC 7208',
        'title': 'Sender Policy Framework (SPF)',
        'tip': 'SPF allows domain owners to specify which mail servers are authorized to send email on behalf of their domain.',
        'fix': 'Add a TXT record starting with "v=spf1" listing authorized sending IPs/domains. End with "-all" (hard fail) or "~all" (soft fail).'
    },
    'dkim': {
        'rfc': 'RFC 6376',
        'title': 'DomainKeys Identified Mail (DKIM)',
        'tip': 'DKIM adds a digital signature to emails that receiving servers can verify using DNS public key.',
        'fix': 'Configure your mail server to sign outgoing emails and publish the public key as a TXT record at selector._domainkey.domain.'
    },
    'dmarc': {
        'rfc': 'RFC 7489',
        'title': 'Domain-based Message Authentication (DMARC)',
        'tip': 'DMARC builds on SPF and DKIM, telling receivers how to handle authentication failures.',
        'fix': 'Add a TXT record at _dmarc.domain with policy (p=none/quarantine/reject) and reporting addresses (rua/ruf).'
    },
    'ptr': {
        'rfc': 'RFC 1912',
        'title': 'Reverse DNS (PTR Record)',
        'tip': 'PTR records map IP addresses to hostnames. Many mail servers reject mail from IPs without valid PTR.',
        'fix': 'Contact your ISP/hosting provider to set up reverse DNS for your mail server IP.'
    },
    'a': {
        'rfc': 'RFC 1035',
        'title': 'Domain Names - A Records',
        'tip': 'A records map domain names to IPv4 addresses.',
        'fix': 'Add A records pointing your domain/subdomain to the correct IP address.'
    },
    'aaaa': {
        'rfc': 'RFC 3596',
        'title': 'DNS Extensions for IPv6 (AAAA)',
        'tip': 'AAAA records map domain names to IPv6 addresses for dual-stack connectivity.',
        'fix': 'Add AAAA records if your server supports IPv6. Not mandatory but recommended.'
    },
    'ns': {
        'rfc': 'RFC 1035',
        'title': 'Name Server Records',
        'tip': 'NS records delegate a DNS zone to authoritative name servers.',
        'fix': 'Ensure NS records point to reliable, geographically distributed name servers.'
    },
    'smtp': {
        'rfc': 'RFC 5321',
        'title': 'SMTP Protocol',
        'tip': 'SMTP servers should respond to EHLO/HELO commands, support standard ports (25, 587, 465), and NOT be open relays.',
        'fix': 'Ensure your mail server is accessible on port 25, responds to EHLO, has valid SSL/TLS on port 465/587, and rejects relay attempts from unauthorized senders.'
    },
    'open_relay': {
        'rfc': 'RFC 5321 Section 7.1',
        'title': 'Open Mail Relay',
        'tip': 'An open relay allows anyone to send email through your server, which will be abused by spammers and get your IP blacklisted.',
        'fix': 'Configure your mail server to require authentication or only accept mail for local domains. Check Postfix: smtpd_relay_restrictions, Sendmail: relay-domains, Exchange: receive connectors.'
    },
    'starttls': {
        'rfc': 'RFC 3207',
        'title': 'SMTP STARTTLS Extension',
        'tip': 'STARTTLS upgrades plain SMTP connections to encrypted TLS.',
        'fix': 'Configure your mail server to advertise and support STARTTLS on port 25 and 587.'
    },
    'autodiscover': {
        'rfc': 'MS-OXDSCLI',
        'title': 'Outlook Autodiscover',
        'tip': 'Autodiscover helps email clients automatically configure account settings.',
        'fix': 'Configure autodiscover.domain.com or SRV record _autodiscover._tcp.domain pointing to your autodiscover service.'
    },
    'blacklist': {
        'rfc': 'RFC 5782',
        'title': 'DNS-Based Blacklists',
        'tip': 'Being listed on blacklists causes email delivery failures.',
        'fix': 'Check each blacklist for delisting procedures. Fix underlying issues (spam, open relay, compromised accounts).'
    },
    'headers': {
        'rfc': 'RFC 5322',
        'title': 'Internet Message Format',
        'tip': 'Email headers must include From, To, Date, and Message-ID for proper delivery.',
        'fix': 'Ensure your mail server adds all required headers with correct formatting.'
    }
}

app = Flask(__name__)


def generate_test_id():
    """Generate a unique test ID."""
    return uuid.uuid4().hex[:12]


def get_hostname():
    """Get the server hostname from DOMAIN env var."""
    return DOMAIN


class MailHandler:
    """Handle incoming emails."""

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        """Validate recipient address."""
        # Extract test_id from email address (format: test_id@domain)
        local_part = address.split('@')[0]
        if local_part in test_addresses:
            envelope.rcpt_tos.append(address)
            return '250 OK'
        # Accept all emails for testing purposes
        envelope.rcpt_tos.append(address)
        return '250 OK'

    async def handle_DATA(self, server, session, envelope):
        """Process received email."""
        test_id = None

        # Extract test_id from recipient
        for rcpt in envelope.rcpt_tos:
            local_part = rcpt.split('@')[0]
            if local_part in test_addresses or len(local_part) == 12:
                test_id = local_part
                break

        if not test_id:
            test_id = generate_test_id()

        # Parse email
        parser = BytesParser(policy=policy.default)
        msg = parser.parsebytes(envelope.content)

        # Extract email data
        email_data = {
            'from': envelope.mail_from,
            'to': envelope.rcpt_tos,
            'subject': msg.get('Subject', '(No Subject)'),
            'date': msg.get('Date', ''),
            'message_id': msg.get('Message-ID', ''),
            'headers': dict(msg.items()),
            'body_plain': '',
            'body_html': '',
            'raw': envelope.content.decode('utf-8', errors='replace'),
            'peer': session.peer,
            'received_at': datetime.now().isoformat(),
        }

        # Extract body
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == 'text/plain':
                    email_data['body_plain'] = part.get_content()
                elif content_type == 'text/html':
                    email_data['body_html'] = part.get_content()
        else:
            content_type = msg.get_content_type()
            content = msg.get_content()
            if content_type == 'text/html':
                email_data['body_html'] = content
            else:
                email_data['body_plain'] = content

        # Perform analysis
        analysis = await analyze_email(envelope, msg, session)

        # Store email and analysis
        emails_store[test_id] = {
            'email': email_data,
            'analysis': analysis,
            'timestamp': datetime.now().isoformat()
        }

        # Persist to MongoDB
        if MONGO_AVAILABLE and reports_collection is not None:
            try:
                reports_collection.update_one(
                    {'_id': test_id},
                    {'$set': {
                        'email': email_data,
                        'analysis': analysis,
                        'timestamp': datetime.now(),
                        'type': 'email_test'
                    }},
                    upsert=True
                )
                print(f"[MONGO] Saved report for test_id: {test_id}")
            except Exception as e:
                print(f"[MONGO] Error saving report: {e}")

        print(f"[SMTP] Received email for test_id: {test_id}")

        # Send async Telegram notification (non-blocking)
        asyncio.create_task(send_telegram_notification(test_id, email_data, analysis))

        return '250 Message accepted for delivery'


async def analyze_email(envelope, msg, session):
    """Analyze email for deliverability factors."""
    analysis = {
        'score': 10.0,  # Start with perfect score
        'checks': [],
        'warnings': [],
        'errors': []
    }

    sender_domain = envelope.mail_from.split('@')[-1] if '@' in envelope.mail_from else ''

    # 1. Check basic headers
    required_headers = ['From', 'To', 'Subject', 'Date', 'Message-ID']
    for header in required_headers:
        if msg.get(header):
            analysis['checks'].append({
                'name': f'{header} Header',
                'status': 'pass',
                'message': f'{header} header is present'
            })
        else:
            analysis['score'] -= 0.5
            analysis['warnings'].append(f'Missing {header} header')
            analysis['checks'].append({
                'name': f'{header} Header',
                'status': 'warning',
                'message': f'{header} header is missing'
            })

    # 2. Check SPF (if DNS available)
    if DNS_AVAILABLE and sender_domain:
        spf_result = await check_spf(sender_domain, session.peer[0])
        analysis['checks'].append(spf_result)
        if spf_result['status'] == 'fail':
            analysis['score'] -= 2.0
            analysis['errors'].append('SPF check failed')
        elif spf_result['status'] == 'warning':
            analysis['score'] -= 1.0
            analysis['warnings'].append('SPF record not found')

    # 3. Check DKIM
    dkim_result = check_dkim(envelope.content, msg)
    analysis['checks'].append(dkim_result)
    if dkim_result['status'] == 'fail':
        analysis['score'] -= 2.0
        analysis['errors'].append('DKIM verification failed')
    elif dkim_result['status'] == 'warning':
        analysis['score'] -= 1.0
        analysis['warnings'].append('No DKIM signature found')

    # 4. Check DMARC (if DNS available)
    if DNS_AVAILABLE and sender_domain:
        dmarc_result = await check_dmarc(sender_domain)
        analysis['checks'].append(dmarc_result)
        if dmarc_result['status'] == 'warning':
            analysis['score'] -= 0.5
            analysis['warnings'].append('No DMARC record found')

    # 5. Check reverse DNS
    if session.peer:
        rdns_result = await check_reverse_dns(session.peer[0])
        analysis['checks'].append(rdns_result)
        if rdns_result['status'] == 'fail':
            analysis['score'] -= 1.0
            analysis['warnings'].append('No reverse DNS for sender IP')

    # 6. Check for spam-like content
    spam_check = check_spam_content(msg)
    analysis['checks'].append(spam_check)
    if spam_check['status'] == 'warning':
        analysis['score'] -= spam_check.get('deduction', 0.5)
        analysis['warnings'].append('Potential spam indicators found')

    # 7. Check HTML/Plain text ratio
    html_check = check_html_content(msg)
    analysis['checks'].append(html_check)
    if html_check['status'] == 'warning':
        analysis['score'] -= 0.5
        analysis['warnings'].append(html_check['message'])

    # 8. Check for internal IP leaks in headers
    ip_leak_check = check_internal_ips(msg)
    analysis['checks'].append(ip_leak_check)
    if ip_leak_check['status'] == 'warning':
        analysis['score'] -= ip_leak_check.get('deduction', 0.5)
        analysis['warnings'].append('Internal IP addresses exposed in headers')

    # 9. Check for obsolete server versions
    version_check = check_server_versions(msg)
    analysis['checks'].append(version_check)
    if version_check['status'] == 'warning':
        analysis['score'] -= version_check.get('deduction', 0.5)
        analysis['warnings'].append('Outdated mail software detected')

    # Ensure score doesn't go below 0
    analysis['score'] = max(0, analysis['score'])

    return analysis


async def check_spf(domain, sender_ip):
    """Check SPF record for the sender domain."""
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        spf_record = None
        for rdata in answers:
            txt = str(rdata).strip('"')
            if txt.startswith('v=spf1'):
                spf_record = txt
                break

        if spf_record:
            return {
                'name': 'SPF Record',
                'status': 'pass',
                'message': f'SPF record found',
                'record': spf_record
            }
        else:
            return {
                'name': 'SPF Record',
                'status': 'warning',
                'message': 'No SPF record found for sender domain'
            }
    except Exception as e:
        return {
            'name': 'SPF Record',
            'status': 'warning',
            'message': f'Could not check SPF: {str(e)}'
        }


def check_dkim(raw_email, msg):
    """Check DKIM signature."""
    dkim_header = msg.get('DKIM-Signature')

    if not dkim_header:
        return {
            'name': 'DKIM Signature',
            'status': 'warning',
            'message': 'No DKIM signature found'
        }

    if DKIM_AVAILABLE:
        try:
            valid = dkim.verify(raw_email)
            if valid:
                return {
                    'name': 'DKIM Signature',
                    'status': 'pass',
                    'message': 'DKIM signature is valid',
                    'record': dkim_header[:100] + '...' if len(dkim_header) > 100 else dkim_header
                }
            else:
                return {
                    'name': 'DKIM Signature',
                    'status': 'fail',
                    'message': 'DKIM signature verification failed',
                    'record': dkim_header[:100] + '...' if len(dkim_header) > 100 else dkim_header
                }
        except Exception as e:
            return {
                'name': 'DKIM Signature',
                'status': 'warning',
                'message': f'Could not verify DKIM: {str(e)}'
            }
    else:
        return {
            'name': 'DKIM Signature',
            'status': 'pass',
            'message': 'DKIM signature present (verification library not available)',
            'record': dkim_header[:100] + '...' if len(dkim_header) > 100 else dkim_header
        }


async def check_dmarc(domain):
    """Check DMARC record for the sender domain."""
    try:
        dmarc_domain = f'_dmarc.{domain}'
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')

        for rdata in answers:
            txt = str(rdata).strip('"')
            if txt.startswith('v=DMARC1'):
                return {
                    'name': 'DMARC Record',
                    'status': 'pass',
                    'message': 'DMARC record found',
                    'record': txt
                }

        return {
            'name': 'DMARC Record',
            'status': 'warning',
            'message': 'No DMARC record found'
        }
    except Exception as e:
        return {
            'name': 'DMARC Record',
            'status': 'warning',
            'message': 'No DMARC record found'
        }


async def check_reverse_dns(ip):
    """Check reverse DNS for sender IP."""
    try:
        hostname = socket.gethostbyaddr(ip)
        return {
            'name': 'Reverse DNS',
            'status': 'pass',
            'record': hostname[0],
            'message': f'Reverse DNS: {hostname[0]}'
        }
    except:
        return {
            'name': 'Reverse DNS',
            'status': 'fail',
            'message': 'No reverse DNS found for sender IP'
        }


def check_spam_content(msg):
    """Check for spam-like content."""
    spam_indicators = []
    subject = msg.get('Subject', '')
    body = ''

    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                try:
                    body = part.get_content()
                except:
                    pass
                break
    else:
        try:
            body = msg.get_content()
        except:
            pass

    content = f"{subject} {body}".lower()

    # Common spam words
    spam_words = ['free', 'winner', 'congratulations', 'urgent', 'act now',
                  'limited time', 'click here', 'unsubscribe', 'buy now']

    found_words = [word for word in spam_words if word in content]

    if found_words:
        return {
            'name': 'Spam Content Check',
            'status': 'warning',
            'message': f'Found spam indicators: {", ".join(found_words[:3])}',
            'deduction': min(len(found_words) * 0.3, 1.5)
        }

    return {
        'name': 'Spam Content Check',
        'status': 'pass',
        'message': 'No obvious spam indicators found'
    }


def check_html_content(msg):
    """Check HTML content quality."""
    has_html = False
    has_plain = False

    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                has_plain = True
            elif part.get_content_type() == 'text/html':
                has_html = True
    else:
        content_type = msg.get_content_type()
        has_plain = content_type == 'text/plain'
        has_html = content_type == 'text/html'

    if has_html and not has_plain:
        return {
            'name': 'HTML/Plain Text',
            'status': 'warning',
            'message': 'HTML email without plain text alternative'
        }
    elif has_html and has_plain:
        return {
            'name': 'HTML/Plain Text',
            'status': 'pass',
            'message': 'Both HTML and plain text versions present'
        }
    else:
        return {
            'name': 'HTML/Plain Text',
            'status': 'pass',
            'message': 'Plain text email'
        }


def check_internal_ips(msg):
    """Check for internal/private IP addresses leaked in headers."""
    import re

    # Private IP ranges (RFC 1918 + link-local + loopback)
    private_ip_patterns = [
        r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}',           # 10.0.0.0/8
        r'172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}',  # 172.16.0.0/12
        r'192\.168\.\d{1,3}\.\d{1,3}',               # 192.168.0.0/16
        r'127\.\d{1,3}\.\d{1,3}\.\d{1,3}',           # 127.0.0.0/8 (loopback)
        r'169\.254\.\d{1,3}\.\d{1,3}',               # 169.254.0.0/16 (link-local)
    ]
    combined_pattern = '|'.join(f'({p})' for p in private_ip_patterns)

    found_ips = []
    headers_with_ips = []

    # Check Received headers (most common place for IP leaks)
    received_headers = msg.get_all('Received', [])
    for i, header in enumerate(received_headers):
        matches = re.findall(combined_pattern, str(header))
        for match in matches:
            ip = [m for m in match if m][0]  # Get the matched group
            if ip not in found_ips:
                found_ips.append(ip)
                headers_with_ips.append(f'Received[{i}]')

    # Check X-Originating-IP
    orig_ip = msg.get('X-Originating-IP', '')
    matches = re.findall(combined_pattern, str(orig_ip))
    if matches:
        for match in matches:
            ip = [m for m in match if m][0]
            if ip not in found_ips:
                found_ips.append(ip)
                headers_with_ips.append('X-Originating-IP')

    # Check X-Sender-IP
    sender_ip = msg.get('X-Sender-IP', '')
    matches = re.findall(combined_pattern, str(sender_ip))
    if matches:
        for match in matches:
            ip = [m for m in match if m][0]
            if ip not in found_ips:
                found_ips.append(ip)
                headers_with_ips.append('X-Sender-IP')

    if found_ips:
        return {
            'name': 'Internal IP Leak',
            'status': 'warning',
            'message': f'Internal IPs exposed: {", ".join(found_ips[:3])}',
            'details': {
                'ips': found_ips,
                'headers': headers_with_ips
            },
            'deduction': 0.5
        }

    return {
        'name': 'Internal IP Leak',
        'status': 'pass',
        'message': 'No internal IP addresses exposed in headers'
    }


def check_server_versions(msg):
    """Check for obsolete or vulnerable mail server versions in headers."""
    import re

    issues = []
    info = []

    # Known obsolete/vulnerable software patterns
    obsolete_patterns = {
        # Microsoft Exchange versions
        r'Microsoft-Server-ActiveSync/(\d+\.\d+)': ('Exchange ActiveSync', '15.0', 'Exchange 2010 or older'),
        r'Microsoft Exchange Server (\d+)': ('Exchange', '2016', 'Exchange 2013 or older'),
        r'Microsoft SMTP Server.*?(\d+\.\d+\.\d+)': ('MS SMTP', '15.0.0', 'Old Microsoft SMTP'),

        # Postfix
        r'Postfix.*?(\d+\.\d+\.\d+)': ('Postfix', '3.5.0', 'Postfix < 3.5'),

        # Sendmail
        r'Sendmail.*?(\d+\.\d+\.\d+)': ('Sendmail', '8.16.0', 'Sendmail < 8.16'),

        # Exim
        r'Exim (\d+\.\d+)': ('Exim', '4.94', 'Exim < 4.94'),

        # Microsoft Outlook
        r'Microsoft Outlook (\d+\.\d+)': ('Outlook', '16.0', 'Outlook 2013 or older'),
        r'Microsoft Office Outlook (\d+\.\d+)': ('Outlook', '16.0', 'Outlook 2013 or older'),

        # Old webmail
        r'Roundcube Webmail/(\d+\.\d+)': ('Roundcube', '1.5', 'Roundcube < 1.5'),
    }

    # Headers to check for version info
    headers_to_check = [
        'Received',
        'X-Mailer',
        'X-MimeOLE',
        'User-Agent',
        'X-Originating-Server',
        'X-MS-Exchange-Organization',
        'X-Mailer-Version',
    ]

    # Collect all header values
    all_header_content = []
    for header_name in headers_to_check:
        values = msg.get_all(header_name, [])
        for v in values:
            all_header_content.append((header_name, str(v)))

    # Also check single-value headers
    for header_name in ['X-Mailer', 'X-MimeOLE', 'User-Agent']:
        val = msg.get(header_name)
        if val:
            all_header_content.append((header_name, str(val)))

    # Check for obsolete versions
    for header_name, content in all_header_content:
        for pattern, (software, min_version, warning_msg) in obsolete_patterns.items():
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                found_version = match.group(1)
                info.append(f'{software} {found_version}')
                # Simple version comparison (works for most cases)
                try:
                    found_parts = [int(x) for x in found_version.split('.')[:2]]
                    min_parts = [int(x) for x in min_version.split('.')[:2]]
                    if found_parts < min_parts:
                        issues.append({
                            'software': software,
                            'version': found_version,
                            'header': header_name,
                            'issue': warning_msg
                        })
                except:
                    pass

    # Check for X-Mailer presence (detect client)
    x_mailer = msg.get('X-Mailer', '')
    if x_mailer and x_mailer not in [i for i in info]:
        info.append(f'X-Mailer: {x_mailer[:50]}')

    # Check for generic old Microsoft indicators
    x_mimeole = msg.get('X-MimeOLE', '')
    if x_mimeole:
        if 'Microsoft MimeOLE' in x_mimeole:
            # Very old Outlook Express / Windows Mail
            issues.append({
                'software': 'MimeOLE',
                'version': x_mimeole,
                'header': 'X-MimeOLE',
                'issue': 'Very old email client (Outlook Express era)'
            })

    if issues:
        issue_msgs = [f"{i['software']}: {i['issue']}" for i in issues[:2]]
        return {
            'name': 'Server Version Check',
            'status': 'warning',
            'message': f'Outdated software: {"; ".join(issue_msgs)}',
            'details': {
                'issues': issues,
                'detected': info
            },
            'deduction': 0.5
        }

    if info:
        return {
            'name': 'Server Version Check',
            'status': 'pass',
            'message': f'Mail software: {", ".join(info[:2])}',
            'details': {'detected': info}
        }

    return {
        'name': 'Server Version Check',
        'status': 'pass',
        'message': 'No version information detected in headers'
    }


# Flask Routes

@app.route('/')
def index():
    """Render main page."""
    return render_template('index.html')


@app.route('/api/generate', methods=['POST'])
def generate_address():
    """Generate a new test email address."""
    test_id = generate_test_id()
    hostname = get_hostname()
    email = f"{test_id}@{hostname}"

    test_addresses[test_id] = {
        'email': email,
        'created': datetime.now().isoformat(),
        'expires': (datetime.now() + timedelta(hours=24)).isoformat()
    }

    return jsonify({
        'test_id': test_id,
        'email': email,
        'smtp_port': SMTP_PORT,
        'instructions': f'Send an email to {email} using SMTP port {SMTP_PORT}'
    })


@app.route('/api/check/<test_id>')
def check_email(test_id):
    """Check if email has been received and return analysis."""
    if test_id in emails_store:
        return jsonify({
            'received': True,
            'data': emails_store[test_id]
        })
    return jsonify({'received': False})


@app.route('/api/results/<test_id>')
def get_results(test_id):
    """Get full results for a test."""
    if test_id in emails_store:
        return jsonify(emails_store[test_id])
    return jsonify({'error': 'Not found'}), 404


@app.route('/report/<test_id>')
def view_report(test_id):
    """View standalone report page for a test."""
    report = None

    # Try in-memory store first
    if test_id in emails_store:
        report = emails_store[test_id]
    # Fall back to MongoDB
    elif MONGO_AVAILABLE and reports_collection is not None:
        try:
            report = reports_collection.find_one({'_id': test_id})
            if report:
                # Convert MongoDB datetime to string for template
                if isinstance(report.get('timestamp'), datetime):
                    report['timestamp'] = report['timestamp'].isoformat()
        except Exception as e:
            print(f"[MONGO] Error fetching report: {e}")

    if not report:
        return render_template('report.html', report=None, test_id=test_id, error="Report not found"), 404

    return render_template('report.html', report=report, test_id=test_id, error=None)


# MXlab Tools API endpoints

@app.route('/api/tools/<tool>')
def run_tool(tool):
    """Run a DNS lookup tool."""
    query = request.args.get('query', '').strip()

    if not query:
        return jsonify({'error': 'Query parameter is required'}), 400

    if not DNS_AVAILABLE:
        return jsonify({'error': 'DNS library not available'}), 500

    tool_handlers = {
        'mx': tool_mx_lookup,
        'dns': tool_a_lookup,
        'txt': tool_txt_lookup,
        'spf': tool_spf_lookup,
        'dkim': tool_dkim_lookup,
        'dmarc': tool_dmarc_lookup,
        'ptr': tool_ptr_lookup,
        'blacklist': tool_blacklist_check,
        'ns': tool_ns_lookup,
        'soa': tool_soa_lookup,
        'cname': tool_cname_lookup,
        'aaaa': tool_aaaa_lookup,
        'ssl': tool_ssl_check,
    }

    handler = tool_handlers.get(tool)
    if not handler:
        return jsonify({'error': f'Unknown tool: {tool}'}), 400

    try:
        result = handler(query)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def tool_mx_lookup(domain):
    """Look up MX records for a domain with IP resolution. Compares public DNS with authoritative NS."""
    resolver = create_resolver(use_cache=False)
    result = {
        'tool': 'MX Lookup',
        'query': domain,
        'status': 'error',
        'records': [],
        'authoritative': None,
        'differences': [],
        'command': f'dig {domain} MX +short'
    }

    try:
        # Query public DNS (no cache)
        answers = resolver.resolve(domain, 'MX')
        records = []
        for rdata in answers:
            mx_host = str(rdata.exchange).rstrip('.')
            record = {
                'priority': rdata.preference,
                'host': mx_host,
                'ttl': answers.rrset.ttl,
                'ips': [],
                'ipv6': []
            }
            # Resolve A records for MX host
            try:
                a_answers = resolver.resolve(mx_host, 'A')
                record['ips'] = [str(r) for r in a_answers]
            except:
                pass
            # Resolve AAAA records for MX host
            try:
                aaaa_answers = resolver.resolve(mx_host, 'AAAA')
                record['ipv6'] = [str(r) for r in aaaa_answers]
            except:
                pass
            records.append(record)
        records.sort(key=lambda x: x['priority'])
        result['records'] = records
        result['count'] = len(records)
        result['status'] = 'success'

        # Query authoritative nameservers
        auth_ns = get_authoritative_nameservers(domain)
        if auth_ns:
            result['authoritative'] = {'nameservers': auth_ns, 'records': []}
            for ns in auth_ns[:2]:  # Query first 2 NS
                auth_records = query_authoritative(domain, 'MX', ns['ip'])
                if isinstance(auth_records, list) and auth_records:
                    result['authoritative']['records'] = auth_records
                    result['authoritative']['queried_ns'] = ns['name']
                    break

            # Compare results
            if result['authoritative']['records']:
                public_hosts = [r['host'] for r in records]
                auth_hosts = [r['value'].split()[-1].rstrip('.') if ' ' in r['value'] else r['value'].rstrip('.') for r in result['authoritative']['records']]

                only_public = set(public_hosts) - set(auth_hosts)
                only_auth = set(auth_hosts) - set(public_hosts)

                if only_public or only_auth:
                    result['differences'] = []
                    if only_public:
                        result['differences'].append({
                            'type': 'public_only',
                            'message': 'In public DNS only (may be cached/outdated)',
                            'records': list(only_public)
                        })
                    if only_auth:
                        result['differences'].append({
                            'type': 'auth_only',
                            'message': 'In authoritative NS only (propagation pending)',
                            'records': list(only_auth)
                        })
                    result['status'] = 'warning'

        return result
    except dns.resolver.NXDOMAIN:
        result['message'] = 'Domain not found'
        return result
    except dns.resolver.NoAnswer:
        result['status'] = 'warning'
        result['message'] = 'No MX records found'
        return result
    except Exception as e:
        result['message'] = str(e)
        return result


def tool_a_lookup(domain):
    """Look up A records for a domain with authoritative comparison."""
    resolver = create_resolver(use_cache=False)
    result = {
        'tool': 'DNS (A) Lookup',
        'query': domain,
        'status': 'error',
        'records': [],
        'authoritative': None,
        'differences': [],
        'command': f'dig {domain} A +short'
    }

    try:
        answers = resolver.resolve(domain, 'A')
        records = [{'ip': str(rdata), 'ttl': answers.rrset.ttl} for rdata in answers]
        result['records'] = records
        result['count'] = len(records)
        result['status'] = 'success'

        # Query authoritative NS
        auth_ns = get_authoritative_nameservers(domain)
        if auth_ns:
            result['authoritative'] = {'nameservers': auth_ns, 'records': []}
            for ns in auth_ns[:2]:
                auth_records = query_authoritative(domain, 'A', ns['ip'])
                if isinstance(auth_records, list) and auth_records:
                    result['authoritative']['records'] = auth_records
                    result['authoritative']['queried_ns'] = ns['name']
                    break

            # Compare
            if result['authoritative']['records']:
                public_ips = set(r['ip'] for r in records)
                auth_ips = set(r['value'] for r in result['authoritative']['records'])
                if public_ips != auth_ips:
                    result['differences'] = []
                    only_public = public_ips - auth_ips
                    only_auth = auth_ips - public_ips
                    if only_public:
                        result['differences'].append({'type': 'public_only', 'message': 'In public DNS only', 'records': list(only_public)})
                    if only_auth:
                        result['differences'].append({'type': 'auth_only', 'message': 'In authoritative NS only', 'records': list(only_auth)})
                    result['status'] = 'warning'

        return result
    except dns.resolver.NXDOMAIN:
        result['message'] = 'Domain not found'
        return result
    except dns.resolver.NoAnswer:
        result['status'] = 'warning'
        result['message'] = 'No A records found'
        return result
    except Exception as e:
        result['message'] = str(e)
        return result


def tool_txt_lookup(domain):
    """Look up TXT records for a domain with authoritative comparison."""
    resolver = create_resolver(use_cache=False)
    result = {
        'tool': 'TXT Lookup',
        'query': domain,
        'status': 'error',
        'records': [],
        'authoritative': None,
        'differences': [],
        'command': f'dig {domain} TXT +short'
    }

    try:
        answers = resolver.resolve(domain, 'TXT')
        records = []
        for rdata in answers:
            txt_value = str(rdata).strip('"')
            records.append({'value': txt_value, 'ttl': answers.rrset.ttl})
        result['records'] = records
        result['count'] = len(records)
        result['status'] = 'success'

        # Query authoritative NS
        auth_ns = get_authoritative_nameservers(domain)
        if auth_ns:
            result['authoritative'] = {'nameservers': auth_ns, 'records': []}
            for ns in auth_ns[:2]:
                auth_records = query_authoritative(domain, 'TXT', ns['ip'])
                if isinstance(auth_records, list) and auth_records:
                    result['authoritative']['records'] = auth_records
                    result['authoritative']['queried_ns'] = ns['name']
                    break

            # Compare (normalize TXT values)
            if result['authoritative']['records']:
                public_txt = set(r['value'].replace('"', '') for r in records)
                auth_txt = set(r['value'].replace('"', '') for r in result['authoritative']['records'])
                if public_txt != auth_txt:
                    result['differences'] = []
                    only_public = public_txt - auth_txt
                    only_auth = auth_txt - public_txt
                    if only_public:
                        result['differences'].append({'type': 'public_only', 'message': 'In public DNS only', 'records': list(only_public)})
                    if only_auth:
                        result['differences'].append({'type': 'auth_only', 'message': 'In authoritative NS only', 'records': list(only_auth)})
                    result['status'] = 'warning'

        return result
    except dns.resolver.NXDOMAIN:
        result['message'] = 'Domain not found'
        return result
    except dns.resolver.NoAnswer:
        result['status'] = 'warning'
        result['message'] = 'No TXT records found'
        return result
    except Exception as e:
        result['message'] = str(e)
        return result


def tool_spf_lookup(domain, depth=0, checked_domains=None):
    """Look up SPF record for a domain with include resolution."""
    resolver = create_resolver(use_cache=False)

    if checked_domains is None:
        checked_domains = set()

    if domain in checked_domains or depth > 10:
        return None  # Prevent loops and too deep recursion

    checked_domains.add(domain)

    try:
        answers = resolver.resolve(domain, 'TXT')
        spf_records = []
        for rdata in answers:
            txt_value = str(rdata).strip('"')
            if txt_value.startswith('v=spf1'):
                parsed = parse_spf_record(txt_value)
                record = {
                    'domain': domain,
                    'value': txt_value,
                    'ttl': answers.rrset.ttl,
                    'parsed': parsed,
                    'includes': []
                }

                # Check include: directives
                for mechanism in parsed.get('mechanisms', []):
                    if mechanism.startswith('include:'):
                        include_domain = mechanism.replace('include:', '')
                        include_result = tool_spf_lookup(include_domain, depth + 1, checked_domains)
                        if include_result and include_result.get('records'):
                            record['includes'].append({
                                'domain': include_domain,
                                'record': include_result['records'][0] if include_result['records'] else None
                            })
                        else:
                            record['includes'].append({
                                'domain': include_domain,
                                'error': 'Could not resolve SPF'
                            })
                    elif mechanism.startswith('redirect='):
                        redirect_domain = mechanism.replace('redirect=', '')
                        redirect_result = tool_spf_lookup(redirect_domain, depth + 1, checked_domains)
                        if redirect_result and redirect_result.get('records'):
                            record['includes'].append({
                                'domain': redirect_domain,
                                'type': 'redirect',
                                'record': redirect_result['records'][0] if redirect_result['records'] else None
                            })

                spf_records.append(record)

        if spf_records:
            return {
                'tool': 'SPF Lookup',
                'query': domain,
                'status': 'success',
                'records': spf_records,
                'count': len(spf_records),
                'lookup_count': len(checked_domains),
                'command': f'dig {domain} TXT +short | grep spf'
            }
        else:
            return {'tool': 'SPF Lookup', 'query': domain, 'status': 'warning', 'message': 'No SPF record found'}
    except dns.resolver.NXDOMAIN:
        return {'tool': 'SPF Lookup', 'query': domain, 'status': 'error', 'message': 'Domain not found'}
    except dns.resolver.NoAnswer:
        return {'tool': 'SPF Lookup', 'query': domain, 'status': 'warning', 'message': 'No SPF record found'}
    except Exception as e:
        return {'tool': 'SPF Lookup', 'query': domain, 'status': 'error', 'message': str(e)}


def parse_spf_record(spf):
    """Parse SPF record into components."""
    parts = spf.split()
    parsed = {'version': '', 'mechanisms': [], 'modifiers': [], 'includes': [], 'all': ''}
    for part in parts:
        if part.startswith('v='):
            parsed['version'] = part
        elif part.startswith('include:'):
            parsed['includes'].append(part.replace('include:', ''))
            parsed['mechanisms'].append(part)
        elif part.endswith('all'):
            parsed['all'] = part
            parsed['mechanisms'].append(part)
        elif part.startswith('+') or part.startswith('-') or part.startswith('~') or part.startswith('?'):
            parsed['mechanisms'].append(part)
        elif '=' in part:
            parsed['modifiers'].append(part)
        else:
            parsed['mechanisms'].append(part)
    return parsed


def tool_dkim_lookup(query):
    """Look up DKIM record for a domain. Query format: selector:domain or just domain.
    When no selector specified, checks ALL common selectors and returns all found."""
    resolver = create_resolver(use_cache=False)

    if ':' in query:
        selector, domain = query.split(':', 1)
        # Single selector lookup
        dkim_domain = f'{selector}._domainkey.{domain}'
        try:
            answers = resolver.resolve(dkim_domain, 'TXT')
            records = []
            for rdata in answers:
                txt_value = str(rdata).strip('"')
                parsed = parse_dkim_record(txt_value)
                records.append({
                    'selector': selector,
                    'domain': dkim_domain,
                    'value': txt_value,
                    'ttl': answers.rrset.ttl,
                    'parsed': parsed
                })
            return {
                'tool': 'DKIM Lookup',
                'query': query,
                'status': 'success',
                'selectors_found': [selector],
                'records': records,
                'command': f'dig {dkim_domain} TXT +short'
            }
        except dns.resolver.NXDOMAIN:
            return {'tool': 'DKIM Lookup', 'query': query, 'status': 'error', 'message': f'DKIM record not found for selector "{selector}"'}
        except dns.resolver.NoAnswer:
            return {'tool': 'DKIM Lookup', 'query': query, 'status': 'warning', 'message': f'No DKIM record for selector "{selector}"'}
        except Exception as e:
            return {'tool': 'DKIM Lookup', 'query': query, 'status': 'error', 'message': str(e)}

    # No selector specified - check ALL common selectors and return all found
    domain = query
    common_selectors = [
        'default', 'google', 'selector1', 'selector2', 'k1', 'k2', 's1', 's2',
        'dkim', 'mail', 'email', 'smtp', 'mandrill', 'mailjet', 'sendgrid',
        'amazonses', 'postmark', 'mailgun', 'sparkpost', 'mailchimp', 'cm',
        'zendesk1', 'zendesk2', 'everlytickey1', 'everlytickey2', 'mxvault',
        'protonmail', 'protonmail2', 'protonmail3'
    ]

    found_records = []
    selectors_found = []
    selectors_checked = []

    for selector in common_selectors:
        dkim_domain = f'{selector}._domainkey.{domain}'
        selectors_checked.append({'selector': selector, 'domain': dkim_domain, 'found': False})
        try:
            answers = resolver.resolve(dkim_domain, 'TXT')
            for rdata in answers:
                txt_value = str(rdata).strip('"')
                if 'v=DKIM1' in txt_value or 'k=' in txt_value or 'p=' in txt_value:
                    parsed = parse_dkim_record(txt_value)
                    found_records.append({
                        'selector': selector,
                        'domain': dkim_domain,
                        'value': txt_value,
                        'ttl': answers.rrset.ttl,
                        'parsed': parsed
                    })
                    selectors_found.append(selector)
                    selectors_checked[-1]['found'] = True
        except:
            continue

    if found_records:
        return {
            'tool': 'DKIM Lookup',
            'query': query,
            'status': 'success',
            'selectors_found': selectors_found,
            'selectors_checked': selectors_checked,
            'records': found_records,
            'count': len(found_records),
            'message': f'Found {len(found_records)} DKIM record(s) with selectors: {", ".join(selectors_found)}'
        }
    else:
        return {
            'tool': 'DKIM Lookup',
            'query': query,
            'status': 'warning',
            'selectors_checked': selectors_checked,
            'records': [],
            'count': 0,
            'message': f'No DKIM records found. Checked {len(common_selectors)} common selectors. Try specifying selector:domain format.'
        }


def parse_dkim_record(dkim_txt):
    """Parse DKIM record into components."""
    parsed = {}
    # DKIM records can have semicolon-separated fields
    parts = dkim_txt.replace(' ', '').split(';')
    for part in parts:
        part = part.strip()
        if '=' in part:
            key, value = part.split('=', 1)
            parsed[key.strip()] = value.strip()
    return parsed


def tool_dmarc_lookup(domain):
    """Look up DMARC record for a domain with authoritative comparison."""
    resolver = create_resolver(use_cache=False)
    dmarc_domain = f'_dmarc.{domain}'
    result = {
        'tool': 'DMARC Lookup',
        'query': domain,
        'status': 'warning',
        'records': [],
        'authoritative': None,
        'differences': [],
        'command': f'dig _dmarc.{domain} TXT +short'
    }

    try:
        answers = resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            txt_value = str(rdata).strip('"')
            if txt_value.startswith('v=DMARC1'):
                parsed = parse_dmarc_record(txt_value)
                result['records'] = [{'value': txt_value, 'ttl': answers.rrset.ttl, 'parsed': parsed}]
                result['status'] = 'success'

                # Query authoritative NS
                auth_ns = get_authoritative_nameservers(domain)
                if auth_ns:
                    result['authoritative'] = {'nameservers': auth_ns, 'records': []}
                    for ns in auth_ns[:2]:
                        auth_records = query_authoritative(dmarc_domain, 'TXT', ns['ip'])
                        if isinstance(auth_records, list) and auth_records:
                            result['authoritative']['records'] = auth_records
                            result['authoritative']['queried_ns'] = ns['name']
                            # Check for differences
                            auth_dmarc = [r['value'].replace('"', '') for r in auth_records if 'DMARC1' in r.get('value', '')]
                            if auth_dmarc and txt_value not in auth_dmarc:
                                result['differences'] = [{'type': 'mismatch', 'message': 'DMARC record differs', 'public': txt_value, 'authoritative': auth_dmarc[0]}]
                                result['status'] = 'warning'
                            break
                return result

        result['message'] = 'No DMARC record found'
        return result
    except dns.resolver.NXDOMAIN:
        result['message'] = 'No DMARC record found'
        return result
    except dns.resolver.NoAnswer:
        result['message'] = 'No DMARC record found'
        return result
    except Exception as e:
        result['status'] = 'error'
        result['message'] = str(e)
        return result


def parse_dmarc_record(dmarc):
    """Parse DMARC record into components."""
    parsed = {}
    parts = dmarc.split(';')
    for part in parts:
        part = part.strip()
        if '=' in part:
            key, value = part.split('=', 1)
            parsed[key.strip()] = value.strip()
    return parsed


def tool_ptr_lookup(ip):
    """Reverse DNS lookup for an IP address."""
    try:
        # Validate IP format
        socket.inet_aton(ip)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return {
            'tool': 'Reverse DNS (PTR)',
            'query': ip,
            'status': 'success',
            'records': [{'hostname': hostname}],
            'command': f'dig -x {ip} +short'
        }
    except socket.herror:
        return {'tool': 'Reverse DNS (PTR)', 'query': ip, 'status': 'warning', 'message': 'No PTR record found'}
    except socket.gaierror:
        return {'tool': 'Reverse DNS (PTR)', 'query': ip, 'status': 'error', 'message': 'Invalid IP address'}
    except Exception as e:
        return {'tool': 'Reverse DNS (PTR)', 'query': ip, 'status': 'error', 'message': str(e)}


def tool_blacklist_check(ip):
    """Check if an IP is on common blacklists."""
    resolver = create_resolver(use_cache=False)

    # Common DNS blacklists
    blacklists = [
        'zen.spamhaus.org',
        'bl.spamcop.net',
        'b.barracudacentral.org',
        'dnsbl.sorbs.net',
        'spam.dnsbl.sorbs.net',
        'cbl.abuseat.org',
        'dnsbl-1.uceprotect.net',
        'psbl.surriel.com',
    ]

    try:
        socket.inet_aton(ip)
    except socket.error:
        return {'tool': 'Blacklist Check', 'query': ip, 'status': 'error', 'message': 'Invalid IP address'}

    # Reverse the IP for DNSBL lookup
    reversed_ip = '.'.join(reversed(ip.split('.')))

    results = []
    listed_count = 0

    for bl in blacklists:
        lookup = f'{reversed_ip}.{bl}'
        try:
            resolver.resolve(lookup, 'A')
            results.append({'blacklist': bl, 'listed': True})
            listed_count += 1
        except dns.resolver.NXDOMAIN:
            results.append({'blacklist': bl, 'listed': False})
        except:
            results.append({'blacklist': bl, 'listed': None, 'error': 'Lookup failed'})

    status = 'error' if listed_count > 0 else 'success'
    return {
        'tool': 'Blacklist Check',
        'query': ip,
        'status': status,
        'records': results,
        'listed_count': listed_count,
        'total_checked': len(blacklists),
        'message': f'Listed on {listed_count} of {len(blacklists)} blacklists' if listed_count > 0 else 'Not listed on any checked blacklists'
    }


def tool_ns_lookup(domain):
    """Look up NS records for a domain."""
    resolver = create_resolver(use_cache=False)
    try:
        answers = resolver.resolve(domain, 'NS')
        records = []
        for rdata in answers:
            ns_name = str(rdata).rstrip('.')
            record = {'nameserver': ns_name, 'ttl': answers.rrset.ttl, 'ips': []}
            # Resolve NS IPs
            try:
                a_answers = resolver.resolve(ns_name, 'A')
                record['ips'] = [str(a) for a in a_answers]
            except:
                pass
            records.append(record)
        return {
            'tool': 'NS Lookup',
            'query': domain,
            'status': 'success',
            'records': records,
            'count': len(records),
            'command': f'dig {domain} NS +short'
        }
    except dns.resolver.NXDOMAIN:
        return {'tool': 'NS Lookup', 'query': domain, 'status': 'error', 'message': 'Domain not found'}
    except dns.resolver.NoAnswer:
        return {'tool': 'NS Lookup', 'query': domain, 'status': 'warning', 'message': 'No NS records found'}
    except Exception as e:
        return {'tool': 'NS Lookup', 'query': domain, 'status': 'error', 'message': str(e)}


def tool_soa_lookup(domain):
    """Look up SOA record for a domain."""
    resolver = create_resolver(use_cache=False)
    try:
        answers = resolver.resolve(domain, 'SOA')
        for rdata in answers:
            return {
                'tool': 'SOA Lookup',
                'query': domain,
                'status': 'success',
                'records': [{
                    'mname': str(rdata.mname).rstrip('.'),
                    'rname': str(rdata.rname).rstrip('.'),
                    'serial': rdata.serial,
                    'refresh': rdata.refresh,
                    'retry': rdata.retry,
                    'expire': rdata.expire,
                    'minimum': rdata.minimum,
                    'ttl': answers.rrset.ttl
                }],
                'command': f'dig {domain} SOA +short'
            }
    except dns.resolver.NXDOMAIN:
        return {'tool': 'SOA Lookup', 'query': domain, 'status': 'error', 'message': 'Domain not found'}
    except dns.resolver.NoAnswer:
        return {'tool': 'SOA Lookup', 'query': domain, 'status': 'warning', 'message': 'No SOA record found'}
    except Exception as e:
        return {'tool': 'SOA Lookup', 'query': domain, 'status': 'error', 'message': str(e)}


def tool_cname_lookup(domain):
    """Look up CNAME record for a domain."""
    resolver = create_resolver(use_cache=False)
    try:
        answers = resolver.resolve(domain, 'CNAME')
        records = [{'target': str(rdata.target).rstrip('.'), 'ttl': answers.rrset.ttl} for rdata in answers]
        return {
            'tool': 'CNAME Lookup',
            'query': domain,
            'status': 'success',
            'records': records,
            'count': len(records),
            'command': f'dig {domain} CNAME +short'
        }
    except dns.resolver.NXDOMAIN:
        return {'tool': 'CNAME Lookup', 'query': domain, 'status': 'error', 'message': 'Domain not found'}
    except dns.resolver.NoAnswer:
        return {'tool': 'CNAME Lookup', 'query': domain, 'status': 'warning', 'message': 'No CNAME record found (domain may have A record instead)'}
    except Exception as e:
        return {'tool': 'CNAME Lookup', 'query': domain, 'status': 'error', 'message': str(e)}


def tool_aaaa_lookup(domain):
    """Look up AAAA (IPv6) records for a domain with authoritative comparison."""
    resolver = create_resolver(use_cache=False)
    result = {
        'tool': 'AAAA (IPv6) Lookup',
        'query': domain,
        'status': 'error',
        'records': [],
        'authoritative': None,
        'differences': [],
        'command': f'dig {domain} AAAA +short'
    }

    try:
        answers = resolver.resolve(domain, 'AAAA')
        records = [{'ip': str(rdata), 'ttl': answers.rrset.ttl} for rdata in answers]
        result['records'] = records
        result['count'] = len(records)
        result['status'] = 'success'

        # Query authoritative NS
        auth_ns = get_authoritative_nameservers(domain)
        if auth_ns:
            result['authoritative'] = {'nameservers': auth_ns, 'records': []}
            for ns in auth_ns[:2]:
                auth_records = query_authoritative(domain, 'AAAA', ns['ip'])
                if isinstance(auth_records, list) and auth_records:
                    result['authoritative']['records'] = auth_records
                    result['authoritative']['queried_ns'] = ns['name']
                    break

            # Compare
            if result['authoritative']['records']:
                public_ips = set(r['ip'] for r in records)
                auth_ips = set(r['value'] for r in result['authoritative']['records'])
                if public_ips != auth_ips:
                    result['differences'] = []
                    only_public = public_ips - auth_ips
                    only_auth = auth_ips - public_ips
                    if only_public:
                        result['differences'].append({'type': 'public_only', 'message': 'In public DNS only', 'records': list(only_public)})
                    if only_auth:
                        result['differences'].append({'type': 'auth_only', 'message': 'In authoritative NS only', 'records': list(only_auth)})
                    result['status'] = 'warning'

        return result
    except dns.resolver.NXDOMAIN:
        result['message'] = 'Domain not found'
        return result
    except dns.resolver.NoAnswer:
        result['status'] = 'warning'
        result['message'] = 'No AAAA records found'
        return result
    except Exception as e:
        result['message'] = str(e)
        return result


def tool_ssl_check(host):
    """Check SSL certificate for a single host. Query can be hostname or hostname:port."""
    # Parse port from query if provided
    port = 443
    if ':' in host:
        parts = host.rsplit(':', 1)
        host = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            pass

    cert_result = check_ssl_certificate(host, port)
    return _format_ssl_result(host, port, cert_result)


def _format_ssl_result(host, port, cert_result):
    """Format SSL check result for display."""
    result = {
        'host': host,
        'port': port,
        'status': cert_result.get('status', 'error'),
        'certificate': None
    }

    if cert_result.get('error'):
        result['message'] = cert_result['error']
        return result

    if cert_result.get('valid'):
        days = cert_result.get('days_remaining')
        subject = cert_result.get('subject', 'Unknown')

        # Build status message
        if cert_result.get('expired'):
            result['message'] = f'EXPIRED - {subject}'
            result['status'] = 'error'
        elif cert_result.get('trusted'):
            if days is not None and days < 30:
                result['message'] = f'{subject} - expires in {days} days'
                result['status'] = 'warning'
            else:
                result['message'] = f'{subject} - {days} days remaining'
                result['status'] = 'success'
        else:
            result['message'] = f'{subject} - NOT TRUSTED'
            result['status'] = 'warning'

        result['certificate'] = {
            'subject': cert_result.get('subject'),
            'issuer': cert_result.get('issuer'),
            'valid_from': cert_result.get('not_before'),
            'valid_until': cert_result.get('not_after'),
            'days_remaining': cert_result.get('days_remaining'),
            'expired': cert_result.get('expired'),
            'trusted': cert_result.get('trusted'),
            'serial': cert_result.get('serial'),
            'version': cert_result.get('version'),
            'signature_algorithm': cert_result.get('signature_algorithm'),
            'san': cert_result.get('san', [])
        }

    return result


def tool_ssl_comprehensive_check(domain, mx_records=None, autodiscover_result=None):
    """Comprehensive SSL certificate check for domain, mail servers, and autodiscover endpoints."""
    result = {
        'tool': 'SSL Certificate Check',
        'query': domain,
        'status': 'success',
        'checks': [],
        'summary': {
            'total': 0,
            'valid': 0,
            'warnings': 0,
            'errors': 0
        },
        'command': f'openssl s_client -connect {domain}:443 -servername {domain} </dev/null 2>/dev/null | openssl x509 -noout -dates -subject -issuer'
    }

    hosts_to_check = []

    # 1. Main domain (HTTPS)
    hosts_to_check.append({
        'host': domain,
        'port': 443,
        'type': 'Web Server',
        'description': f'Main domain ({domain})'
    })

    # 2. Autodiscover subdomain
    autodiscover_host = f'autodiscover.{domain}'
    hosts_to_check.append({
        'host': autodiscover_host,
        'port': 443,
        'type': 'Autodiscover',
        'description': f'Autodiscover ({autodiscover_host})'
    })

    # 3. Mail servers from MX records (check port 465 for SMTPS)
    if mx_records and isinstance(mx_records, list):
        seen_mx = set()
        for mx in mx_records[:3]:  # Limit to first 3 MX servers
            mx_host = mx.get('host', '')
            if mx_host and mx_host not in seen_mx:
                seen_mx.add(mx_host)
                hosts_to_check.append({
                    'host': mx_host,
                    'port': 465,
                    'type': 'Mail Server (SMTPS)',
                    'description': f'MX: {mx_host}:465'
                })

    # 4. Additional autodiscover endpoints from autodiscover check
    if autodiscover_result and autodiscover_result.get('checks'):
        for check in autodiscover_result['checks']:
            # Check SRV records for autodiscover targets
            if check.get('type') == 'dns' and check.get('records'):
                for srv in check.get('records', []):
                    target = srv.get('target', '')
                    if target and target not in [h['host'] for h in hosts_to_check]:
                        hosts_to_check.append({
                            'host': target,
                            'port': 443,
                            'type': 'Autodiscover SRV',
                            'description': f'SRV target: {target}'
                        })

    # Run SSL checks for all hosts
    for host_info in hosts_to_check:
        cert_result = check_ssl_certificate(host_info['host'], host_info['port'])
        check_result = _format_ssl_result(host_info['host'], host_info['port'], cert_result)
        check_result['type'] = host_info['type']
        check_result['description'] = host_info['description']

        result['checks'].append(check_result)
        result['summary']['total'] += 1

        if check_result['status'] == 'success':
            result['summary']['valid'] += 1
        elif check_result['status'] == 'warning':
            result['summary']['warnings'] += 1
        elif check_result['status'] == 'info':
            # Service not available - not an error
            if 'unavailable' not in result['summary']:
                result['summary']['unavailable'] = 0
            result['summary']['unavailable'] += 1
        else:
            result['summary']['errors'] += 1

    # Determine overall status
    if result['summary']['errors'] > 0:
        result['status'] = 'error'
        result['message'] = f"{result['summary']['errors']} certificate error(s) found"
    elif result['summary']['warnings'] > 0:
        result['status'] = 'warning'
        result['message'] = f"{result['summary']['warnings']} certificate warning(s)"
    elif result['summary']['valid'] > 0:
        result['status'] = 'success'
        result['message'] = f"{result['summary']['valid']} certificate(s) valid"
    else:
        result['status'] = 'info'
        result['message'] = 'No SSL services available'

    return result


def check_smtp_connectivity(host, port=25, timeout=10, test_open_relay=True):
    """Check SMTP connectivity with full connection transcript and open relay test."""
    result = {
        'host': host,
        'port': port,
        'status': 'error',
        'connection': False,
        'helo_supported': False,
        'ehlo_supported': False,
        'starttls': False,
        'open_relay': None,  # None = not tested, True = vulnerable, False = secure
        'banner': None,
        'capabilities': [],
        'transcript': [],
        'message': ''
    }

    def log(direction, data):
        """Add to transcript."""
        result['transcript'].append({
            'direction': direction,  # 'send' or 'recv'
            'data': data.strip() if data else ''
        })

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        result['connection'] = True
        log('info', f'Connected to {host}:{port}')

        # Read banner
        banner = sock.recv(1024).decode('utf-8', errors='replace').strip()
        result['banner'] = banner
        log('recv', banner)

        if not banner.startswith('220'):
            result['message'] = f'Invalid banner response'
            log('info', 'ERROR: Invalid banner (expected 220)')
            sock.close()
            return result

        # Test EHLO first
        ehlo_cmd = 'EHLO mxlab.test\r\n'
        log('send', ehlo_cmd.strip())
        sock.send(ehlo_cmd.encode())
        ehlo_response = sock.recv(4096).decode('utf-8', errors='replace').strip()
        log('recv', ehlo_response)

        if ehlo_response.startswith('250'):
            result['ehlo_supported'] = True
            # Parse capabilities from EHLO response
            lines = ehlo_response.split('\n')
            for line in lines[1:]:  # Skip first line (greeting)
                line = line.strip()
                if line.startswith('250-') or line.startswith('250 '):
                    cap = line[4:].strip()
                    if cap:
                        result['capabilities'].append(cap)
                        if cap.upper() == 'STARTTLS':
                            result['starttls'] = True

            result['status'] = 'success'
            result['message'] = 'EHLO supported'
        else:
            log('info', 'EHLO not supported, trying HELO...')

            # Try HELO if EHLO failed
            helo_cmd = 'HELO mxlab.test\r\n'
            log('send', helo_cmd.strip())
            sock.send(helo_cmd.encode())
            helo_response = sock.recv(1024).decode('utf-8', errors='replace').strip()
            log('recv', helo_response)

            if helo_response.startswith('250'):
                result['helo_supported'] = True
                result['status'] = 'warning'
                result['message'] = 'Only HELO supported (EHLO failed)'
            else:
                result['message'] = 'Neither EHLO nor HELO supported'
                sock.close()
                return result

        # Open Relay Test (only on port 25 and if requested)
        if test_open_relay and port == 25 and (result['ehlo_supported'] or result['helo_supported']):
            log('info', '--- Open Relay Test ---')
            result['open_relay'] = False  # Assume secure until proven otherwise

            try:
                # Try to send from external domain to another external domain
                # Using well-known test domains that won't cause issues
                mail_from_cmd = 'MAIL FROM:<openrelay-test@example.org>\r\n'
                log('send', mail_from_cmd.strip())
                sock.send(mail_from_cmd.encode())
                mail_response = sock.recv(1024).decode('utf-8', errors='replace').strip()
                log('recv', mail_response)

                if mail_response.startswith('250'):
                    # Server accepted MAIL FROM, now try RCPT TO external domain
                    rcpt_to_cmd = 'RCPT TO:<openrelay-test@example.net>\r\n'
                    log('send', rcpt_to_cmd.strip())
                    sock.send(rcpt_to_cmd.encode())
                    rcpt_response = sock.recv(1024).decode('utf-8', errors='replace').strip()
                    log('recv', rcpt_response)

                    if rcpt_response.startswith('250') or rcpt_response.startswith('251'):
                        # Server accepted relay to external domain - OPEN RELAY!
                        result['open_relay'] = True
                        result['status'] = 'error'
                        result['message'] = 'OPEN RELAY DETECTED - Server accepts mail relay to external domains'
                        log('info', 'WARNING: Server is an OPEN RELAY!')
                    elif rcpt_response.startswith('4') or rcpt_response.startswith('5'):
                        # Server rejected relay - this is correct behavior
                        log('info', 'Server correctly rejected relay attempt')

                    # Reset the transaction
                    rset_cmd = 'RSET\r\n'
                    log('send', rset_cmd.strip())
                    sock.send(rset_cmd.encode())
                    try:
                        rset_response = sock.recv(1024).decode('utf-8', errors='replace').strip()
                        log('recv', rset_response)
                    except:
                        pass
                else:
                    log('info', 'MAIL FROM rejected (normal for some configurations)')

            except socket.timeout:
                log('info', 'Open relay test timed out')
            except Exception as e:
                log('info', f'Open relay test error: {str(e)}')

        # Send QUIT
        quit_cmd = 'QUIT\r\n'
        log('send', quit_cmd.strip())
        sock.send(quit_cmd.encode())
        try:
            quit_response = sock.recv(1024).decode('utf-8', errors='replace').strip()
            log('recv', quit_response)
        except:
            pass

        sock.close()
        log('info', 'Connection closed')

    except socket.timeout:
        result['message'] = f'Connection timeout'
        log('info', f'ERROR: Connection timeout after {timeout}s')
    except ConnectionRefusedError:
        result['message'] = f'Connection refused'
        log('info', 'ERROR: Connection refused')
    except OSError as e:
        result['message'] = f'Network error: {str(e)}'
        log('info', f'ERROR: {str(e)}')
    except Exception as e:
        result['message'] = str(e)
        log('info', f'ERROR: {str(e)}')

    return result


def tool_smtp_check(domain):
    """Check SMTP connectivity for ALL of a domain's mail servers with full logs."""
    # First get MX records
    mx_result = tool_mx_lookup(domain)

    if mx_result['status'] == 'error':
        return {
            'tool': 'SMTP Connectivity',
            'query': domain,
            'status': 'error',
            'message': 'Could not resolve MX records',
            'rfc': RFC_TIPS['smtp']
        }

    mx_records = mx_result.get('records', [])
    if not mx_records:
        # Fallback to domain A record
        mx_records = [{'host': domain, 'priority': 0, 'ips': [], 'ipv6': []}]

    results_by_mx = []
    overall_status = 'error'

    for mx in mx_records:
        host = mx['host']
        mx_result_entry = {
            'host': host,
            'priority': mx.get('priority', 0),
            'ips': mx.get('ips', []),
            'ipv6': mx.get('ipv6', []),
            'ports': {}
        }

        # Check port 25 (SMTP)
        smtp_25 = check_smtp_connectivity(host, 25)
        smtp_25['port_name'] = 'SMTP (25)'
        mx_result_entry['ports']['25'] = smtp_25

        if smtp_25['status'] == 'success':
            overall_status = 'success'
        elif smtp_25['status'] == 'warning' and overall_status != 'success':
            overall_status = 'warning'

        # Check port 587 (Submission)
        smtp_587 = check_smtp_connectivity(host, 587)
        smtp_587['port_name'] = 'Submission (587)'
        mx_result_entry['ports']['587'] = smtp_587

        # Check port 465 (SMTPS)
        smtp_465 = check_smtp_connectivity(host, 465)
        smtp_465['port_name'] = 'SMTPS (465)'
        mx_result_entry['ports']['465'] = smtp_465

        results_by_mx.append(mx_result_entry)

    # Count successes
    successful_mx = sum(1 for mx in results_by_mx if mx['ports']['25'].get('status') == 'success')

    return {
        'tool': 'SMTP Connectivity',
        'query': domain,
        'status': overall_status,
        'mx_count': len(results_by_mx),
        'mx_successful': successful_mx,
        'results': results_by_mx,
        'rfc': RFC_TIPS['smtp'],
        'message': f'{successful_mx} of {len(results_by_mx)} MX servers responding on port 25',
        'command': f'telnet {results_by_mx[0]["host"] if results_by_mx else domain} 25'
    }


def check_ssl_certificate(host, port=443, timeout=10):
    """Check SSL certificate for a host, allowing untrusted certs."""
    cert_info = {
        'host': host,
        'port': port,
        'status': 'error',
        'valid': False,
        'trusted': False,
        'subject': None,
        'issuer': None,
        'not_before': None,
        'not_after': None,
        'expired': None,
        'days_remaining': None,
        'san': [],
        'serial': None,
        'version': None,
        'signature_algorithm': None,
        'error': None
    }

    # First check if host resolves
    try:
        socket.gethostbyname(host)
    except socket.gaierror as e:
        cert_info['error'] = f'Host not found: {host}'
        cert_info['status'] = 'info'  # Not an error - subdomain may not exist
        return cert_info

    try:
        # Create SSL context that doesn't verify (to get cert even if untrusted)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # Get certificate in DER (binary) format - this works even with CERT_NONE
                cert_der = ssock.getpeercert(binary_form=True)

                if not cert_der:
                    cert_info['error'] = 'No certificate received'
                    return cert_info

                # Try to use cryptography library for detailed parsing
                try:
                    from cryptography import x509
                    from cryptography.hazmat.backends import default_backend

                    cert = x509.load_der_x509_certificate(cert_der, default_backend())

                    # Extract subject
                    try:
                        cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
                        cert_info['subject'] = cn[0].value if cn else None
                    except:
                        cert_info['subject'] = str(cert.subject)

                    # Extract issuer
                    try:
                        issuer_cn = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
                        issuer_org = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)
                        cert_info['issuer'] = issuer_cn[0].value if issuer_cn else (issuer_org[0].value if issuer_org else str(cert.issuer))
                    except:
                        cert_info['issuer'] = str(cert.issuer)

                    # Validity dates
                    cert_info['not_before'] = cert.not_valid_before_utc.strftime('%Y-%m-%d %H:%M:%S UTC')
                    cert_info['not_after'] = cert.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S UTC')

                    # Check expiry
                    now = datetime.utcnow()
                    cert_info['expired'] = cert.not_valid_after_utc.replace(tzinfo=None) < now
                    cert_info['days_remaining'] = (cert.not_valid_after_utc.replace(tzinfo=None) - now).days

                    # Serial number
                    cert_info['serial'] = format(cert.serial_number, 'X')

                    # Version
                    cert_info['version'] = cert.version.name

                    # Signature algorithm
                    cert_info['signature_algorithm'] = cert.signature_algorithm_oid._name

                    # Subject Alternative Names
                    try:
                        san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                        san_values = san_ext.value.get_values_for_type(x509.DNSName)
                        # Handle both old (objects with .value) and new (direct strings) cryptography versions
                        cert_info['san'] = [str(name) for name in san_values]
                    except x509.ExtensionNotFound:
                        cert_info['san'] = []
                    except Exception:
                        cert_info['san'] = []

                    cert_info['valid'] = True

                except ImportError:
                    # Fallback: basic parsing without cryptography library
                    cert_info['error'] = 'cryptography library not available for detailed parsing'
                    cert_info['valid'] = True  # We got a cert, just can't parse details

        # Now check if the certificate is trusted (separate connection with verification)
        try:
            context_verify = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=timeout) as sock2:
                with context_verify.wrap_socket(sock2, server_hostname=host) as ssock2:
                    # If we get here without exception, cert is trusted
                    cert_info['trusted'] = True
        except ssl.SSLCertVerificationError as e:
            cert_info['trusted'] = False
            cert_info['trust_error'] = str(e)
        except Exception as e:
            cert_info['trusted'] = False
            cert_info['trust_error'] = f'Verification failed: {str(e)}'

        # Set final status
        if cert_info['valid']:
            if cert_info['expired']:
                cert_info['status'] = 'error'
            elif cert_info['trusted']:
                cert_info['status'] = 'success'
            else:
                cert_info['status'] = 'warning'

    except socket.timeout:
        cert_info['error'] = 'Connection timeout'
        cert_info['status'] = 'warning'
    except ConnectionRefusedError:
        cert_info['error'] = 'Port not open'
        cert_info['status'] = 'info'  # Not an error - service just not available
    except ssl.SSLError as e:
        cert_info['error'] = f'SSL error: {str(e)}'
    except OSError as e:
        if 'No route to host' in str(e) or 'Network is unreachable' in str(e):
            cert_info['error'] = 'Host unreachable'
            cert_info['status'] = 'info'
        else:
            cert_info['error'] = f'Connection error: {str(e)}'
    except Exception as e:
        cert_info['error'] = f'Error: {str(e)}'

    return cert_info


def tool_autodiscover_check(domain):
    """Check Outlook Autodiscover configuration with SSL certificate status."""
    import urllib.request
    import urllib.error

    results = {
        'tool': 'Autodiscover Check',
        'query': domain,
        'status': 'warning',
        'checks': [],
        'rfc': RFC_TIPS['autodiscover']
    }

    # 1. Check autodiscover.domain.com A record
    autodiscover_domain = f'autodiscover.{domain}'
    try:
        answers = dns.resolver.resolve(autodiscover_domain, 'A')
        ips = [str(r) for r in answers]
        results['checks'].append({
            'name': 'Autodiscover A Record',
            'type': 'dns',
            'target': autodiscover_domain,
            'status': 'success',
            'message': f'Resolves to {", ".join(ips)}',
            'ips': ips
        })
    except:
        results['checks'].append({
            'name': 'Autodiscover A Record',
            'type': 'dns',
            'target': autodiscover_domain,
            'status': 'warning',
            'message': 'No A record found'
        })

    # 2. Check autodiscover.domain.com CNAME
    try:
        answers = dns.resolver.resolve(autodiscover_domain, 'CNAME')
        cname = str(answers[0].target).rstrip('.')
        results['checks'].append({
            'name': 'Autodiscover CNAME',
            'type': 'dns',
            'target': autodiscover_domain,
            'status': 'success',
            'message': f'CNAME points to {cname}',
            'cname': cname
        })
    except:
        results['checks'].append({
            'name': 'Autodiscover CNAME',
            'type': 'dns',
            'target': autodiscover_domain,
            'status': 'info',
            'message': 'No CNAME record (may use A record)'
        })

    # 3. Check SRV record _autodiscover._tcp.domain
    srv_domain = f'_autodiscover._tcp.{domain}'
    try:
        answers = dns.resolver.resolve(srv_domain, 'SRV')
        srv_records = []
        for rdata in answers:
            srv_records.append({
                'priority': rdata.priority,
                'weight': rdata.weight,
                'port': rdata.port,
                'target': str(rdata.target).rstrip('.')
            })
        results['checks'].append({
            'name': 'Autodiscover SRV Record',
            'type': 'dns',
            'target': srv_domain,
            'status': 'success',
            'message': f'SRV record found',
            'records': srv_records
        })
    except:
        results['checks'].append({
            'name': 'Autodiscover SRV Record',
            'type': 'dns',
            'target': srv_domain,
            'status': 'warning',
            'message': 'No SRV record found',
            'command': f'dig {srv_domain} SRV +short'
        })

    # 4. Check SSL certificate for autodiscover endpoints
    ssl_hosts = [
        autodiscover_domain,
        domain
    ]

    for ssl_host in ssl_hosts:
        cert_result = check_ssl_certificate(ssl_host, 443)

        # Build detailed message
        cert_message = ''
        cert_status = cert_result.get('status', 'error')

        if cert_result['valid']:
            days = cert_result.get('days_remaining')
            subject = cert_result.get('subject', 'Unknown')

            if cert_result['expired']:
                cert_message = f"EXPIRED - {subject}"
                cert_status = 'error'
            elif cert_result['trusted']:
                cert_message = f"{subject} - {days} days remaining"
                if days is not None and days < 30:
                    cert_message = f"{subject} - EXPIRES SOON ({days} days)"
                    cert_status = 'warning'
            else:
                trust_err = cert_result.get('trust_error', 'Not trusted')
                # Shorten long trust errors
                if len(trust_err) > 80:
                    trust_err = trust_err[:77] + '...'
                cert_message = f"{subject} - UNTRUSTED: {trust_err}"
        else:
            cert_message = cert_result.get('error', 'Could not retrieve certificate')

        results['checks'].append({
            'name': f'SSL Certificate ({ssl_host})',
            'type': 'ssl',
            'target': ssl_host,
            'status': cert_status,
            'message': cert_message,
            'certificate': {
                'subject': cert_result.get('subject'),
                'issuer': cert_result.get('issuer'),
                'valid_from': cert_result.get('not_before'),
                'valid_until': cert_result.get('not_after'),
                'trusted': cert_result.get('trusted'),
                'expired': cert_result.get('expired'),
                'days_remaining': cert_result.get('days_remaining'),
                'san': cert_result.get('san', []),
                'serial': cert_result.get('serial'),
                'version': cert_result.get('version'),
                'signature_algorithm': cert_result.get('signature_algorithm')
            }
        })

    # 5. Check HTTP endpoints (all of them, with results for each)
    autodiscover_urls = [
        f'https://autodiscover.{domain}/autodiscover/autodiscover.xml',
        f'https://{domain}/autodiscover/autodiscover.xml',
        f'http://autodiscover.{domain}/autodiscover/autodiscover.xml',
        f'http://{domain}/autodiscover/autodiscover.xml'
    ]

    # Create SSL context that ignores certificate errors
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    for url in autodiscover_urls:
        check_result = {
            'name': 'HTTP Endpoint',
            'type': 'http',
            'target': url,
            'status': 'error',
            'message': ''
        }

        try:
            req = urllib.request.Request(url, method='GET')
            req.add_header('User-Agent', 'MXLab/1.0 Autodiscover')

            # Use SSL context for HTTPS URLs
            if url.startswith('https://'):
                with urllib.request.urlopen(req, timeout=5, context=ssl_context) as response:
                    status_code = response.getcode()
                    check_result['http_code'] = status_code
                    check_result['status'] = 'success'
                    check_result['message'] = f'Accessible (HTTP {status_code})'
            else:
                with urllib.request.urlopen(req, timeout=5) as response:
                    status_code = response.getcode()
                    check_result['http_code'] = status_code
                    check_result['status'] = 'success'
                    check_result['message'] = f'Accessible (HTTP {status_code})'

        except urllib.error.HTTPError as e:
            check_result['http_code'] = e.code
            if e.code in [401, 403]:
                check_result['status'] = 'success'
                check_result['message'] = f'Exists - requires auth (HTTP {e.code})'
            elif e.code == 404:
                check_result['status'] = 'warning'
                check_result['message'] = 'Not found (HTTP 404)'
            else:
                check_result['status'] = 'warning'
                check_result['message'] = f'HTTP error {e.code}'
        except urllib.error.URLError as e:
            check_result['message'] = f'Connection failed: {str(e.reason)[:50]}'
        except socket.timeout:
            check_result['message'] = 'Connection timeout'
        except Exception as e:
            check_result['message'] = str(e)[:50]

        results['checks'].append(check_result)

    # Determine overall status
    success_count = sum(1 for c in results['checks'] if c['status'] == 'success')
    if success_count >= 2:
        results['status'] = 'success'
        results['message'] = 'Autodiscover is properly configured'
    elif success_count >= 1:
        results['status'] = 'warning'
        results['message'] = 'Partial Autodiscover configuration'
    else:
        results['status'] = 'error'
        results['message'] = 'Autodiscover not configured'

    return results


# ============================================
# Exchange Connectivity Test Functions
# ============================================

def parse_autodiscover_xml(xml_content):
    """Parse Autodiscover XML response and extract protocol settings."""
    try:
        root = ET.fromstring(xml_content)
        ns = {
            'a': 'http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006',
            'o': 'http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a'
        }
        result = {'user': {}, 'protocols': {}, 'settings': []}
        account = root.find('.//o:Account', ns)
        if account is not None:
            user = account.find('o:User', ns)
            if user is not None:
                result['user']['display_name'] = user.findtext('o:DisplayName', '', ns)
                result['user']['email'] = user.findtext('o:AutoDiscoverSMTPAddress', '', ns)
            for protocol in account.findall('.//o:Protocol', ns):
                proto_type = protocol.findtext('o:Type', '', ns)
                proto_data = {
                    'server': protocol.findtext('o:Server', '', ns),
                    'ssl': protocol.findtext('o:SSL', '', ns),
                    'port': protocol.findtext('o:Port', '', ns),
                    'auth_package': protocol.findtext('o:AuthPackage', '', ns),
                }
                ews_url = protocol.findtext('o:EwsUrl', '', ns)
                if ews_url: proto_data['ews_url'] = ews_url
                as_url = protocol.findtext('o:ASUrl', '', ns)
                if as_url: proto_data['activesync_url'] = as_url
                if proto_type: result['protocols'][proto_type] = proto_data
        return result
    except Exception as e:
        return {'error': str(e)}


def test_exchange_autodiscover(email, password, manual_server=None):
    """Test Autodiscover connectivity for Exchange/Office 365."""
    domain = email.split('@')[1] if '@' in email else email
    steps = []
    autodiscover_xml = None
    autodiscover_parsed = None
    autodiscover_url = None

    # DNS SRV lookup
    step = {'name': 'DNS SRV Lookup', 'test': 'autodiscover', 'status': 'error', 'response_time_ms': 0, 'message': ''}
    start_time = datetime.now()
    try:
        if DNS_AVAILABLE:
            resolver = create_resolver(use_cache=False)
            answers = resolver.resolve(f'_autodiscover._tcp.{domain}', 'SRV')
            srv_target = str(answers[0].target).rstrip('.')
            step['status'] = 'success'
            step['message'] = f'SRV record found: {srv_target}'
        else:
            step['status'] = 'warning'
            step['message'] = 'DNS library not available'
    except Exception as e:
        step['status'] = 'warning'
        step['message'] = f'No SRV record: {str(e)[:50]}'
    step['response_time_ms'] = int((datetime.now() - start_time).total_seconds() * 1000)
    steps.append(step)

    autodiscover_urls = [f'https://{manual_server}/autodiscover/autodiscover.xml'] if manual_server else [
        f'https://autodiscover.{domain}/autodiscover/autodiscover.xml',
        f'https://{domain}/autodiscover/autodiscover.xml',
    ]
    autodiscover_request = f'''<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
  <Request><EMailAddress>{email}</EMailAddress>
    <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
  </Request>
</Autodiscover>'''

    for url in autodiscover_urls:
        step = {'name': 'Autodiscover Request', 'test': 'autodiscover', 'status': 'error', 'response_time_ms': 0, 'message': '', 'details': {'url': url}}
        start_time = datetime.now()
        try:
            auth = HTTPBasicAuth(email, password)
            response = requests.post(url, data=autodiscover_request, auth=auth, headers={'Content-Type': 'text/xml'}, timeout=15, verify=True)
            step['response_time_ms'] = int((datetime.now() - start_time).total_seconds() * 1000)
            step['details']['status_code'] = response.status_code
            if response.status_code == 200:
                step['status'] = 'success'
                step['message'] = f'Autodiscover response received ({response.status_code})'
                autodiscover_xml = response.text
                autodiscover_url = url
                autodiscover_parsed = parse_autodiscover_xml(autodiscover_xml)
                steps.append(step)
                break
            elif response.status_code == 401:
                if NTLM_AVAILABLE:
                    try:
                        ntlm_auth = HttpNtlmAuth(email, password)
                        response = requests.post(url, data=autodiscover_request, auth=ntlm_auth, headers={'Content-Type': 'text/xml'}, timeout=15, verify=True)
                        if response.status_code == 200:
                            step['status'] = 'success'
                            step['message'] = 'Autodiscover response received (NTLM auth)'
                            autodiscover_xml = response.text
                            autodiscover_url = url
                            autodiscover_parsed = parse_autodiscover_xml(autodiscover_xml)
                            steps.append(step)
                            break
                    except: pass
                step['status'] = 'error'
                step['message'] = 'Authentication failed (401)'
            else:
                step['status'] = 'error'
                step['message'] = f'HTTP {response.status_code}'
        except requests.exceptions.SSLError as e:
            step['status'] = 'error'
            step['message'] = f'SSL Error: {str(e)[:50]}'
        except requests.exceptions.Timeout:
            step['status'] = 'error'
            step['message'] = 'Request timeout (15s)'
        except Exception as e:
            step['status'] = 'error'
            step['message'] = str(e)[:50]
        step['response_time_ms'] = int((datetime.now() - start_time).total_seconds() * 1000)
        steps.append(step)

    return {'test': 'autodiscover', 'status': 'success' if autodiscover_xml else 'error', 'steps': steps,
            'autodiscover_url': autodiscover_url, 'autodiscover_xml': autodiscover_xml, 'autodiscover_parsed': autodiscover_parsed,
            'message': 'Autodiscover successful' if autodiscover_xml else 'Autodiscover failed'}


def test_exchange_ews(email, password, autodiscover_result):
    """Test Exchange Web Services connectivity."""
    ews_url = 'https://outlook.office365.com/EWS/Exchange.asmx'
    if autodiscover_result and autodiscover_result.get('autodiscover_parsed'):
        for proto_data in autodiscover_result['autodiscover_parsed'].get('protocols', {}).values():
            if proto_data.get('ews_url'): ews_url = proto_data['ews_url']; break

    step = {'name': 'EWS GetFolder Request', 'test': 'ews', 'status': 'error', 'response_time_ms': 0, 'message': '', 'details': {'url': ews_url}}
    ews_request = '''<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"><soap:Body><GetFolder xmlns="http://schemas.microsoft.com/exchange/services/2006/messages"><FolderShape><t:BaseShape>Default</t:BaseShape></FolderShape><FolderIds><t:DistinguishedFolderId Id="inbox"/></FolderIds></GetFolder></soap:Body></soap:Envelope>'''
    start_time = datetime.now()
    try:
        response = requests.post(ews_url, data=ews_request, auth=HTTPBasicAuth(email, password),
                                 headers={'Content-Type': 'text/xml; charset=utf-8', 'SOAPAction': '"http://schemas.microsoft.com/exchange/services/2006/messages/GetFolder"'}, timeout=15, verify=True)
        step['response_time_ms'] = int((datetime.now() - start_time).total_seconds() * 1000)
        step['details']['status_code'] = response.status_code
        if response.status_code == 200 and ('GetFolderResponse' in response.text or 'Inbox' in response.text):
            step['status'] = 'success'
            step['message'] = 'EWS GetFolder successful - Inbox accessible'
        elif response.status_code == 401:
            step['status'] = 'error'
            step['message'] = 'Authentication failed (401)'
        else:
            step['status'] = 'error'
            step['message'] = f'HTTP {response.status_code}'
    except Exception as e:
        step['status'] = 'error'
        step['message'] = str(e)[:50]
    return {'test': 'ews', 'status': step['status'], 'steps': [step], 'message': step['message']}


def test_exchange_activesync(email, password, autodiscover_result):
    """Test Exchange ActiveSync connectivity."""
    as_url = 'https://outlook.office365.com/Microsoft-Server-ActiveSync'
    step = {'name': 'ActiveSync OPTIONS', 'test': 'activesync', 'status': 'error', 'response_time_ms': 0, 'message': '', 'details': {'url': as_url}}
    start_time = datetime.now()
    try:
        response = requests.options(as_url, auth=HTTPBasicAuth(email, password), timeout=15, verify=True)
        step['response_time_ms'] = int((datetime.now() - start_time).total_seconds() * 1000)
        step['details']['status_code'] = response.status_code
        ms_server = response.headers.get('MS-Server-ActiveSync', '')
        if response.status_code == 200:
            step['status'] = 'success'
            step['message'] = f'ActiveSync available (v{ms_server})'
        elif response.status_code == 401:
            step['status'] = 'error'
            step['message'] = 'Authentication failed (401)'
        else:
            step['status'] = 'warning'
            step['message'] = f'HTTP {response.status_code}'
    except Exception as e:
        step['status'] = 'error'
        step['message'] = str(e)[:50]
    return {'test': 'activesync', 'status': step['status'], 'steps': [step], 'message': step['message']}


def test_exchange_mapi_http(email, password, autodiscover_result):
    """Test MAPI over HTTP connectivity."""
    mapi_url = 'https://outlook.office365.com/mapi/emsmdb/'
    step = {'name': 'MAPI-HTTP Connect', 'test': 'mapi_http', 'status': 'error', 'response_time_ms': 0, 'message': '', 'details': {'url': mapi_url}}
    start_time = datetime.now()
    try:
        response = requests.post(mapi_url, auth=HTTPBasicAuth(email, password), headers={'Content-Type': 'application/mapi-http', 'X-RequestType': 'Connect'}, timeout=15, verify=True)
        step['response_time_ms'] = int((datetime.now() - start_time).total_seconds() * 1000)
        step['details']['status_code'] = response.status_code
        if response.status_code == 200:
            step['status'] = 'success'
            step['message'] = 'MAPI-HTTP endpoint accessible'
        elif response.status_code == 401:
            step['status'] = 'error'
            step['message'] = 'Authentication failed (401)'
        else:
            step['status'] = 'warning'
            step['message'] = f'HTTP {response.status_code}'
    except Exception as e:
        step['status'] = 'error'
        step['message'] = str(e)[:50]
    return {'test': 'mapi_http', 'status': step['status'], 'steps': [step], 'message': step['message']}


def test_exchange_availability(email, password, autodiscover_result):
    """Test Exchange Availability Service."""
    ews_url = 'https://outlook.office365.com/EWS/Exchange.asmx'
    step = {'name': 'Availability Service', 'test': 'availability', 'status': 'error', 'response_time_ms': 0, 'message': '', 'details': {'url': ews_url}}
    now = datetime.utcnow()
    availability_request = f'''<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"><soap:Body><GetUserAvailabilityRequest xmlns="http://schemas.microsoft.com/exchange/services/2006/messages"><t:TimeZone><t:Bias>0</t:Bias></t:TimeZone><MailboxDataArray><t:MailboxData><t:Email><t:Address>{email}</t:Address></t:Email><t:AttendeeType>Required</t:AttendeeType></t:MailboxData></MailboxDataArray><t:FreeBusyViewOptions><t:TimeWindow><t:StartTime>{now.strftime('%Y-%m-%dT00:00:00')}</t:StartTime><t:EndTime>{(now + timedelta(days=1)).strftime('%Y-%m-%dT00:00:00')}</t:EndTime></t:TimeWindow><t:RequestedView>FreeBusy</t:RequestedView></t:FreeBusyViewOptions></GetUserAvailabilityRequest></soap:Body></soap:Envelope>'''
    start_time = datetime.now()
    try:
        response = requests.post(ews_url, data=availability_request, auth=HTTPBasicAuth(email, password),
                                 headers={'Content-Type': 'text/xml; charset=utf-8', 'SOAPAction': '"http://schemas.microsoft.com/exchange/services/2006/messages/GetUserAvailability"'}, timeout=15, verify=True)
        step['response_time_ms'] = int((datetime.now() - start_time).total_seconds() * 1000)
        step['details']['status_code'] = response.status_code
        if response.status_code == 200 and 'FreeBusyView' in response.text:
            step['status'] = 'success'
            step['message'] = 'Availability service working'
        elif response.status_code == 401:
            step['status'] = 'error'
            step['message'] = 'Authentication failed (401)'
        else:
            step['status'] = 'error'
            step['message'] = f'HTTP {response.status_code}'
    except Exception as e:
        step['status'] = 'error'
        step['message'] = str(e)[:50]
    return {'test': 'availability', 'status': step['status'], 'steps': [step], 'message': step['message']}


async def send_telegram_exchange_notification(domain, summary, client_ip, report_id=None):
    """Send notification about Exchange connectivity test."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID: return
    try:
        score = summary.get('score', 0)
        emoji = "✅" if score >= 80 else "👍" if score >= 60 else "⚠️" if score >= 40 else "❌"
        status = "EXCELLENT" if score >= 80 else "GOOD" if score >= 60 else "FAIR" if score >= 40 else "POOR"
        message = f"""{emoji} <b>ExchLookup Test</b>\n\n<b>Domain:</b> <code>{domain}</code>\n<b>Score:</b> {score}/100 — {status}\n<b>Tests:</b> {', '.join(summary.get('tests_run', []))}\n<b>Results:</b> ✅ {summary.get('passed', 0)} | ⚠️ {summary.get('warnings', 0)} | ❌ {summary.get('errors', 0)}\n<b>Client IP:</b> <code>{client_ip}</code>"""
        if report_id: message += f"\n\n🔗 <a href=\"https://{DOMAIN}/report/{report_id}\">View Report</a>"
        async with aiohttp.ClientSession() as session:
            await session.post(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage", json={'chat_id': TELEGRAM_CHAT_ID, 'text': message, 'parse_mode': 'HTML', 'disable_notification': True})
    except Exception as e:
        print(f"[TELEGRAM] Error: {e}")


@app.route('/api/exchange/test/stream', methods=['POST'])
def exchange_test_stream():
    """Stream Exchange connectivity test results using Server-Sent Events."""
    from flask import Response
    data = request.get_json() or {}
    email = data.get('email', '').strip()
    password = data.get('password', '')
    use_autodiscover = data.get('use_autodiscover', True)
    manual_server = data.get('manual_server', '').strip() if not use_autodiscover else None
    tests_config = data.get('tests', {})
    client_ip = request.headers.get('X-Forwarded-For', request.headers.get('X-Real-IP', request.remote_addr))
    if client_ip and ',' in client_ip: client_ip = client_ip.split(',')[0].strip()
    if not email or not password: return jsonify({'error': 'Email and password are required'}), 400
    if '@' not in email: return jsonify({'error': 'Invalid email format'}), 400
    domain = email.split('@')[1]

    def generate():
        def send_event(event_type, event_data):
            return f"event: {event_type}\ndata: {json.dumps(event_data)}\n\n"
        tests_to_run = []
        if tests_config.get('autodiscover', True): tests_to_run.append('autodiscover')
        if tests_config.get('ews', False): tests_to_run.append('ews')
        if tests_config.get('activesync', False): tests_to_run.append('activesync')
        if tests_config.get('mapi_http', False): tests_to_run.append('mapi_http')
        if tests_config.get('availability', False): tests_to_run.append('availability')
        if not tests_to_run: tests_to_run = ['autodiscover']

        yield send_event('start', {'email_domain': domain, 'tests_selected': len(tests_to_run), 'timestamp': datetime.now().isoformat()})
        all_results = {}
        all_steps = []
        autodiscover_result = None

        if 'autodiscover' in tests_to_run:
            autodiscover_result = test_exchange_autodiscover(email, password, manual_server)
            all_results['autodiscover'] = autodiscover_result
            for step in autodiscover_result.get('steps', []):
                yield send_event('step', step)
                all_steps.append(step)
            if autodiscover_result.get('autodiscover_xml'):
                yield send_event('autodiscover_xml', {'parsed': autodiscover_result.get('autodiscover_parsed'), 'raw': autodiscover_result.get('autodiscover_xml')})

        test_functions = {'ews': test_exchange_ews, 'activesync': test_exchange_activesync, 'mapi_http': test_exchange_mapi_http, 'availability': test_exchange_availability}
        for test_name in tests_to_run:
            if test_name == 'autodiscover': continue
            func = test_functions.get(test_name)
            if func:
                result = func(email, password, autodiscover_result)
                all_results[test_name] = result
                for step in result.get('steps', []):
                    yield send_event('step', step)
                    all_steps.append(step)

        passed = sum(1 for s in all_steps if s['status'] == 'success')
        warnings = sum(1 for s in all_steps if s['status'] == 'warning')
        errors = sum(1 for s in all_steps if s['status'] == 'error')
        total = len(all_steps)
        score = round((passed / total) * 100) if total > 0 else 0
        summary = {'total': total, 'passed': passed, 'warnings': warnings, 'errors': errors, 'score': score, 'tests_run': tests_to_run}

        report_id = None
        if MONGO_AVAILABLE and reports_collection is not None:
            try:
                report_id = f"exchange_{domain}_{int(datetime.now().timestamp())}"
                report_doc = {'_id': report_id, 'type': 'exchange_test', 'email_domain': domain, 'timestamp': datetime.now().isoformat(), 'tests_run': tests_to_run, 'results': all_results, 'summary': summary}
                if autodiscover_result and autodiscover_result.get('autodiscover_xml'): report_doc['autodiscover_xml'] = autodiscover_result['autodiscover_xml']
                reports_collection.insert_one(report_doc)
            except Exception as e:
                print(f"[MONGO] Error: {e}")

        import threading
        def send_notification():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(send_telegram_exchange_notification(domain, summary, client_ip, report_id))
            loop.close()
        threading.Thread(target=send_notification, daemon=True).start()

        complete_data = {'summary': summary, 'timestamp': datetime.now().isoformat()}
        if report_id: complete_data['report_id'] = report_id; complete_data['report_url'] = f"/report/{report_id}"
        yield send_event('complete', complete_data)

    return Response(generate(), mimetype='text/event-stream', headers={'Cache-Control': 'no-cache', 'Connection': 'keep-alive', 'X-Accel-Buffering': 'no'})


@app.route('/api/tools/report/stream')
def stream_domain_report():
    """Stream domain report results progressively using Server-Sent Events."""
    from flask import Response

    domain = request.args.get('query', '').strip()
    client_ip = request.headers.get('X-Forwarded-For', request.headers.get('X-Real-IP', request.remote_addr))
    if client_ip and ',' in client_ip:
        client_ip = client_ip.split(',')[0].strip()

    if not domain:
        return jsonify({'error': 'Domain parameter is required'}), 400

    if not DNS_AVAILABLE:
        return jsonify({'error': 'DNS library not available'}), 500

    def generate():
        """Generator function for SSE stream."""
        checks_completed = 0
        total_checks = 12  # Total number of checks (added SSL)
        all_checks = {}  # Collect all check results for saving

        # Helper to send SSE event
        def send_event(event_type, data):
            return f"event: {event_type}\ndata: {json.dumps(data)}\n\n"

        # Send start event
        yield send_event('start', {'domain': domain, 'total_checks': total_checks})

        # 1. MX Lookup (store for later use)
        mx_result = tool_mx_lookup(domain)
        mx_result['rfc'] = RFC_TIPS['mx']
        all_checks['mx'] = mx_result
        checks_completed += 1
        yield send_event('check', {'name': 'mx', 'result': mx_result, 'progress': checks_completed})

        # 2. A Record
        result = tool_a_lookup(domain)
        result['rfc'] = RFC_TIPS['a']
        all_checks['a'] = result
        checks_completed += 1
        yield send_event('check', {'name': 'a', 'result': result, 'progress': checks_completed})

        # 3. AAAA Record
        result = tool_aaaa_lookup(domain)
        result['rfc'] = RFC_TIPS['aaaa']
        all_checks['aaaa'] = result
        checks_completed += 1
        yield send_event('check', {'name': 'aaaa', 'result': result, 'progress': checks_completed})

        # 4. NS Record
        result = tool_ns_lookup(domain)
        result['rfc'] = RFC_TIPS['ns']
        all_checks['ns'] = result
        checks_completed += 1
        yield send_event('check', {'name': 'ns', 'result': result, 'progress': checks_completed})

        # 5. TXT Record
        result = tool_txt_lookup(domain)
        all_checks['txt'] = result
        checks_completed += 1
        yield send_event('check', {'name': 'txt', 'result': result, 'progress': checks_completed})

        # 6. SPF
        result = tool_spf_lookup(domain)
        if result:
            result['rfc'] = RFC_TIPS['spf']
        else:
            result = {'tool': 'SPF Lookup', 'status': 'warning', 'message': 'No SPF record found', 'rfc': RFC_TIPS['spf']}
        all_checks['spf'] = result
        checks_completed += 1
        yield send_event('check', {'name': 'spf', 'result': result, 'progress': checks_completed})

        # 7. DKIM
        result = tool_dkim_lookup(domain)
        result['rfc'] = RFC_TIPS['dkim']
        all_checks['dkim'] = result
        checks_completed += 1
        yield send_event('check', {'name': 'dkim', 'result': result, 'progress': checks_completed})

        # 8. DMARC
        result = tool_dmarc_lookup(domain)
        result['rfc'] = RFC_TIPS['dmarc']
        all_checks['dmarc'] = result
        checks_completed += 1
        yield send_event('check', {'name': 'dmarc', 'result': result, 'progress': checks_completed})

        # 9. SMTP (slower)
        result = tool_smtp_check(domain)
        all_checks['smtp'] = result
        checks_completed += 1
        yield send_event('check', {'name': 'smtp', 'result': result, 'progress': checks_completed})

        # 10. Autodiscover (store for SSL check)
        autodiscover_result = tool_autodiscover_check(domain)
        all_checks['autodiscover'] = autodiscover_result
        checks_completed += 1
        yield send_event('check', {'name': 'autodiscover', 'result': autodiscover_result, 'progress': checks_completed})

        # 11. SSL Certificate Check (after autodiscover to check all endpoints)
        # Checks: main domain, autodiscover subdomain, mail servers (SMTPS)
        mx_records = mx_result.get('records', []) if mx_result else []
        result = tool_ssl_comprehensive_check(domain, mx_records, autodiscover_result)
        all_checks['ssl'] = result
        checks_completed += 1
        yield send_event('check', {'name': 'ssl', 'result': result, 'progress': checks_completed})

        # 12. Blacklist (need MX IP first)
        if mx_result.get('records'):
            mx_host = mx_result['records'][0]['host']
            try:
                mx_ips = dns.resolver.resolve(mx_host, 'A')
                mx_ip = str(mx_ips[0])
                result = tool_blacklist_check(mx_ip)
                result['rfc'] = RFC_TIPS['blacklist']
                result['checked_ip'] = mx_ip
                result['checked_host'] = mx_host
            except:
                result = {
                    'tool': 'Blacklist Check',
                    'status': 'warning',
                    'message': 'Could not resolve MX server IP'
                }
        else:
            result = {
                'tool': 'Blacklist Check',
                'status': 'warning',
                'message': 'No MX records to check'
            }
        all_checks['blacklist'] = result
        checks_completed += 1
        yield send_event('check', {'name': 'blacklist', 'result': result, 'progress': checks_completed})

        # Calculate summary with weighted scoring
        # Weights: critical checks have higher impact, optional checks have lower
        check_weights = {
            'mx': 1.0,          # Essential for email
            'spf': 1.0,         # Important authentication
            'dkim': 1.0,        # Important authentication
            'dmarc': 1.0,       # Important authentication
            'blacklist': 1.0,   # Critical security
            'a': 0.8,           # Basic DNS
            'ns': 0.8,          # Basic DNS
            'smtp': 0.8,        # Email connectivity
            'ssl': 0.8,         # Security
            'txt': 0.1,         # Informational
            'autodiscover': 0.1, # Optional (Exchange)
            'aaaa': 0.1,        # IPv6 is optional
        }

        summary = {'total': 0, 'passed': 0, 'warnings': 0, 'errors': 0, 'score': 0}
        weighted_passed = 0
        total_weight = 0

        for check_name, check_data in all_checks.items():
            summary['total'] += 1
            weight = check_weights.get(check_name, 0.5)
            total_weight += weight
            status = check_data.get('status', 'error')
            if status == 'success':
                summary['passed'] += 1
                weighted_passed += weight
            elif status == 'warning':
                summary['warnings'] += 1
                weighted_passed += weight * 0.5  # Warnings get half credit
            else:
                summary['errors'] += 1

        if total_weight > 0:
            base_score = (weighted_passed / total_weight) * 100
            summary['score'] = max(0, round(base_score))

        # Save to MongoDB
        report_id = None
        if MONGO_AVAILABLE and reports_collection is not None:
            try:
                report_id = f"lookup_{domain}_{int(datetime.now().timestamp())}"
                report_doc = {
                    '_id': report_id,
                    'type': 'domain_lookup',
                    'domain': domain,
                    'timestamp': datetime.now().isoformat(),
                    'checks': all_checks,
                    'summary': summary
                }
                reports_collection.insert_one(report_doc)
                print(f"[MONGO] Saved streaming lookup report: {report_id}")
            except Exception as e:
                print(f"[MONGO] Error saving streaming lookup report: {e}")

        # Send Telegram notification (async in thread)
        import threading
        def send_notification():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(send_telegram_report_notification(domain, summary, client_ip, report_id))
            loop.close()
        threading.Thread(target=send_notification, daemon=True).start()

        # Send completion event with report_id
        complete_data = {'domain': domain, 'total_checks': total_checks, 'summary': summary}
        if report_id:
            complete_data['report_id'] = report_id
            complete_data['report_url'] = f"/report/{report_id}"
        yield send_event('complete', complete_data)

    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no'
        }
    )


@app.route('/api/tools/report')
def full_domain_report():
    """Generate a comprehensive domain report with all checks."""
    domain = request.args.get('query', '').strip()

    if not domain:
        return jsonify({'error': 'Domain parameter is required'}), 400

    if not DNS_AVAILABLE:
        return jsonify({'error': 'DNS library not available'}), 500

    # Run all checks
    report = {
        'domain': domain,
        'timestamp': datetime.now().isoformat(),
        'checks': {},
        'summary': {
            'total': 0,
            'passed': 0,
            'warnings': 0,
            'errors': 0,
            'score': 0
        }
    }

    # DNS Checks
    report['checks']['mx'] = tool_mx_lookup(domain)
    report['checks']['mx']['rfc'] = RFC_TIPS['mx']

    report['checks']['a'] = tool_a_lookup(domain)
    report['checks']['a']['rfc'] = RFC_TIPS['a']

    report['checks']['aaaa'] = tool_aaaa_lookup(domain)
    report['checks']['aaaa']['rfc'] = RFC_TIPS['aaaa']

    report['checks']['ns'] = tool_ns_lookup(domain)
    report['checks']['ns']['rfc'] = RFC_TIPS['ns']

    report['checks']['txt'] = tool_txt_lookup(domain)

    # Email Authentication
    report['checks']['spf'] = tool_spf_lookup(domain)
    report['checks']['spf']['rfc'] = RFC_TIPS['spf']

    report['checks']['dkim'] = tool_dkim_lookup(domain)
    report['checks']['dkim']['rfc'] = RFC_TIPS['dkim']

    report['checks']['dmarc'] = tool_dmarc_lookup(domain)
    report['checks']['dmarc']['rfc'] = RFC_TIPS['dmarc']

    # SMTP Connectivity
    report['checks']['smtp'] = tool_smtp_check(domain)

    # Autodiscover
    report['checks']['autodiscover'] = tool_autodiscover_check(domain)

    # SSL Certificate (after autodiscover to check all endpoints)
    mx_records = report['checks']['mx'].get('records', [])
    report['checks']['ssl'] = tool_ssl_comprehensive_check(domain, mx_records, report['checks']['autodiscover'])

    # Blacklist check (if we have MX IPs)
    if report['checks']['mx'].get('records'):
        mx_host = report['checks']['mx']['records'][0]['host']
        try:
            mx_ips = dns.resolver.resolve(mx_host, 'A')
            mx_ip = str(mx_ips[0])
            report['checks']['blacklist'] = tool_blacklist_check(mx_ip)
            report['checks']['blacklist']['rfc'] = RFC_TIPS['blacklist']
            report['checks']['blacklist']['checked_ip'] = mx_ip
            report['checks']['blacklist']['checked_host'] = mx_host
        except:
            report['checks']['blacklist'] = {
                'tool': 'Blacklist Check',
                'status': 'warning',
                'message': 'Could not resolve MX server IP for blacklist check'
            }

    # Calculate summary with weighted scoring
    # Weights: critical checks have higher impact, optional checks have lower
    check_weights = {
        'mx': 1.0,          # Essential for email
        'spf': 1.0,         # Important authentication
        'dkim': 1.0,        # Important authentication
        'dmarc': 1.0,       # Important authentication
        'blacklist': 1.0,   # Critical security
        'a': 0.8,           # Basic DNS
        'ns': 0.8,          # Basic DNS
        'smtp': 0.8,        # Email connectivity
        'ssl': 0.8,         # Security
        'txt': 0.5,         # Informational
        'autodiscover': 0.4, # Optional (Exchange)
        'aaaa': 0.2,        # IPv6 is optional
    }

    weighted_passed = 0
    total_weight = 0

    for check_name, check_data in report['checks'].items():
        report['summary']['total'] += 1
        weight = check_weights.get(check_name, 0.5)
        total_weight += weight
        status = check_data.get('status', 'error')
        if status == 'success':
            report['summary']['passed'] += 1
            weighted_passed += weight
        elif status == 'warning':
            report['summary']['warnings'] += 1
            weighted_passed += weight * 0.5  # Warnings get half credit
        else:
            report['summary']['errors'] += 1

    # Calculate score (0-100) using weighted scoring
    if total_weight > 0:
        base_score = (weighted_passed / total_weight) * 100
        report['summary']['score'] = max(0, round(base_score))

    # Persist domain lookup report to MongoDB
    report_id = None
    if MONGO_AVAILABLE and reports_collection is not None:
        try:
            report_id = f"lookup_{domain}_{int(datetime.now().timestamp())}"
            report_copy = report.copy()
            report_copy['_id'] = report_id
            report_copy['type'] = 'domain_lookup'
            reports_collection.insert_one(report_copy)
            report['report_id'] = report_id
            report['report_url'] = f"/report/{report_id}"
            print(f"[MONGO] Saved domain lookup report: {report_id}")
        except Exception as e:
            print(f"[MONGO] Error saving domain lookup report: {e}")

    # Send Telegram notification (async, non-blocking)
    client_ip = request.headers.get('X-Forwarded-For', request.headers.get('X-Real-IP', request.remote_addr))
    if client_ip and ',' in client_ip:
        client_ip = client_ip.split(',')[0].strip()

    import threading
    def send_notification():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(send_telegram_report_notification(domain, report['summary'], client_ip, report_id))
        loop.close()

    threading.Thread(target=send_notification, daemon=True).start()

    return jsonify(report)


def run_smtp_server():
    """Run the SMTP server in a separate thread."""
    handler = MailHandler()
    # Max message size 1MB (1048576 bytes)
    controller = Controller(handler, hostname='0.0.0.0', port=SMTP_PORT, data_size_limit=1048576)
    controller.start()
    print(f"[SMTP] Server running on port {SMTP_PORT} (max message size: 1MB)")
    return controller


if __name__ == '__main__':
    print("=" * 50)
    print("  Mail Tester - Email Deliverability Analyzer")
    print("=" * 50)

    # Start SMTP server
    smtp_controller = run_smtp_server()

    # Start Flask web server
    print(f"[WEB] Server running on http://localhost:{WEB_PORT}")
    print(f"\nUsage:")
    print(f"  1. Open http://localhost:{WEB_PORT} in your browser")
    print(f"  2. Generate a test email address")
    print(f"  3. Send an email to the generated address via SMTP port {SMTP_PORT}")
    print(f"  4. View the analysis results")
    print("=" * 50)

    try:
        app.run(host='0.0.0.0', port=WEB_PORT, debug=False)
    finally:
        smtp_controller.stop()
