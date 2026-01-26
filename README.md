# MXLab

**Email Deliverability & DNS Analysis Tool**

MXLab is a comprehensive, self-hosted alternative to mail-tester.com for analyzing email configuration and deliverability.

## Features

### MXtest - Email Analysis
- Generate temporary test email addresses
- Receive and analyze emails via built-in SMTP server
- Check SPF, DKIM, DMARC authentication
- Verify email headers and content
- Score-based deliverability rating (0-10)

### MXlab Lookup - DNS Tools
- **MX Lookup**: Find mail servers with resolved IP addresses
- **SPF Lookup**: Recursive SPF record analysis with include resolution
- **DKIM Lookup**: Check multiple common selectors automatically
- **DMARC Lookup**: Parse and display DMARC policies
- **SMTP Connectivity**: Full connection logs with HELO/EHLO testing
- **Autodiscover**: Check Exchange/Outlook autodiscover with SSL certificate validation
- **Blacklist Check**: Monitor IP reputation across major blacklists
- **DNS Records**: A, AAAA, NS, TXT, CNAME, SOA lookups

### Additional Features
- Real-time streaming results (Server-Sent Events)
- Progressive loading UI
- Persistent reports with shareable URLs
- Optional Telegram notifications
- Docker deployment ready

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              DOCKER COMPOSE                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────┐    ┌─────────────────────────┐ │
│  │            MXLab Container              │    │   MongoDB Container     │ │
│  │                                         │    │                         │ │
│  │  ┌─────────────────────────────────┐   │    │  ┌───────────────────┐  │ │
│  │  │         Flask Web Server        │   │    │  │    reports DB     │  │ │
│  │  │            (port 5000)          │   │    │  │                   │  │ │
│  │  │                                 │   │    │  │  - email_test     │  │ │
│  │  │  /              → Web UI        │   │    │  │  - domain_lookup  │  │ │
│  │  │  /report/<id>   → Report Page   │◄─────────►│                   │  │ │
│  │  │  /api/*         → REST API      │   │    │  └───────────────────┘  │ │
│  │  └─────────────────────────────────┘   │    │                         │ │
│  │                                         │    │     mongodb:27017       │ │
│  │  ┌─────────────────────────────────┐   │    └─────────────────────────┘ │
│  │  │       aiosmtpd SMTP Server      │   │                                │
│  │  │            (port 25)            │   │    ┌─────────────────────────┐ │
│  │  │                                 │   │    │   Telegram API          │ │
│  │  │  Receives test emails           │   │    │   (optional)            │ │
│  │  │  Triggers analysis              │───────►│                         │ │
│  │  │  Stores results                 │   │    │  Notifications on:      │ │
│  │  └─────────────────────────────────┘   │    │  - Email received       │ │
│  │                                         │    │  - Domain report done   │ │
│  └─────────────────────────────────────────┘    └─────────────────────────┘ │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
         │                    │
         │ :8080              │ :25
         ▼                    ▼
┌─────────────────┐  ┌─────────────────────────────────────────────────────────┐
│   Web Browser   │  │                    External Mail Servers                │
│                 │  │                                                         │
│  - Generate     │  │  Sender MTA ──► SMTP ──► MXLab ──► Analysis ──► Report │
│    test email   │  │                                                         │
│  - View reports │  └─────────────────────────────────────────────────────────┘
│  - DNS lookups  │
└─────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                            DATA FLOW                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  MXtest (Email Analysis):                                                   │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌───────┐ │
│  │ Generate │───►│  Send    │───►│ Receive  │───►│ Analyze  │───►│ Store │ │
│  │ Address  │    │  Email   │    │  SMTP    │    │  Email   │    │ Report│ │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘    └───────┘ │
│                                                        │              │     │
│                                                        ▼              ▼     │
│                                                   ┌─────────┐   ┌────────┐ │
│                                                   │Telegram │   │MongoDB │ │
│                                                   │  Notify │   │        │ │
│                                                   └─────────┘   └────────┘ │
│                                                                             │
│  MXlab Lookup (DNS Analysis):                                               │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐             │
│  │  Enter   │───►│  Query   │───►│ Stream   │───►│  Store   │             │
│  │  Domain  │    │  DNS     │    │ Results  │    │  Report  │             │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘             │
│                       │                               │                     │
│                       ▼                               ▼                     │
│              ┌─────────────────┐              ┌─────────────┐              │
│              │ MX, SPF, DKIM,  │              │ /report/<id>│              │
│              │ DMARC, SMTP,    │              │ Permanent   │              │
│              │ Blacklist, etc. │              │ URL         │              │
│              └─────────────────┘              └─────────────┘              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Using Docker (Recommended)

1. Clone the repository:
```bash
git clone https://github.com/igrbtn/mxlab_pub.git
cd mxlab_pub
```

2. Create environment file:
```bash
cp .env.example .env
```

3. Edit `.env` and set your domain:
```bash
DOMAIN=mxlab.yourdomain.com
```

4. Build and run:
```bash
docker-compose up -d
```

5. Access the web interface at `http://localhost:8080`

### Manual Installation

1. Install Python 3.8+ and dependencies:
```bash
pip install -r requirements.txt
```

2. Set environment variables:
```bash
export DOMAIN=mxlab.yourdomain.com
export SMTP_PORT=25
export WEB_PORT=5000
```

3. Run the application:
```bash
python app.py
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DOMAIN` | `localhost` | Your server's domain name |
| `SMTP_PORT` | `25` | SMTP server port |
| `WEB_PORT` | `5000` | Web interface port |
| `MONGO_URI` | `mongodb://mongodb:27017/` | MongoDB connection string |
| `TELEGRAM_BOT_TOKEN` | *(empty)* | Optional: Telegram bot token for notifications |
| `TELEGRAM_CHAT_ID` | *(empty)* | Optional: Telegram chat ID for notifications |

### DNS Configuration

For full functionality, configure these DNS records for your domain:

```
# A record for web access
mxlab.yourdomain.com    A       YOUR_SERVER_IP

# MX record to receive test emails
mxlab.yourdomain.com    MX  10  mxlab.yourdomain.com
```

### Firewall Ports

Ensure these ports are open:
- **25** (SMTP) - For receiving test emails
- **8080** (or your configured port) - Web interface

## Usage

### Testing Email Deliverability

1. Open the MXLab web interface
2. Click "Generate Test Email Address"
3. Send an email from your mail server to the generated address
4. View the analysis results including:
   - Overall score (0-10)
   - SPF verification
   - DKIM signature check
   - DMARC compliance
   - Header analysis
   - Content review

### Domain Lookup

1. Switch to the "MXlab Lookup" tab
2. Enter a domain name
3. Click "Full Domain Report"
4. View progressive results as each check completes

## Docker Deployment

### Production Setup

For production, consider:

1. **Reverse Proxy**: Use nginx/traefik with SSL termination
2. **Port 25**: Many cloud providers block port 25; you may need a VPS
3. **PTR Record**: Set up reverse DNS for your server IP
4. **Firewall**: Restrict access as needed

Example nginx configuration:
```nginx
server {
    listen 443 ssl;
    server_name mxlab.yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_cache_bypass $http_upgrade;
    }
}
```

## Optional: Telegram Notifications

To receive notifications when emails are tested or domain reports are generated:

1. Create a Telegram bot via [@BotFather](https://t.me/BotFather)
2. Get your chat ID (send a message to [@userinfobot](https://t.me/userinfobot))
3. Add to your `.env`:
```bash
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/generate` | POST | Generate test email address |
| `/api/check/<test_id>` | GET | Check if email received |
| `/api/results/<test_id>` | GET | Get full analysis results (JSON) |
| `/report/<test_id>` | GET | View report page (HTML) |
| `/api/tools/<tool>?query=<domain>` | GET | Run individual DNS tool |
| `/api/tools/report?query=<domain>` | GET | Full domain report (JSON) |
| `/api/tools/report/stream?query=<domain>` | GET | Streaming domain report (SSE) |

### Available Tools
`mx`, `dns`, `txt`, `spf`, `dkim`, `dmarc`, `ptr`, `blacklist`, `ns`, `soa`, `cname`, `aaaa`

## Tech Stack

- **Backend**: Python, Flask, aiosmtpd
- **Database**: MongoDB (persistent reports)
- **DNS**: dnspython
- **DKIM**: dkimpy
- **Frontend**: Vanilla JavaScript, CSS
- **Deployment**: Docker Compose

## License

MIT License - See LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

For issues and feature requests, please use the GitHub issue tracker.
