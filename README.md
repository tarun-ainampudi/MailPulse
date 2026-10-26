# MailPulse — Email Deliverability & MX Verification

MailPulse is a lightweight, privacy-focused web application for checking email address syntax, identifying disposable and role-based email addresses, and verifying domain mail configuration through DNS-over-HTTPS (DoH).

The application runs entirely in the browser without requiring a backend server or sending test emails.

## Features

- **Email Validation:** Checks email syntax, length, and formatting rules based on RFC 5322.
- **MX Record Verification:** Queries Cloudflare and Google DNS-over-HTTPS endpoints to check domain mail exchange records.
- **Email Classification:** Identifies disposable email domains, free webmail providers, and role-based addresses.
- **Deliverability Assessment:** Classifies addresses as `Likely Delivered`, `Likely to Bounce`, or `Unknown` based on available checks.
- **Dashboard:** Displays verification statistics and results using Chart.js.
- **Data Export:** Exports verification results to CSV and JSON files.
- **Privacy-Focused:** Performs validation and DNS lookups directly from the browser, without a backend or SMTP probing.

## Requirements

- A modern web browser such as Chrome, Firefox, Safari, or Edge.
- An internet connection for DNS lookups and CDN-hosted dependencies.
- An optional local development server for serving the application.

## Installation and Usage

Clone the repository:

```bash
git clone https://github.com/your-username/mailpulse.git
cd mailpulse
```

Open `index.html` in your browser, or start a local development server:

```bash
npx serve
```

Then:

1. Open the application in your browser.
2. Enter email addresses separated by commas, semicolons, or newlines.
3. Click **Load Sample Emails** to try the application with sample data, or enter your own addresses.
4. Click **Verify All Addresses** to start verification.
5. Review the results and export them as CSV or JSON.

## Project Structure

```text
mailpulse/
├── index.html    # Application structure and layout
├── styles.css    # Custom styles and visual enhancements
├── app.js        # Validation, DNS lookups, and UI logic
└── README.md     # Project documentation
```

## How It Works

1. **Input Parsing:** Extracts email addresses from comma-, semicolon-, or newline-separated input.
2. **Syntax Validation:** Checks email formatting and applicable length constraints.
3. **Heuristic Checks:** Identifies disposable domains, free email providers, and role-based addresses.
4. **DNS Verification:** Queries MX records through Cloudflare and Google DoH APIs. If no MX records are found, it checks for an A record as a fallback.
5. **Result Classification:** Combines syntax, DNS, and heuristic results to estimate email deliverability.

## Limitations

- **Mailbox Existence:** DNS records confirm domain-level mail configuration, not whether a specific mailbox exists.
- **Deliverability Estimates:** Results indicate likelihood, not guaranteed delivery. Mailbox availability, recipient-server policies, and other factors cannot be fully verified without additional checks.
- **Unknown Results:** Some domains may return inconclusive results due to DNS failures, provider restrictions, or ambiguous configurations.
- **No SMTP Verification:** The application does not connect to SMTP servers or send test emails.
- **External Dependencies:** DNS queries and CDN-hosted libraries require an internet connection. Browser policies, network restrictions, or service outages may affect functionality.

## Technology Stack

- HTML5
- CSS3
- Vanilla JavaScript
- Tailwind CSS
- Chart.js
- Lucide Icons
- Cloudflare and Google DNS-over-HTTPS APIs

## Privacy

Email validation and result processing take place in the browser. The application does not require a backend server or send test emails. DNS queries disclose the domain being queried to the selected DNS provider.
## License

This project is open-source and available for personal and commercial use.
