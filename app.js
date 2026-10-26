tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          colors: {
            brand: {
              50: '#eef2ff',
              100: '#e0e7ff',
              500: '#6366f1',
              600: '#4f46e5',
              700: '#4338ca',
            }
          }
        }
      }
    }

/* ==========================================================================
       DATA & CONSTANTS
       ========================================================================== */
    
    // Known disposable / burner email domains
    const DISPOSABLE_DOMAINS = new Set([
      '10minutemail.com', '10minutemail.net', 'guerrillamail.com', 'guerrillamail.info', 
      'mailinator.com', 'temp-mail.org', 'tempmail.net', 'throwawaymail.com', 
      'yopmail.com', 'trashmail.com', 'getairmail.com', 'sharklasers.com', 
      'fakemailgenerator.com', 'dispostable.com', 'nada.ltd', 'mohmal.com',
      'burnermail.io', 'inboxkitten.com', 'crazymailing.com', 'mytemp.email',
      'emailondeck.com', 'tempr.email', 'disposablemail.com', 'generator.email'
    ]);

    // Known free consumer webmail domains
    const FREE_WEBMAIL_DOMAINS = new Set([
      'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.uk', 'yahoo.fr',
      'hotmail.com', 'outlook.com', 'live.com', 'msn.com', 'icloud.com',
      'me.com', 'mac.com', 'aol.com', 'protonmail.com', 'proton.me', 'zoho.com',
      'gmx.com', 'gmx.net', 'mail.com', 'yandex.com', 'fastmail.com'
    ]);

    // Role-based prefixes (e.g. support@, admin@)
    const ROLE_PREFIXES = new Set([
      'admin', 'administrator', 'support', 'help', 'info', 'sales', 'billing',
      'contact', 'jobs', 'careers', 'marketing', 'press', 'media', 'team',
      'hr', 'legal', 'compliance', 'abuse', 'postmaster', 'hostmaster',
      'webmaster', 'security', 'privacy', 'office', 'general', 'inquiries'
    ]);

    // Sample emails showcasing varied conditions
    const SAMPLE_EMAILS = [
      'support@google.com',
      'contact@stripe.com',
      'hello@github.com',
      'team@cloudflare.com',
      'invalid..format@@broken.com',
      'user@nonexistent-fake-domain-99482.xyz',
      'burner-tester@10minutemail.com',
      'admin@microsoft.com',
      'missingtld@domain',
      'info@amazon.com',
      'developer@random-throwaway-inbox.yopmail.com',
      'sarah.connor@gmail.com'
    ];

    /* ==========================================================================
       APPLICATION STATE
       ========================================================================== */
    let currentResults = [];
    let currentFilter = 'all';
    let statusChartInstance = null;

    /* ==========================================================================
       CORE VALIDATION & DOH DNS ENGINE
       ========================================================================== */

    /**
     * Checks RFC 5322 conformity with practical syntax rules.
     */
    function validateEmailSyntax(email) {
      if (!email || typeof email !== 'string') return { valid: false, reason: 'Empty address' };
      email = email.trim();

      // RFC 5322 compliant regex (practical)
      const rfcRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

      if (email.length > 254) {
        return { valid: false, reason: 'Total length exceeds 254 characters' };
      }

      const parts = email.split('@');
      if (parts.length !== 2) {
        return { valid: false, reason: 'Address must contain exactly one "@" symbol' };
      }

      const [local, domain] = parts;
      if (local.length === 0) return { valid: false, reason: 'Missing username before "@"' };
      if (local.length > 64) return { valid: false, reason: 'Local username exceeds 64 characters' };
      if (local.startsWith('.') || local.endsWith('.')) return { valid: false, reason: 'Username cannot start or end with a dot' };
      if (local.includes('..')) return { valid: false, reason: 'Username contains consecutive dots' };

      if (!domain) return { valid: false, reason: 'Missing domain after "@"' };
      if (domain.length > 253) return { valid: false, reason: 'Domain exceeds 253 characters' };
      if (!domain.includes('.')) return { valid: false, reason: 'Domain lacks a top-level domain (TLD)' };
      if (domain.startsWith('.') || domain.endsWith('.')) return { valid: false, reason: 'Domain cannot begin or end with a dot' };
      if (domain.startsWith('-') || domain.endsWith('-')) return { valid: false, reason: 'Domain labels cannot begin or end with a hyphen' };

      const tld = domain.split('.').pop();
      if (!tld || tld.length < 2) return { valid: false, reason: 'Invalid or missing TLD extension' };

      if (!rfcRegex.test(email)) {
        return { valid: false, reason: 'Contains illegal characters or invalid format' };
      }

      return { valid: true, local, domain: domain.toLowerCase() };
    }

    /**
     * Resolves DNS MX records using Cloudflare and Google DNS-over-HTTPS (DoH).
     * This avoids raw TCP Port 25 restrictions enforced by hosts like Render/Railway.
     */
    async function queryMxRecordsDoH(domain) {
      // 1. First attempt: Cloudflare DNS-over-HTTPS (type 15 = MX)
      try {
        const cfUrl = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=MX`;
        const res = await fetch(cfUrl, {
          headers: { 'Accept': 'application/dns-json' },
          cache: 'no-store'
        });
        
        if (res.ok) {
          const data = await res.json();
          // Status 0 = NOERROR, Status 3 = NXDOMAIN
          if (data.Status === 3) {
            return { success: false, status: 'NXDOMAIN', mx: [], reason: 'Domain does not exist (NXDOMAIN)' };
          }
          if (data.Answer && Array.isArray(data.Answer) && data.Answer.length > 0) {
            const mxRecords = data.Answer
              .filter(rec => rec.type === 15)
              .map(rec => {
                // Cloudflare DoH format: "priority host." e.g. "10 aspmx.l.google.com."
                const parts = rec.data ? rec.data.split(' ') : [];
                return {
                  priority: parts[0] || '10',
                  host: (parts[1] || rec.data || '').replace(/\.$/, '')
                };
              });

            if (mxRecords.length > 0) {
              return { success: true, status: 'FOUND', mx: mxRecords, provider: 'Cloudflare DoH' };
            }
          }
        }
      } catch (err) {
        // Fallback to Google DoH if Cloudflare fails or is blocked
        console.warn('Cloudflare DoH attempt failed, falling back to Google DoH:', err);
      }

      // 2. Secondary fallback: Google Public DNS DoH
      try {
        const googleUrl = `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=MX`;
        const res = await fetch(googleUrl, { cache: 'no-store' });
        if (res.ok) {
          const data = await res.json();
          if (data.Status === 3) {
            return { success: false, status: 'NXDOMAIN', mx: [], reason: 'Domain does not exist (NXDOMAIN)' };
          }
          if (data.Answer && Array.isArray(data.Answer) && data.Answer.length > 0) {
            const mxRecords = data.Answer
              .filter(rec => rec.type === 15)
              .map(rec => {
                const parts = rec.data ? rec.data.split(' ') : [];
                return {
                  priority: parts[0] || '10',
                  host: (parts[1] || rec.data || '').replace(/\.$/, '')
                };
              });

            if (mxRecords.length > 0) {
              return { success: true, status: 'FOUND', mx: mxRecords, provider: 'Google DoH' };
            }
          }
        }
      } catch (err) {
        console.warn('Google DoH lookup also failed:', err);
      }

      // 3. Fallback check for A record if no MX (RFC 5321 allows implicit MX via A record)
      try {
        const aUrl = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`;
        const res = await fetch(aUrl, { headers: { 'Accept': 'application/dns-json' } });
        if (res.ok) {
          const data = await res.json();
          if (data.Status === 3) {
            return { success: false, status: 'NXDOMAIN', mx: [], reason: 'Domain does not exist (NXDOMAIN)' };
          }
          if (data.Answer && data.Answer.length > 0) {
            return { 
              success: true, 
              status: 'A_RECORD_FALLBACK', 
              mx: [{ priority: '0', host: `[A Record Fallback] ${domain}` }],
              reason: 'No explicit MX record, but valid A host record exists'
            };
          }
        }
      } catch (e) {
        // Network failure
      }

      return { 
        success: false, 
        status: 'NO_MX', 
        mx: [], 
        reason: 'No MX or mail exchanger DNS records configured for this domain' 
      };
    }

    /**
     * Evaluates an individual email string into Deliverability Status.
     */
    async function evaluateEmail(rawEmail, options = {}) {
      const email = (rawEmail || '').trim();
      const syntax = validateEmailSyntax(email);

      if (!syntax.valid) {
        return {
          email,
          status: 'bounce',
          statusLabel: 'Likely to Bounce',
          badgeClass: 'bg-rose-100 text-rose-800 border-rose-200',
          reason: `Syntax error: ${syntax.reason}`,
          syntaxValid: false,
          isDisposable: false,
          isRole: false,
          isFree: false,
          mxRecords: [],
          domain: 'N/A'
        };
      }

      const { local, domain } = syntax;
      const isDisposable = DISPOSABLE_DOMAINS.has(domain);
      const isFree = FREE_WEBMAIL_DOMAINS.has(domain);
      const isRole = ROLE_PREFIXES.has(local.toLowerCase());

      // If disposable domain & user selected to flag as bounce
      if (isDisposable && options.skipDisposable) {
        return {
          email,
          status: 'bounce',
          statusLabel: 'Likely to Bounce',
          badgeClass: 'bg-rose-100 text-rose-800 border-rose-200',
          reason: 'Burner / disposable temporary email service detected',
          syntaxValid: true,
          isDisposable: true,
          isRole,
          isFree: false,
          mxRecords: [],
          domain
        };
      }

      // Check MX via live DoH
      const dnsResult = await queryMxRecordsDoH(domain);

      if (!dnsResult.success) {
        return {
          email,
          status: 'bounce',
          statusLabel: 'Likely to Bounce',
          badgeClass: 'bg-rose-100 text-rose-800 border-rose-200',
          reason: dnsResult.reason || 'Domain has no configured Mail Exchangers (MX)',
          syntaxValid: true,
          isDisposable,
          isRole,
          isFree,
          mxRecords: [],
          domain
        };
      }

      // If MX exists, analyze whether it is Likely Delivered or Unknown
      // In industry practice, free webmail (gmail/yahoo/outlook) or catch-all corporate domains
      // cannot guarantee mailbox existence without sending a real message.
      if (isDisposable) {
        return {
          email,
          status: 'bounce',
          statusLabel: 'Likely to Bounce',
          badgeClass: 'bg-rose-100 text-rose-800 border-rose-200',
          reason: 'Active MX exists, but provider is a known temporary burner service',
          syntaxValid: true,
          isDisposable: true,
          isRole,
          isFree: false,
          mxRecords: dnsResult.mx,
          domain
        };
      }

      // For standard legitimate domains with active MX
      // Major providers (Gmail, Outlook, Yahoo) disable VRFY and reject fake RCPT TO handshakes:
      // Hence, for personal consumer accounts or unverified corporate mailboxes, "Unknown" is the correct RFC status.
      // High-confidence role accounts on major corporate domains (e.g. support@google.com, contact@stripe.com)
      // or reputable custom domains are classified with high deliverability.
      let finalStatus = 'delivered';
      let finalLabel = 'Likely Delivered';
      let finalBadge = 'bg-emerald-100 text-emerald-800 border-emerald-200';
      let finalReason = `Valid RFC syntax & active mail exchanger (${dnsResult.mx[0].host}) confirmed.`;

      // If it's a personal consumer email on Gmail/Outlook/etc. where individual existence is guarded:
      if (isFree) {
        // Individual mailbox cannot be guaranteed without live SMTP transaction
        finalStatus = 'unknown';
        finalLabel = 'Unknown';
        finalBadge = 'bg-amber-100 text-amber-800 border-amber-200';
        finalReason = `Domain mail servers are active (${dnsResult.mx[0].host}), but mailbox exists behind anti-harvesting protection; unconfirmable without sending.`;
      } else if (isRole) {
        finalStatus = 'delivered';
        finalLabel = 'Likely Delivered';
        finalBadge = 'bg-emerald-100 text-emerald-800 border-emerald-200';
        finalReason = `Standard role address on authenticated domain with active MX (${dnsResult.mx[0].host}).`;
      }

      return {
        email,
        status: finalStatus,
        statusLabel: finalLabel,
        badgeClass: finalBadge,
        reason: finalReason,
        syntaxValid: true,
        isDisposable: false,
        isRole,
        isFree,
        mxRecords: dnsResult.mx,
        domain
      };
    }

    /* ==========================================================================
       USER INTERFACE RENDERING & EVENT LISTENERS
       ========================================================================== */

    const emailInput = document.getElementById('emailInput');
    const detectedCount = document.getElementById('detectedCount');
    const startVerifyBtn = document.getElementById('startVerifyBtn');
    const verifyBtnLabel = document.getElementById('verifyBtnLabel');
    const clearBtn = document.getElementById('clearBtn');
    const skipDisposable = document.getElementById('skipDisposable');
    const progressContainer = document.getElementById('progressContainer');
    const progressBar = document.getElementById('progressBar');
    const progressPercent = document.getElementById('progressPercent');
    const progressLabel = document.getElementById('progressLabel');
    const resultsTableBody = document.getElementById('resultsTableBody');
    const tableEmptyState = document.getElementById('tableEmptyState');
    const tableResultsCount = document.getElementById('tableResultsCount');
    const tableSearch = document.getElementById('tableSearch');

    // Metrics elements
    const metricTotal = document.getElementById('metricTotal');
    const metricDelivered = document.getElementById('metricDelivered');
    const metricDeliveredRate = document.getElementById('metricDeliveredRate');
    const metricBounce = document.getElementById('metricBounce');
    const metricBounceRate = document.getElementById('metricBounceRate');
    const metricUnknown = document.getElementById('metricUnknown');
    const metricUnknownRate = document.getElementById('metricUnknownRate');
    const statMxFound = document.getElementById('statMxFound');
    const statNoMx = document.getElementById('statNoMx');
    const statDisposable = document.getElementById('statDisposable');
    const statRole = document.getElementById('statRole');

    // Modals
    const detailModal = document.getElementById('detailModal');
    const docsModal = document.getElementById('docsModal');
    const openDocsBtn = document.getElementById('openDocsBtn');
    const footerDocsLink = document.getElementById('footerDocsLink');
    const closeDocsBtn = document.getElementById('closeDocsBtn');
    const closeDocsFooterBtn = document.getElementById('closeDocsFooterBtn');
    const closeModalBtn = document.getElementById('closeModalBtn');
    const closeModalFooterBtn = document.getElementById('closeModalFooterBtn');

    // Export Dropdown
    const exportDropdownBtn = document.getElementById('exportDropdownBtn');
    const exportMenu = document.getElementById('exportMenu');
    const exportCsvBtn = document.getElementById('exportCsvBtn');
    const exportJsonBtn = document.getElementById('exportJsonBtn');

    // Parse input string into individual clean email strings
    function parseInputEmails(rawText) {
      if (!rawText) return [];
      return rawText
        .split(/[\n,;]+/)
        .map(e => e.replace(/["'<>]/g, '').trim())
        .filter(e => e.length > 0);
    }

    // Update input counter
    function updateEmailCounter() {
      const list = parseInputEmails(emailInput.value);
      detectedCount.textContent = `${list.length} email${list.length === 1 ? '' : 's'} detected`;
    }

    emailInput.addEventListener('input', updateEmailCounter);

    // Load sample emails button
    document.getElementById('openSampleBtn').addEventListener('click', () => {
      emailInput.value = SAMPLE_EMAILS.join('\n');
      updateEmailCounter();
    });

    // Clear input
    clearBtn.addEventListener('click', () => {
      emailInput.value = '';
      updateEmailCounter();
    });

    // Initialize Chart.js
    function initChart() {
      const ctx = document.getElementById('statusChart').getContext('2d');
      statusChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
          labels: ['Likely Delivered', 'Likely Bounce', 'Unknown'],
          datasets: [{
            data: [0, 0, 0],
            backgroundColor: ['#10b981', '#ef4444', '#f59e0b'],
            borderWidth: 2,
            borderColor: '#ffffff',
            hoverOffset: 4
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: '72%',
          plugins: {
            legend: { display: false },
            tooltip: {
              callbacks: {
                label: function(context) {
                  return ` ${context.label}: ${context.raw}`;
                }
              }
            }
          }
        }
      });
    }

    // Refresh Statistics & Chart
    function updateMetrics() {
      const total = currentResults.length;
      const delivered = currentResults.filter(r => r.status === 'delivered').length;
      const bounce = currentResults.filter(r => r.status === 'bounce').length;
      const unknown = currentResults.filter(r => r.status === 'unknown').length;

      const mxFoundCount = currentResults.filter(r => r.mxRecords && r.mxRecords.length > 0).length;
      const noMxCount = currentResults.filter(r => !r.mxRecords || r.mxRecords.length === 0).length;
      const disposableCount = currentResults.filter(r => r.isDisposable).length;
      const roleCount = currentResults.filter(r => r.isRole).length;

      metricTotal.textContent = total;
      metricDelivered.textContent = delivered;
      metricBounce.textContent = bounce;
      metricUnknown.textContent = unknown;

      metricDeliveredRate.textContent = total > 0 ? `${Math.round((delivered / total) * 100)}% of total` : '0% of total';
      metricBounceRate.textContent = total > 0 ? `${Math.round((bounce / total) * 100)}% of total` : '0% of total';
      metricUnknownRate.textContent = total > 0 ? `${Math.round((unknown / total) * 100)}% of total` : '0% of total';

      statMxFound.textContent = mxFoundCount;
      statNoMx.textContent = noMxCount;
      statDisposable.textContent = disposableCount;
      statRole.textContent = roleCount;

      const placeholder = document.getElementById('chartEmptyPlaceholder');
      if (total > 0) {
        placeholder.classList.add('hidden');
        if (statusChartInstance) {
          statusChartInstance.data.datasets[0].data = [delivered, bounce, unknown];
          statusChartInstance.update();
        }
      } else {
        placeholder.classList.remove('hidden');
        if (statusChartInstance) {
          statusChartInstance.data.datasets[0].data = [0, 0, 0];
          statusChartInstance.update();
        }
      }
    }

    // Render Table rows according to search & filter
    function renderTable() {
      const searchTerm = (tableSearch.value || '').toLowerCase().trim();
      
      const filtered = currentResults.filter(item => {
        const matchesFilter = currentFilter === 'all' || item.status === currentFilter;
        const matchesSearch = !searchTerm || 
          item.email.toLowerCase().includes(searchTerm) || 
          item.reason.toLowerCase().includes(searchTerm) ||
          item.domain.toLowerCase().includes(searchTerm);
        return matchesFilter && matchesSearch;
      });

      tableResultsCount.textContent = `Showing ${filtered.length} of ${currentResults.length} result${currentResults.length === 1 ? '' : 's'}`;

      if (filtered.length === 0) {
        resultsTableBody.innerHTML = `
          <tr>
            <td colspan="6" class="py-12 text-center text-slate-400">
              <div class="flex flex-col items-center justify-center space-y-1">
                <i data-lucide="search-x" class="w-6 h-6 text-slate-300"></i>
                <p class="font-medium text-slate-600">No matching emails found</p>
                <p class="text-xs text-slate-400">Try adjusting your search terms or filter selection.</p>
              </div>
            </td>
          </tr>
        `;
        lucide.createIcons();
        return;
      }

      resultsTableBody.innerHTML = '';
      filtered.forEach((item, index) => {
        const tr = document.createElement('tr');
        tr.className = 'hover:bg-slate-50/80 transition-colors border-b border-slate-100';

        // MX display summary
        let mxSummary = '<span class="text-slate-400 italic">None</span>';
        if (item.mxRecords && item.mxRecords.length > 0) {
          const topMx = item.mxRecords[0];
          const extra = item.mxRecords.length > 1 ? ` <span class="text-[10px] text-slate-400 font-mono">+${item.mxRecords.length - 1} more</span>` : '';
          mxSummary = `<span class="font-mono text-[11px] text-slate-700 font-medium">${topMx.host}</span>${extra}`;
        }

        // Tags
        let badgesHtml = '';
        if (item.isRole) {
          badgesHtml += '<span class="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-bold bg-blue-50 text-blue-700 border border-blue-200 mr-1">Role</span>';
        }
        if (item.isDisposable) {
          badgesHtml += '<span class="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-bold bg-purple-50 text-purple-700 border border-purple-200 mr-1">Burner</span>';
        }
        if (item.isFree) {
          badgesHtml += '<span class="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-bold bg-slate-100 text-slate-700 border border-slate-200 mr-1">Webmail</span>';
        }
        if (!badgesHtml) {
          badgesHtml = '<span class="text-slate-400 text-[11px]">Standard</span>';
        }

        // Status badge icon
        let statusIcon = 'check-circle-2';
        if (item.status === 'bounce') statusIcon = 'x-circle';
        if (item.status === 'unknown') statusIcon = 'help-circle';

        tr.innerHTML = `
          <td class="py-3 px-4">
            <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-bold border ${item.badgeClass}">
              <i data-lucide="${statusIcon}" class="w-3.5 h-3.5"></i>
              ${item.statusLabel}
            </span>
          </td>
          <td class="py-3 px-4">
            <div class="font-mono font-medium text-slate-900">${escapeHtml(item.email)}</div>
            <div class="text-[10px] text-slate-400">${item.domain}</div>
          </td>
          <td class="py-3 px-4">
            ${mxSummary}
          </td>
          <td class="py-3 px-4">
            ${badgesHtml}
          </td>
          <td class="py-3 px-4 text-slate-600 max-w-xs truncate" title="${escapeHtml(item.reason)}">
            ${escapeHtml(item.reason)}
          </td>
          <td class="py-3 px-4 text-right">
            <button class="view-detail-btn px-2.5 py-1 text-xs font-semibold text-indigo-600 hover:text-indigo-800 hover:bg-indigo-50 rounded-lg transition-colors border border-indigo-100" data-index="${index}">
              Inspect
            </button>
          </td>
        `;

        resultsTableBody.appendChild(tr);
      });

      // Bind inspect buttons
      document.querySelectorAll('.view-detail-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
          const idx = parseInt(btn.getAttribute('data-index'), 10);
          showDetailModal(filtered[idx]);
        });
      });

      lucide.createIcons();
    }

    function escapeHtml(text) {
      if (!text) return '';
      return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
    }

    // Modal Display
    function showDetailModal(item) {
      if (!item) return;
      document.getElementById('modalEmailTitle').textContent = item.email;
      const statusBadge = document.getElementById('modalStatusBadge');
      statusBadge.className = `px-2.5 py-0.5 rounded-full text-xs font-bold border ${item.badgeClass}`;
      statusBadge.textContent = item.statusLabel;

      document.getElementById('modalReason').textContent = item.reason;
      document.getElementById('modalSyntax').textContent = item.syntaxValid ? 'Compliant (RFC 5322)' : 'Invalid Syntax';
      document.getElementById('modalCategory').textContent = item.isFree ? 'Free Webmail Service' : 'Corporate / Custom Domain';
      document.getElementById('modalDisposable').textContent = item.isDisposable ? 'Yes (Burner Domain)' : 'No (Legitimate Host)';
      document.getElementById('modalRole').textContent = item.isRole ? 'Yes (Role-based mailbox)' : 'No (Direct Named Recipient)';

      const mxContainer = document.getElementById('modalMxList');
      if (item.mxRecords && item.mxRecords.length > 0) {
        mxContainer.innerHTML = item.mxRecords
          .map(r => `<div class="py-0.5"><span class="text-indigo-400 font-bold">Pref ${r.priority}</span> &rarr; ${escapeHtml(r.host)}</div>`)
          .join('');
      } else {
        mxContainer.innerHTML = '<span class="text-rose-400">No MX or Mail Exchanger DNS records found for this domain.</span>';
      }

      detailModal.classList.remove('hidden');
    }

    closeModalBtn.addEventListener('click', () => detailModal.classList.add('hidden'));
    closeModalFooterBtn.addEventListener('click', () => detailModal.classList.add('hidden'));
    detailModal.addEventListener('click', (e) => {
      if (e.target === detailModal) detailModal.classList.add('hidden');
    });

    // Docs / Limitations Modal
    function openDocs() {
      docsModal.classList.remove('hidden');
    }
    openDocsBtn.addEventListener('click', openDocs);
    footerDocsLink.addEventListener('click', (e) => { e.preventDefault(); openDocs(); });
    closeDocsBtn.addEventListener('click', () => docsModal.classList.add('hidden'));
    closeDocsFooterBtn.addEventListener('click', () => docsModal.classList.add('hidden'));
    docsModal.addEventListener('click', (e) => {
      if (e.target === docsModal) docsModal.classList.add('hidden');
    });

    // Filter Buttons
    document.querySelectorAll('.filter-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.filter-btn').forEach(b => {
          b.classList.remove('bg-white', 'shadow-xs', 'text-slate-900');
          b.classList.add('text-slate-600');
        });
        btn.classList.add('bg-white', 'shadow-xs', 'text-slate-900');
        btn.classList.remove('text-slate-600');

        currentFilter = btn.getAttribute('data-filter');
        renderTable();
      });
    });

    tableSearch.addEventListener('input', renderTable);

    // Export Dropdown Toggle
    exportDropdownBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      exportMenu.classList.toggle('hidden');
    });
    window.addEventListener('click', () => {
      if (!exportMenu.classList.contains('hidden')) {
        exportMenu.classList.add('hidden');
      }
    });

    // Export CSV
    exportCsvBtn.addEventListener('click', () => {
      if (currentResults.length === 0) return;
      const headers = ['Email', 'Status', 'Domain', 'Reason', 'Syntax Valid', 'Disposable', 'Role Account', 'MX Records'];
      const rows = currentResults.map(r => [
        `"${r.email}"`,
        `"${r.statusLabel}"`,
        `"${r.domain}"`,
        `"${r.reason.replace(/"/g, '""')}"`,
        r.syntaxValid ? 'YES' : 'NO',
        r.isDisposable ? 'YES' : 'NO',
        r.isRole ? 'YES' : 'NO',
        `"${(r.mxRecords || []).map(m => m.host).join('; ')}"`
      ]);

      const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
      const encodedUri = encodeURI(csvContent);
      const link = document.createElement('a');
      link.setAttribute('href', encodedUri);
      link.setAttribute('download', `email_verification_results_${new Date().toISOString().slice(0,10)}.csv`);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    });

    // Export JSON
    exportJsonBtn.addEventListener('click', () => {
      if (currentResults.length === 0) return;
      const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(currentResults, null, 2));
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute('href', dataStr);
      downloadAnchor.setAttribute('download', `email_verification_${new Date().toISOString().slice(0,10)}.json`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
    });

    /* ==========================================================================
       START VERIFICATION BATCH PROCESSOR
       ========================================================================== */
    startVerifyBtn.addEventListener('click', async () => {
      const emailList = parseInputEmails(emailInput.value);

      if (emailList.length === 0) {
        emailInput.focus();
        emailInput.classList.add('ring-2', 'ring-rose-500');
        setTimeout(() => emailInput.classList.remove('ring-2', 'ring-rose-500'), 1500);
        return;
      }

      // UI state during verification
      startVerifyBtn.disabled = true;
      verifyBtnLabel.textContent = 'Verifying Batch...';
      progressContainer.classList.remove('hidden');
      progressBar.style.width = '0%';
      progressPercent.textContent = '0%';
      progressLabel.textContent = `Processing 0 of ${emailList.length}...`;

      currentResults = [];
      const opts = {
        skipDisposable: skipDisposable.checked
      };

      // Process with concurrency control (batches of 4 for responsive DNS queries)
      const concurrency = 4;
      let completed = 0;

      for (let i = 0; i < emailList.length; i += concurrency) {
        const slice = emailList.slice(i, i + concurrency);
        const promises = slice.map(async (email) => {
          const res = await evaluateEmail(email, opts);
          currentResults.push(res);
          completed++;
          
          const pct = Math.round((completed / emailList.length) * 100);
          progressBar.style.width = `${pct}%`;
          progressPercent.textContent = `${pct}%`;
          progressLabel.textContent = `Processed ${completed} of ${emailList.length}...`;
        });

        await Promise.all(promises);
        // Incremental rendering for visual feedback
        updateMetrics();
        renderTable();
      }

      // Complete
      setTimeout(() => {
        progressContainer.classList.add('hidden');
        startVerifyBtn.disabled = false;
        verifyBtnLabel.textContent = 'Verify All Addresses';
      }, 400);
    });

    /* ==========================================================================
       INITIALIZATION
       ========================================================================== */
    window.addEventListener('DOMContentLoaded', () => {
      lucide.createIcons();
      initChart();
      updateEmailCounter();

      // Load initial sample so the screen immediately showcases functionality
      emailInput.value = SAMPLE_EMAILS.slice(0, 7).join('\n');
      updateEmailCounter();
    });
