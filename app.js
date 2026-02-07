const CLOUDFLARE_DNS_API = 'https://cloudflare-dns.com/dns-query';
const BACKEND_API = 'https://dns-checker-api.restack.workers.dev';

const emailInput = document.getElementById('emailInput');
const checkButton = document.getElementById('checkButton');
const loadingIndicator = document.getElementById('loadingIndicator');
const errorMessage = document.getElementById('errorMessage');
const results = document.getElementById('results');

checkButton.addEventListener('click', handleCheck);
emailInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        handleCheck();
    }
});

async function handleCheck() {
    const email = emailInput.value.trim().toLowerCase();
    
    if (!email) {
        showError('Please enter an email address');
        return;
    }

    if (!isValidEmail(email)) {
        showError('Please enter a valid email address');
        return;
    }
    
    const domain = extractDomain(email);

    hideAll();
    loadingIndicator.classList.remove('hidden');
    checkButton.disabled = true;

    try {
        const spfResult = await checkSPF(domain);
        const dkimResults = await checkDKIM(domain);
        const dmarcResult = await checkDMARC(domain);
        
        const score = calculateScore(spfResult, dkimResults, dmarcResult);

        displayResults(spfResult, dkimResults, dmarcResult, score);
        
        // Log to backend (non-blocking)
        logToBackend(email, domain, { spf: spfResult, dkim: dkimResults, dmarc: dmarcResult }, score).catch(() => {
            // Silently fail - logging shouldn't break the user experience
        });
    } catch (error) {
        showError(`Error checking DNS records: ${error.message}`);
    } finally {
        loadingIndicator.classList.add('hidden');
        checkButton.disabled = false;
    }
}

function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

function extractDomain(email) {
    return email.split('@')[1];
}

function calculateScore(spfResult, dkimResults, dmarcResult) {
    let score = 0;
    
    // SPF: 40 points
    if (spfResult.hasExactlyOne) {
        score += 40;
    }
    
    // DKIM: 40 points (8 points per selector)
    const dkimCount = Object.values(dkimResults).filter(Boolean).length;
    score += dkimCount * 8;
    
    // DMARC: 20 points
    if (dmarcResult.exists) {
        score += 20;
    }
    
    return score;
}

async function queryDNS(name, type) {
    const url = `${CLOUDFLARE_DNS_API}?name=${encodeURIComponent(name)}&type=${type}`;
    
    const response = await fetch(url, {
        headers: {
            'Accept': 'application/dns-json'
        }
    });

    if (!response.ok) {
        throw new Error(`DNS query failed: ${response.statusText}`);
    }

    const data = await response.json();
    return data;
}

async function checkSPF(domain) {
    try {
        const data = await queryDNS(domain, 'TXT');
        
        if (!data.Answer) {
            return {
                exists: false,
                hasExactlyOne: false,
                record: null,
                hasBullhorn: false,
                hasSendgrid: false
            };
        }

        const spfRecords = data.Answer
            .filter(record => record.data && record.data.startsWith('"v=spf1'))
            .map(record => record.data.replace(/^"|"$/g, ''));

        const hasExactlyOne = spfRecords.length === 1;
        const spfRecord = spfRecords[0] || null;

        let hasBullhorn = false;
        let hasSendgrid = false;

        if (spfRecord) {
            hasBullhorn = spfRecord.includes('include:_spf.bullhornmail.com');
            hasSendgrid = spfRecord.includes('include:sendgrid.net');
        }

        return {
            exists: spfRecords.length > 0,
            hasExactlyOne,
            record: spfRecord,
            hasBullhorn,
            hasSendgrid
        };
    } catch (error) {
        throw new Error(`SPF check failed: ${error.message}`);
    }
}

async function checkDKIM(domain) {
    const selectors = ['bh', 'ba', 'ba2', 'hf', 'hf2'];
    const results = {};

    for (const selector of selectors) {
        const dkimDomain = `${selector}._domainkey.${domain}`;
        try {
            const data = await queryDNS(dkimDomain, 'TXT');
            results[selector] = !!(data.Answer && data.Answer.length > 0);
        } catch (error) {
            results[selector] = false;
        }
    }

    return results;
}

async function checkDMARC(domain) {
    const dmarcDomain = `_dmarc.${domain}`;
    
    try {
        const data = await queryDNS(dmarcDomain, 'TXT');
        
        if (!data.Answer || data.Answer.length === 0) {
            return {
                exists: false,
                policy: null
            };
        }

        const dmarcRecord = data.Answer[0].data.replace(/^"|"$/g, '');
        
        let policy = null;
        if (dmarcRecord.includes('p=reject')) {
            policy = 'reject';
        } else if (dmarcRecord.includes('p=quarantine')) {
            policy = 'quarantine';
        } else if (dmarcRecord.includes('p=none')) {
            policy = 'none';
        }

        return {
            exists: true,
            policy
        };
    } catch (error) {
        return {
            exists: false,
            policy: null
        };
    }
}

function displayResults(spfResult, dkimResults, dmarcResult, score) {
    // Store results globally for email function
    window.lastCheckResults = {
        email: emailInput.value.trim().toLowerCase(),
        domain: extractDomain(emailInput.value.trim().toLowerCase()),
        score,
        spf: spfResult,
        dkim: dkimResults,
        dmarc: dmarcResult
    };
    
    // Update score display
    document.getElementById('scorePercentage').textContent = `${score}%`;
    updateScoreCircle(score);
    
    document.getElementById('spfExists').innerHTML = spfResult.hasExactlyOne ? '<span class="icon-check">✓</span>' : '<span class="icon-cross">✗</span>';
    document.getElementById('spfExists').className = `status ${spfResult.hasExactlyOne ? 'yes' : 'no'}`;

    const spfMechanismsSection = document.getElementById('spfMechanismsSection');
    const spfRecordSection = document.getElementById('spfRecordSection');
    if (spfResult.exists && spfResult.record) {
        spfMechanismsSection.classList.remove('hidden');
        spfRecordSection.classList.remove('hidden');
        
        document.getElementById('spfBullhorn').innerHTML = spfResult.hasBullhorn ? '<span class=\"icon-check\">✓</span>' : '<span class=\"icon-cross\">✗</span>';
        document.getElementById('spfBullhorn').className = `status ${spfResult.hasBullhorn ? 'present' : 'missing'}`;
        
        document.getElementById('spfSendgrid').innerHTML = spfResult.hasSendgrid ? '<span class=\"icon-check\">✓</span>' : '<span class=\"icon-cross\">✗</span>';
        document.getElementById('spfSendgrid').className = `status ${spfResult.hasSendgrid ? 'present' : 'missing'}`;
        
        document.getElementById('spfRecord').textContent = spfResult.record;
    } else {
        spfMechanismsSection.classList.add('hidden');
        spfRecordSection.classList.add('hidden');
    }

    document.getElementById('dkimBh').innerHTML = dkimResults.bh ? '<span class="icon-check">✓</span>' : '<span class="icon-cross">✗</span>';
    document.getElementById('dkimBh').className = `status ${dkimResults.bh ? 'exists' : 'missing'}`;
    
    document.getElementById('dkimBa').innerHTML = dkimResults.ba ? '<span class="icon-check">✓</span>' : '<span class="icon-cross">✗</span>';
    document.getElementById('dkimBa').className = `status ${dkimResults.ba ? 'exists' : 'missing'}`;
    
    document.getElementById('dkimBa2').innerHTML = dkimResults.ba2 ? '<span class="icon-check">✓</span>' : '<span class="icon-cross">✗</span>';
    document.getElementById('dkimBa2').className = `status ${dkimResults.ba2 ? 'exists' : 'missing'}`;
    
    document.getElementById('dkimHf').innerHTML = dkimResults.hf ? '<span class="icon-check">✓</span>' : '<span class="icon-cross">✗</span>';
    document.getElementById('dkimHf').className = `status ${dkimResults.hf ? 'exists' : 'missing'}`;
    
    document.getElementById('dkimHf2').innerHTML = dkimResults.hf2 ? '<span class="icon-check">✓</span>' : '<span class="icon-cross">✗</span>';
    document.getElementById('dkimHf2').className = `status ${dkimResults.hf2 ? 'exists' : 'missing'}`;

    document.getElementById('dmarcExists').innerHTML = dmarcResult.exists ? '<span class="icon-check">✓</span>' : '<span class="icon-cross">✗</span>';
    document.getElementById('dmarcExists').className = `status ${dmarcResult.exists ? 'yes' : 'no'}`;

    const dmarcPolicySection = document.getElementById('dmarcPolicySection');
    if (dmarcResult.exists && dmarcResult.policy) {
        dmarcPolicySection.classList.remove('hidden');
        document.getElementById('dmarcPolicy').textContent = `p=${dmarcResult.policy}`;
        document.getElementById('dmarcPolicy').className = 'status policy';
    } else {
        dmarcPolicySection.classList.add('hidden');
    }

    results.classList.remove('hidden');
}

function updateScoreCircle(score) {
    const circle = document.getElementById('scoreCircle');
    const circumference = 2 * Math.PI * 54; // radius is 54
    const offset = circumference - (score / 100) * circumference;
    circle.style.strokeDashoffset = offset;
    
    // Change color based on score
    if (score >= 80) {
        circle.style.stroke = '#27AE60';
    } else if (score >= 50) {
        circle.style.stroke = '#F39C12';
    } else {
        circle.style.stroke = '#E74C3C';
    }
}

function showError(message) {
    hideAll();
    errorMessage.textContent = message;
    errorMessage.classList.remove('hidden');
}


async function logToBackend(email, domain, results, score) {
    try {
        console.log('Sending to backend:', { email, domain, results, score });
        const response = await fetch(`${BACKEND_API}/log`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email, domain, results, score })
        });
        const responseData = await response.json();
        console.log('Backend response:', responseData);
    } catch (error) {
        console.error('Failed to log to backend:', error);
    }
}

// Admin Portal Functionality
const adminButton = document.getElementById('adminButton');
const adminModal = document.getElementById('adminModal');
const closeAdmin = document.getElementById('closeAdmin');
const pinSection = document.getElementById('pinSection');
const pinInput = document.getElementById('pinInput');
const pinSubmit = document.getElementById('pinSubmit');
const pinError = document.getElementById('pinError');
const dashboardSection = document.getElementById('dashboardSection');
const refreshButton = document.getElementById('refreshButton');

const ADMIN_PIN = '1501';

adminButton.addEventListener('click', () => {
    adminModal.classList.remove('hidden');
    pinInput.value = '';
    pinError.classList.add('hidden');
    pinInput.focus();
});

closeAdmin.addEventListener('click', () => {
    adminModal.classList.add('hidden');
    pinSection.classList.remove('hidden');
    dashboardSection.classList.add('hidden');
});

adminModal.addEventListener('click', (e) => {
    if (e.target === adminModal) {
        adminModal.classList.add('hidden');
        pinSection.classList.remove('hidden');
        dashboardSection.classList.add('hidden');
    }
});

pinSubmit.addEventListener('click', verifyPin);
pinInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        verifyPin();
    }
});

refreshButton.addEventListener('click', () => {
    loadDashboard();
});

function verifyPin() {
    const enteredPin = pinInput.value.trim();
    
    if (enteredPin === ADMIN_PIN) {
        pinError.classList.add('hidden');
        pinSection.classList.add('hidden');
        dashboardSection.classList.remove('hidden');
        loadDashboard();
    } else {
        pinError.classList.remove('hidden');
        pinInput.value = '';
        pinInput.focus();
    }
}

async function loadDashboard() {
    try {
        const response = await fetch(`${BACKEND_API}/stats`);
        
        if (!response.ok) {
            throw new Error('Failed to fetch stats');
        }
        
        const data = await response.json();
        console.log('Dashboard data received:', data);
        console.log('First check record:', data.recentChecks[0]);
        
        // Update total checks
        document.getElementById('totalChecks').textContent = data.totalChecks || 0;
        
        // Update recent checks
        const recentChecksList = document.getElementById('recentChecksList');
        if (data.recentChecks && data.recentChecks.length > 0) {
            recentChecksList.innerHTML = data.recentChecks.map(check => {
                // Convert database integers (0/1) to booleans explicitly
                const spfExists = Boolean(check.spf_exists);
                const dmarcExists = Boolean(check.dmarc_exists);
                const dkimBh = Boolean(check.dkim_bh);
                const dkimBa = Boolean(check.dkim_ba);
                const dkimBa2 = Boolean(check.dkim_ba2);
                const dkimHf = Boolean(check.dkim_hf);
                const dkimHf2 = Boolean(check.dkim_hf2);
                const score = check.score || 0;
                const displayEmail = check.email || check.domain; // Fallback to domain if no email
                
                return `
                <div class="check-item-detailed">
                    <div class="check-header">
                        <span class="check-domain">${escapeHtml(displayEmail)}</span>
                        <div class="score-badge score-${getScoreClass(score)}">${score}%</div>
                        <span class="check-time">${formatTimestamp(check.timestamp)}</span>
                    </div>
                    <div class="check-results">
                        <div class="result-grid">
                            <div class="result-box">
                                <span class="result-label">SPF Record</span>
                                <span class="result-value ${spfExists ? 'success' : 'fail'}">${spfExists ? '✓' : '✗'}</span>
                            </div>
                            <div class="result-box">
                                <span class="result-label">DMARC Record</span>
                                <span class="result-value ${dmarcExists ? 'success' : 'fail'}">${dmarcExists ? '✓' : '✗'}</span>
                                ${check.dmarc_policy ? `<span class="result-detail">${escapeHtml(check.dmarc_policy)}</span>` : ''}
                            </div>
                        </div>
                        <div class="dkim-section">
                            <span class="result-label">DKIM Selectors</span>
                            <div class="dkim-grid">
                                <span class="dkim-item ${dkimBh ? 'success' : 'fail'}">bh: ${dkimBh ? '✓' : '✗'}</span>
                                <span class="dkim-item ${dkimBa ? 'success' : 'fail'}">ba: ${dkimBa ? '✓' : '✗'}</span>
                                <span class="dkim-item ${dkimBa2 ? 'success' : 'fail'}">ba2: ${dkimBa2 ? '✓' : '✗'}</span>
                                <span class="dkim-item ${dkimHf ? 'success' : 'fail'}">hf: ${dkimHf ? '✓' : '✗'}</span>
                                <span class="dkim-item ${dkimHf2 ? 'success' : 'fail'}">hf2: ${dkimHf2 ? '✓' : '✗'}</span>
                            </div>
                        </div>
                    </div>
                </div>
                `;
            }).join('');
        } else {
            recentChecksList.innerHTML = '<p>No checks yet</p>';
        }
        
        // Update top domains
        const topDomainsList = document.getElementById('topDomainsList');
        if (data.topDomains && data.topDomains.length > 0) {
            topDomainsList.innerHTML = data.topDomains.map(item => `
                <div class="domain-item">
                    <span class="domain-name">${escapeHtml(item.domain)}</span>
                    <span class="domain-count">${item.count}</span>
                </div>
            `).join('');
        } else {
            topDomainsList.innerHTML = '<p>No data yet</p>';
        }
    } catch (error) {
        console.error('Failed to load dashboard:', error);
        document.getElementById('recentChecksList').innerHTML = '<p>Error loading data</p>';
        document.getElementById('topDomainsList').innerHTML = '<p>Error loading data</p>';
    }
}

function formatTimestamp(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString('en-US', {
        month: 'short',
        day: 'numeric',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function getScoreClass(score) {
    if (score >= 80) return 'high';
    if (score >= 50) return 'medium';
    return 'low';
}

function emailResults() {
    if (!window.lastCheckResults) return;
    
    const { email, domain, score, spf, dkim, dmarc } = window.lastCheckResults;
    
    const subject = `DNS Email Authentication Report for ${email}`;
    
    const body = `DNS Email Authentication Check Results
=====================================

Email Checked: ${email}
Domain: ${domain}
Overall Security Score: ${score}%

📊 RESULTS SUMMARY
------------------

SPF Record:
${spf.hasExactlyOne ? '✓ Valid SPF record found' : '✗ No valid SPF record'}
${spf.hasBullhorn ? '✓ Bullhorn configured' : '✗ Bullhorn not configured'}
${spf.hasSendgrid ? '✓ Sendgrid configured' : '✗ Sendgrid not configured'}

DKIM Selectors:
${dkim.bh ? '✓' : '✗'} bh._domainkey
${dkim.ba ? '✓' : '✗'} ba._domainkey
${dkim.ba2 ? '✓' : '✗'} ba2._domainkey
${dkim.hf ? '✓' : '✗'} hf._domainkey
${dkim.hf2 ? '✓' : '✗'} hf2._domainkey

DMARC Record:
${dmarc.exists ? '✓ DMARC record found' : '✗ No DMARC record found'}
${dmarc.policy ? `Policy: p=${dmarc.policy}` : ''}

${spf.record ? `\nFull SPF Record:\n${spf.record}` : ''}

------------------
Generated by RE:STACK DNS Email Authentication Checker
${window.location.href}`;
    
    const mailtoLink = `mailto:${email}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
    window.location.href = mailtoLink;
}

// Add event listener for email button
document.addEventListener('DOMContentLoaded', () => {
    const emailButton = document.getElementById('emailResultsButton');
    if (emailButton) {
        emailButton.addEventListener('click', emailResults);
    }
});

function hideAll() {
    loadingIndicator.classList.add('hidden');
    errorMessage.classList.add('hidden');
    results.classList.add('hidden');
}
