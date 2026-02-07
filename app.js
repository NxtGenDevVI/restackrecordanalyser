const CLOUDFLARE_DNS_API = 'https://cloudflare-dns.com/dns-query';

const domainInput = document.getElementById('domainInput');
const checkButton = document.getElementById('checkButton');
const loadingIndicator = document.getElementById('loadingIndicator');
const errorMessage = document.getElementById('errorMessage');
const results = document.getElementById('results');

checkButton.addEventListener('click', handleCheck);
domainInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        handleCheck();
    }
});

async function handleCheck() {
    const domain = domainInput.value.trim().toLowerCase();
    
    if (!domain) {
        showError('Please enter a domain name');
        return;
    }

    if (!isValidDomain(domain)) {
        showError('Please enter a valid domain name');
        return;
    }

    hideAll();
    loadingIndicator.classList.remove('hidden');
    checkButton.disabled = true;

    try {
        const spfResult = await checkSPF(domain);
        const dkimResults = await checkDKIM(domain);
        const dmarcResult = await checkDMARC(domain);

        displayResults(spfResult, dkimResults, dmarcResult);
    } catch (error) {
        showError(`Error checking DNS records: ${error.message}`);
    } finally {
        loadingIndicator.classList.add('hidden');
        checkButton.disabled = false;
    }
}

function isValidDomain(domain) {
    const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/;
    return domainRegex.test(domain);
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

function displayResults(spfResult, dkimResults, dmarcResult) {
    document.getElementById('spfExists').textContent = spfResult.hasExactlyOne ? 'Yes' : 'No';
    document.getElementById('spfExists').className = `status ${spfResult.hasExactlyOne ? 'yes' : 'no'}`;

    const spfMechanismsSection = document.getElementById('spfMechanismsSection');
    if (spfResult.exists && spfResult.record) {
        spfMechanismsSection.classList.remove('hidden');
        
        document.getElementById('spfBullhorn').textContent = spfResult.hasBullhorn ? 'Present' : 'Missing';
        document.getElementById('spfBullhorn').className = `status ${spfResult.hasBullhorn ? 'present' : 'missing'}`;
        
        document.getElementById('spfSendgrid').textContent = spfResult.hasSendgrid ? 'Present' : 'Missing';
        document.getElementById('spfSendgrid').className = `status ${spfResult.hasSendgrid ? 'present' : 'missing'}`;
        
        document.getElementById('spfRecord').textContent = spfResult.record;
    } else {
        spfMechanismsSection.classList.add('hidden');
    }

    document.getElementById('dkimBh').textContent = dkimResults.bh ? 'Exists' : 'Missing';
    document.getElementById('dkimBh').className = `status ${dkimResults.bh ? 'exists' : 'missing'}`;
    
    document.getElementById('dkimBa').textContent = dkimResults.ba ? 'Exists' : 'Missing';
    document.getElementById('dkimBa').className = `status ${dkimResults.ba ? 'exists' : 'missing'}`;
    
    document.getElementById('dkimBa2').textContent = dkimResults.ba2 ? 'Exists' : 'Missing';
    document.getElementById('dkimBa2').className = `status ${dkimResults.ba2 ? 'exists' : 'missing'}`;
    
    document.getElementById('dkimHf').textContent = dkimResults.hf ? 'Exists' : 'Missing';
    document.getElementById('dkimHf').className = `status ${dkimResults.hf ? 'exists' : 'missing'}`;
    
    document.getElementById('dkimHf2').textContent = dkimResults.hf2 ? 'Exists' : 'Missing';
    document.getElementById('dkimHf2').className = `status ${dkimResults.hf2 ? 'exists' : 'missing'}`;

    document.getElementById('dmarcExists').textContent = dmarcResult.exists ? 'Yes' : 'No';
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

function showError(message) {
    hideAll();
    errorMessage.textContent = message;
    errorMessage.classList.remove('hidden');
}

function hideAll() {
    loadingIndicator.classList.add('hidden');
    errorMessage.classList.add('hidden');
    results.classList.add('hidden');
}
