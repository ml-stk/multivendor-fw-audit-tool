let fileContent = "";

document.getElementById('configFile').addEventListener('change', function(e) {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
        fileContent = event.target.result;
        document.getElementById('auditBtn').disabled = false;
    };
    reader.readAsText(file);
});

document.getElementById('auditBtn').addEventListener('click', () => {
    const vendor = document.getElementById('vendorSelect').value;
    const resultsContainer = document.getElementById('resultsContainer');
    resultsContainer.innerHTML = "";

    let findings = [];

    if (vendor === 'fortinet') {
        findings = auditFortinet(fileContent);
    } else if (vendor === 'cisco_asa') {
        findings = auditCiscoASA(fileContent);
    } else if (vendor === 'paloalto') {
        findings = auditPaloAlto(fileContent);
    }

    // Render findings
    if (findings.length === 0) {
        resultsContainer.innerHTML = `<div class="finding-card safe"><h4>✅ No major compliance violations detected.</h4></div>`;
    } else {
        findings.forEach(f => {
            const card = document.createElement('div');
            card.className = `finding-card ${f.severity}`;
            card.innerHTML = `<strong>[${f.severity.toUpperCase()}]</strong> ${f.message}`;
            resultsContainer.appendChild(card);
        });
    }

    document.getElementById('outputArea').classList.remove('hidden');
});

// Vendor Audit Rules
function auditFortinet(text) {
    const findings = [];
    if (/telnet/i.test(text)) {
        findings.push({ severity: 'danger', message: 'Insecure management protocol (Telnet) is referenced in the configuration.' });
    }
    if (/set logtraffic disable/i.test(text)) {
        findings.push({ severity: 'warning', message: 'Traffic logging has been explicitly disabled on some policies.' });
    }
    if (/0\.0\.0\.0\/0.*0\.0\.0\.0\/0/i.test(text) && !/deny/i.test(text)) {
        findings.push({ severity: 'danger', message: 'Potential Any-to-Any (0.0.0.0/0 to 0.0.0.0/0) allow rule detected.' });
    }
    return findings;
}

function auditCiscoASA(text) {
    const findings = [];
    if (/http server enable/i.test(text)) {
        findings.push({ severity: 'danger', message: 'Insecure HTTP management server is enabled on the Cisco ASA.' });
    }
    if (/telnet /i.test(text)) {
        findings.push({ severity: 'danger', message: 'Telnet login is configured instead of secure SSH.' });
    }
    if (/access-list.*permit ip any any/i.test(text)) {
        findings.push({ severity: 'danger', message: 'Unrestricted "permit ip any any" access list rule found.' });
    }
    return findings;
}

function auditPaloAlto(text) {
    const findings = [];
    if (/service-http\b/.test(text)) {
        findings.push({ severity: 'warning', message: 'Plaintext HTTP service profile or management usage detected.' });
    }
    if (/to any.*from any.*action allow/i.test(text)) {
        findings.push({ severity: 'danger', message: 'Wide-open security policy matching Any-to-Any permit rule.' });
    }
    return findings;
}
