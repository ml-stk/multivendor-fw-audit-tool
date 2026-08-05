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

    // Route to the correct audit engine based on vendor selection
    if (vendor === 'fortinet') {
        findings = auditFortinet(fileContent);
    } else if (vendor === 'cisco_asa') {
        findings = auditCiscoASA(fileContent);
    } else if (vendor === 'paloalto') {
        findings = auditPaloAlto(fileContent);
    } else if (vendor === 'meraki') {
        findings = auditMeraki(fileContent);
    } else if (vendor === 'sophos') {
        findings = auditSophos(fileContent);
    }

    // Render findings visually
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

// --- Vendor Audit Rules ---

function auditFortinet(text) {
    const findings = [];
    if (/telnet/i.test(text)) {
        findings.push({ severity: 'danger', message: 'Insecure management protocol (Telnet) is referenced.' });
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
        findings.push({ severity: 'danger', message: 'Insecure HTTP management server is enabled.' });
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

function auditMeraki(text) {
    const findings = [];
    // Meraki configs are typically JSON from the Dashboard API
    // Looking for Any-to-Any Allow rules in JSON format
    if (/"policy"\s*:\s*"allow"/i.test(text) && /"srcCidr"\s*:\s*"Any"/i.test(text) && /"destCidr"\s*:\s*"Any"/i.test(text)) {
        findings.push({ severity: 'danger', message: 'Permissive Any-to-Any allow rule found in Meraki JSON policy.' });
    }
    // Looking for disabled syslog/logging
    if (/"syslogDefaultRule"\s*:\s*false/i.test(text)) {
        findings.push({ severity: 'warning', message: 'Default syslog logging is disabled.' });
    }
    // SNMP v2 instead of v3
    if (/"snmpV2cEnabled"\s*:\s*true/i.test(text)) {
        findings.push({ severity: 'warning', message: 'Insecure SNMPv2c is enabled. Consider using SNMPv3.' });
    }
    return findings;
}

function auditSophos(text) {
    const findings = [];
    // Sophos exports can be text CLI dumps or XML
    // Checks for Any-to-Any Accept rules
    if (/Action\s*=\s*Accept/i.test(text) && /Source\s*=\s*Any/i.test(text) && /Destination\s*=\s*Any/i.test(text)) {
        findings.push({ severity: 'danger', message: 'Unrestricted Any-to-Any Accept rule identified.' });
    }
    // Same check for XML format
    if (/<Action>Accept<\/Action>.*<SourceNetworks>.*Any.*<\/SourceNetworks>/i.test(text.replace(/\n/g, ''))) {
        findings.push({ severity: 'danger', message: 'XML: Unrestricted Any-to-Any Accept rule identified.' });
    }
    // Check for plaintext administration access
    if (/Administration.*Device\s*Access.*HTTP\s*:\s*Enable/i.test(text.replace(/\n/g, ' '))) {
        findings.push({ severity: 'danger', message: 'Insecure HTTP administration access is enabled on a zone.' });
    }
    return findings;
}
