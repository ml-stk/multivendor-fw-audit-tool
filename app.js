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

    // Route to vendor engine
    if (vendor === 'fortinet') { findings = auditFortinet(fileContent); } 
    else if (vendor === 'cisco_asa') { findings = auditCiscoASA(fileContent); } 
    else if (vendor === 'paloalto') { findings = auditPaloAlto(fileContent); } 
    else if (vendor === 'meraki') { findings = auditMeraki(fileContent); } 
    else if (vendor === 'sophos') { findings = auditSophos(fileContent); }

    // Render Table
    if (findings.length === 0) {
        resultsContainer.innerHTML = `<div class="alert-banner" style="background-color: #d4edda; color: #155724;">✅ No potential security issues found.</div>`;
    } else {
        let tableHTML = `
            <div class="alert-banner">
                ⚠️ Found ${findings.length} potential security issues.
            </div>
            <div class="actions-row">
                <button id="downloadCsvBtn" class="btn btn-primary">Download Full Audit (CSV)</button>
            </div>
            <table class="audit-table">
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Element</th>
                        <th>Security Issue</th>
                        <th>Recommendation</th>
                    </tr>
                </thead>
                <tbody>
        `;

        findings.forEach(f => {
            tableHTML += `
                <tr>
                    <td><span class="badge badge-${f.severity.toLowerCase()}">${f.severity.toUpperCase()}</span></td>
                    <td><strong>${f.element}</strong></td>
                    <td>${f.issue}</td>
                    <td>${f.recommendation}</td>
                </tr>
            `;
        });

        tableHTML += `</tbody></table>`;
        resultsContainer.innerHTML = tableHTML;

        // Attach CSV Download Event
        document.getElementById('downloadCsvBtn').addEventListener('click', () => downloadCSV(findings));
    }

    document.getElementById('outputArea').classList.remove('hidden');
});

// CSV Generator
function downloadCSV(findings) {
    let csvContent = "Severity,Element,Security Issue,Recommendation\n";
    findings.forEach(f => {
        // Wrap in quotes to handle commas in text
        csvContent += `"${f.severity}","${f.element}","${f.issue}","${f.recommendation}"\n`;
    });
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', 'firewall_audit_results.csv');
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// --- Block-Level Vendor Audit Engines ---

function auditFortinet(text) {
    const findings = [];
    
    // 1. Global Interface Checks (Order independent)
    if (/set allowaccess[^\n]*(?:telnet|http\b)/i.test(text)) {
        findings.push({ severity: 'HIGH', element: 'Global / Interfaces', issue: 'Insecure management protocol (Telnet/HTTP)', recommendation: 'Disable plaintext protocols and enforce SSH/HTTPS.' });
    }

    // 2. Isolate Firewall Policy Sections
    // Uses multi-line flags (m) to safely capture blocks across all VDOMs
    const policyBlocks = [...text.matchAll(/config firewall policy\b([\s\S]*?)^\s*end\b/gim)];
    
    policyBlocks.forEach(blockMatch => {
        const policySection = blockMatch[1];
        
        // 3. Extract every individual policy block: "edit <ID> ... next"
        const policies = [...policySection.matchAll(/^\s*edit\s+(\d+)\b([\s\S]*?)^\s*next\b/gim)];

        policies.forEach(p => {
            const id = p[1];
            const body = p[2]; // The raw text inside this specific policy

            // 4. Test for conditions independently (solves the line-order bug)
            const isAccept = /set action accept/i.test(body);
            const hasServiceAll = /set service "ALL"/i.test(body);
            const hasSrcAll = /set srcaddr "all"/i.test(body);
            const hasDstAll = /set dstaddr "all"/i.test(body);
            const loggingDisabled = /set logtraffic disable/i.test(body);

            // 5. Evaluate Logic
            if (loggingDisabled) {
                findings.push({ severity: 'MEDIUM', element: `Policy ${id}`, issue: 'Traffic logging disabled', recommendation: 'Set logtraffic to "utm" or "all" to maintain audit trails.' });
            }
            if (isAccept && hasSrcAll && hasDstAll) {
                findings.push({ severity: 'HIGH', element: `Policy ${id}`, issue: 'Any-to-Any Permit rule', recommendation: 'Restrict source and destination to explicit networks/IPs.' });
            }
            if (isAccept && hasServiceAll) {
                findings.push({ severity: 'MEDIUM', element: `Policy ${id}`, issue: 'Service port set to ALL', recommendation: 'Define explicit TCP/UDP ports required for the application.' });
            }
        });
    });

    return findings;
}

function auditCiscoASA(text) {
    const findings = [];
    
    if (/http server enable/i.test(text)) {
        findings.push({ severity: 'HIGH', element: 'Global Settings', issue: 'HTTP management server enabled', recommendation: 'Disable HTTP server and use SSH.' });
    }
    
    // Extract ACL blocks to find specific lines
    const aclLines = [...text.matchAll(/access-list\s+(\S+)\s+extended\s+permit\s+ip\s+any\s+any/gi)];
    aclLines.forEach(acl => {
        findings.push({ severity: 'HIGH', element: `ACL: ${acl[1]}`, issue: 'Permit IP Any Any', recommendation: 'Replace with explicit source/destination host or subnet rules.' });
    });

    if (/enable password.*level.*7/i.test(text)) {
        findings.push({ severity: 'MEDIUM', element: 'User/Enable Authentication', issue: 'Weak Type 7 password encryption', recommendation: 'Upgrade password hashing to Type 8 (PBKDF2) or Type 9 (scrypt).' });
    }

    return findings;
}

function auditPaloAlto(text) {
    const findings = [];
    
    if (/<service-http>(?:yes|True)<\/service-http>/i.test(text)) {
        findings.push({ severity: 'HIGH', element: 'Management Profile', issue: 'Plaintext HTTP management enabled', recommendation: 'Remove HTTP from the interface management profile.' });
    }
    
    // Extract rule names from "set rulebase security rules <RuleName>"
    const rules = [...text.matchAll(/set rulebase security rules\s+(\S+)\s+(.*action allow.*)/gi)];
    rules.forEach(rule => {
        const ruleName = rule[1].replace(/"/g, ''); // strip quotes if present
        const ruleBody = rule[2];
        
        if (/from any to any/i.test(ruleBody)) {
            findings.push({ severity: 'HIGH', element: `Rule: ${ruleName}`, issue: 'Any-to-Any permit rule', recommendation: 'Restrict zones and source/destination addresses.' });
        }
        if (/application any service (any|application-default)/i.test(ruleBody)) {
            findings.push({ severity: 'MEDIUM', element: `Rule: ${ruleName}`, issue: 'Unrestricted Application & Service', recommendation: 'Define specific App-IDs instead of port-based Any.' });
        }
    });

    return findings;
}

// Basic fallbacks for Meraki and Sophos using the new schema
function auditMeraki(text) {
    const findings = [];
    if (/"policy"\s*:\s*"allow"[\s\S]*?"srcCidr"\s*:\s*"Any"[\s\S]*?"destCidr"\s*:\s*"Any"/i.test(text)) {
        findings.push({ severity: 'HIGH', element: 'L3 Firewall Rule', issue: 'Any-to-Any allow rule found', recommendation: 'Restrict CIDR blocks in the Meraki Dashboard.' });
    }
    if (/"syslogDefaultRule"\s*:\s*false/i.test(text)) {
        findings.push({ severity: 'MEDIUM', element: 'Network Wide Settings', issue: 'Default syslog logging disabled', recommendation: 'Enable syslog logging for traffic visibility.' });
    }
    return findings;
}

function auditSophos(text) {
    const findings = [];
    if (/(Action\s*=\s*Accept[\s\S]*?Source\s*=\s*Any[\s\S]*?Destination\s*=\s*Any|<Action>Accept<\/Action>[\s\S]*?<SourceNetworks>.*Any.*<\/SourceNetworks>[\s\S]*?<DestinationNetworks>.*Any.*<\/DestinationNetworks>)/i.test(text)) {
        findings.push({ severity: 'HIGH', element: 'Firewall Rule', issue: 'Unrestricted Any-to-Any Accept', recommendation: 'Lock down source and destination networks explicitly.' });
    }
    if (/(Administration.*Device\s*Access.*HTTP\s*:\s*Enable|<ManageHTTP>Enable<\/ManageHTTP>)/i.test(text)) {
        findings.push({ severity: 'HIGH', element: 'Device Access', issue: 'HTTP administration enabled', recommendation: 'Disable HTTP access on WAN and LAN zones.' });
    }
    return findings;
}
