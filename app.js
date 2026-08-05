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
    
    // 1. Global Checks
    if (/^\s*http server enable/im.test(text)) {
        findings.push({ severity: 'HIGH', element: 'Global Settings', issue: 'HTTP management server enabled', recommendation: 'Disable HTTP server and use SSH.' });
    }
    if (/^\s*enable password.*level.*7/im.test(text) || /^\s*username.*password\s+7/im.test(text)) {
        findings.push({ severity: 'MEDIUM', element: 'User Authentication', issue: 'Weak Type 7 password encryption', recommendation: 'Upgrade password hashing to Type 8 (PBKDF2) or Type 9 (scrypt).' });
    }
    
    // 2. ACL Rules (Cisco syntax mandates single-line order, so we isolate the line and extract the ACL name)
    const aclLines = [...text.matchAll(/^\s*access-list\s+(\S+)\s+extended\s+permit\s+ip\s+(any|any4)\s+(any|any4)/gim)];
    aclLines.forEach(acl => {
        findings.push({ severity: 'HIGH', element: `ACL: ${acl[1]}`, issue: 'Permit IP Any Any', recommendation: 'Replace with explicit source/destination host or subnet rules.' });
    });

    return findings;
}

function auditPaloAlto(text) {
    const findings = [];
    
    // 1. Global Management Checks
    if (/<service-http>(?:yes|True)<\/service-http>/i.test(text) || /set network interface.*management-profile.*(http|telnet)/i.test(text)) {
        findings.push({ severity: 'HIGH', element: 'Management Profile', issue: 'Plaintext HTTP/Telnet management enabled', recommendation: 'Remove plaintext protocols from the interface management profile.' });
    }
    
    // 2. XML Format - Block Level Processing
    if (text.includes('<?xml') || text.includes('<security>')) {
        const rulesBlockMatch = text.match(/<rules>([\s\S]*?)<\/rules>/i);
        if (rulesBlockMatch) {
            const entries = [...rulesBlockMatch[1].matchAll(/<entry name="([^"]+)">([\s\S]*?)<\/entry>/gi)];
            
            entries.forEach(entry => {
                const ruleName = entry[1];
                const body = entry[2];
                
                // Order-agnostic boolean checks
                const isAllow = /<action>allow<\/action>/i.test(body);
                const fromAny = /<from>\s*<member>any<\/member>\s*<\/from>/i.test(body);
                const toAny = /<to>\s*<member>any<\/member>\s*<\/to>/i.test(body);
                const appAny = /<application>\s*<member>any<\/member>\s*<\/application>/i.test(body);
                const serviceAny = /<service>\s*<member>(any|application-default)<\/member>\s*<\/service>/i.test(body);

                if (isAllow && fromAny && toAny) {
                    findings.push({ severity: 'HIGH', element: `Rule: ${ruleName}`, issue: 'Any-to-Any permit rule', recommendation: 'Restrict zones and source/destination addresses.' });
                }
                if (isAllow && appAny && serviceAny) {
                    findings.push({ severity: 'MEDIUM', element: `Rule: ${ruleName}`, issue: 'Unrestricted Application & Service', recommendation: 'Define specific App-IDs instead of port-based Any.' });
                }
            });
        }
    } else {
        // 3. CLI "Set" Format - Grouping by Rule Name
        const ruleLines = [...text.matchAll(/^\s*set rulebase security rules\s+"?([^"\n]+)"?\s+(.*)/gim)];
        const rules = {};
        
        // Group all commands belonging to the same rule name
        ruleLines.forEach(match => {
            const name = match[1];
            if (!rules[name]) rules[name] = "";
            rules[name] += match[2] + "\n";
        });

        Object.keys(rules).forEach(ruleName => {
            const body = rules[ruleName];
            if (/action allow/i.test(body) && /from any/i.test(body) && /to any/i.test(body)) {
                findings.push({ severity: 'HIGH', element: `Rule: ${ruleName}`, issue: 'Any-to-Any permit rule', recommendation: 'Restrict zones and source/destination addresses.' });
            }
        });
    }

    return findings;
}

function auditMeraki(text) {
    const findings = [];
    
    // 1. Global Checks
    if (/"syslogDefaultRule"\s*:\s*false/i.test(text)) {
        findings.push({ severity: 'MEDIUM', element: 'Network Wide Settings', issue: 'Default syslog logging disabled', recommendation: 'Enable syslog logging for traffic visibility.' });
    }

    // 2. JSON Object Block Extraction
    // Safely isolates individual JSON objects { ... } to prevent cross-rule contamination
    const ruleBlocks = text.match(/\{[^{}]*?\}/g) || [];
    
    ruleBlocks.forEach((body, index) => {
        // Order-agnostic JSON key checks
        if (/"policy"\s*:\s*"allow"/i.test(body)) {
            const srcAny = /"srcCidr"\s*:\s*"Any"/i.test(body);
            const destAny = /"destCidr"\s*:\s*"Any"/i.test(body);
            const srcPortAny = /"srcPort"\s*:\s*"Any"/i.test(body);
            const destPortAny = /"destPort"\s*:\s*"Any"/i.test(body);

            if (srcAny && destAny) {
                findings.push({ severity: 'HIGH', element: `L3 Rule Block ${index + 1}`, issue: 'Any-to-Any allow rule found', recommendation: 'Restrict CIDR blocks in the Meraki Dashboard.' });
            }
            if (srcPortAny && destPortAny) {
                findings.push({ severity: 'MEDIUM', element: `L3 Rule Block ${index + 1}`, issue: 'Permissive Any-Port allow rule', recommendation: 'Define explicit TCP/UDP ports.' });
            }
        }
    });

    return findings;
}

function auditSophos(text) {
    const findings = [];
    
    // 1. Global Checks
    if (/(Administration.*Device\s*Access.*HTTP\s*:\s*Enable|<ManageHTTP>Enable<\/ManageHTTP>)/i.test(text)) {
        findings.push({ severity: 'HIGH', element: 'Device Access', issue: 'HTTP administration enabled', recommendation: 'Disable HTTP access on WAN and LAN zones.' });
    }

    // 2. XML Format Block Extraction
    const xmlRules = [...text.matchAll(/<FirewallRule>([\s\S]*?)<\/FirewallRule>/gi)];
    
    xmlRules.forEach((rule, index) => {
        const body = rule[1];
        
        // Try to extract the custom rule name, fallback to index if missing
        const nameMatch = body.match(/<Name>([^<]+)<\/Name>/i);
        const ruleName = nameMatch ? nameMatch[1] : `Rule ${index + 1}`;

        // Strip line breaks for inner tag evaluation
        const cleanBody = body.replace(/\n/g, ' ');
        
        const isAccept = /<Action>Accept<\/Action>/i.test(cleanBody);
        const hasSourceAny = /<SourceNetworks>.*Any.*<\/SourceNetworks>/i.test(cleanBody);
        const hasDestAny = /<DestinationNetworks>.*Any.*<\/DestinationNetworks>/i.test(cleanBody);
        const hasServiceAny = /<Services>.*Any.*<\/Services>/i.test(cleanBody);

        if (isAccept && hasSourceAny && hasDestAny) {
             findings.push({ severity: 'HIGH', element: `Rule: ${ruleName}`, issue: 'Unrestricted Any-to-Any Accept', recommendation: 'Lock down source and destination networks explicitly.' });
        }
        if (isAccept && hasServiceAny) {
             findings.push({ severity: 'MEDIUM', element: `Rule: ${ruleName}`, issue: 'Policy allows Any Service', recommendation: 'Define specific ports and services.' });
        }
    });

    return findings;
}
