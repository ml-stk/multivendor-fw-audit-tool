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
                        <th>Standard / Framework</th>
                    </tr>
                </thead>
                <tbody>
        `;

        findings.forEach(f => {
            // Provide a fallback if a finding hasn't been mapped to a standard yet
            const complianceText = f.compliance ? f.compliance : 'Best Practice';
            
            tableHTML += `
                <tr>
                    <td><span class="badge badge-${f.severity.toLowerCase()}">${f.severity.toUpperCase()}</span></td>
                    <td><strong>${f.element}</strong></td>
                    <td>${f.issue}</td>
                    <td>${f.recommendation}</td>
                    <td><span class="compliance-tag">${complianceText}</span></td>
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
    let csvContent = "Severity,Element,Security Issue,Recommendation,Standard\n";
    findings.forEach(f => {
        const complianceText = f.compliance ? f.compliance : 'Best Practice';
        csvContent += `"${f.severity}","${f.element}","${f.issue}","${f.recommendation}","${complianceText}"\n`;
    });
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', 'firewall_compliance_audit.csv');
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// --- Block-Level Vendor Audit Engines ---

function auditFortinet(text) {
    const findings = [];
    
    // 1. Global Interface Checks
    if (/set allowaccess[^\n]*(?:telnet|http\b)/i.test(text)) {
        findings.push({ 
            severity: 'HIGH', 
            element: 'Global / Interfaces', 
            issue: 'Insecure management protocol (Telnet/HTTP)', 
            recommendation: 'Disable plaintext protocols and enforce SSH/HTTPS.',
            compliance: 'PCI-DSS Req 2.2.6 / CIS 4.1'
        });
    }

    // 2. Isolate Firewall Policy Sections
    const policyBlocks = [...text.matchAll(/config firewall policy\b([\s\S]*?)^\s*end\b/gim)];
    
    policyBlocks.forEach(blockMatch => {
        const policySection = blockMatch[1];
        
        // 3. Extract individual policies
        const policies = [...policySection.matchAll(/^\s*edit\s+(\d+)\b([\s\S]*?)^\s*next\b/gim)];

        policies.forEach(p => {
            const id = p[1];
            const body = p[2];

            // 4. Test conditions independently
            const isAccept = /set action accept/i.test(body);
            const hasServiceAll = /set service "ALL"/i.test(body);
            const hasSrcAll = /set srcaddr "all"/i.test(body);
            const hasDstAll = /set dstaddr "all"/i.test(body);
            
            // Fix: Check for explicit logging. If missing, it defaults to disabled.
            const hasLogging = /set logtraffic\s+(all|utm)/i.test(body); 

            // 5. Evaluate Logic against original tool parameters
            
            if (isAccept && hasSrcAll && hasDstAll) {
                findings.push({ 
                    severity: 'CRITICAL', 
                    element: `Policy ${id}`, 
                    issue: 'Permissive Access (Any-to-Any)', 
                    recommendation: 'Restrict source and destination addresses to specific subnets.',
                    compliance: 'PCI-DSS Req 1.2.1 / NIST 800-41'
                });
            }

            if (isAccept && !hasLogging) {
                findings.push({ 
                    severity: 'HIGH', 
                    element: `Policy ${id}`, 
                    issue: 'Traffic Logging Disabled on Allow Rule', 
                    recommendation: "Set logtraffic to 'all' or 'utm' to ensure an audit trail is maintained.",
                    compliance: 'PCI-DSS Req 10.2.1 / CIS 8.2'
                });
            }

            if (isAccept && hasServiceAll) {
                findings.push({ 
                    severity: 'MEDIUM', 
                    element: `Policy ${id}`, 
                    issue: 'Service port set to ALL', 
                    recommendation: 'Define explicit TCP/UDP ports required for the application.',
                    compliance: 'PCI-DSS Req 1.2.2 / CIS 4.4'
                });
            }
        });
    });

    return findings;
}

function auditCiscoASA(text) {
    const findings = [];
    
    // 1. Global Checks
    if (/^\s*http server enable/im.test(text)) {
        findings.push({ 
            severity: 'HIGH', 
            element: 'Global Settings', 
            issue: 'HTTP management server enabled', 
            recommendation: 'Disable HTTP server and use SSH.',
            compliance: 'PCI-DSS Req 2.2.6 / CIS 4.1'
        });
    }
    if (/^\s*enable password.*level.*7/im.test(text) || /^\s*username.*password\s+7/im.test(text)) {
        findings.push({ 
            severity: 'MEDIUM', 
            element: 'User Authentication', 
            issue: 'Weak Type 7 password encryption', 
            recommendation: 'Upgrade password hashing to Type 8 (PBKDF2) or Type 9 (scrypt).',
            compliance: 'PCI-DSS Req 8.3.2 / NIST 800-53'
        });
    }
    
    // 2. ACL Rules Inspection
    const aclLines = [...text.matchAll(/^\s*access-list\s+(\S+)\s+extended\s+permit\s+ip\s+(any|any4)\s+(any|any4)/gim)];
    aclLines.forEach(acl => {
        findings.push({ 
            severity: 'CRITICAL', 
            element: `ACL: ${acl[1]}`, 
            issue: 'Permissive Access (Any-to-Any)', 
            recommendation: 'Replace with explicit source/destination host or subnet rules.',
            compliance: 'PCI-DSS Req 1.2.1 / NIST 800-41'
        });
    });

    return findings;
}

function auditPaloAlto(text) {
    const findings = [];
    
    // 1. Global Management Checks
    if (/<service-http>(?:yes|True)<\/service-http>/i.test(text) || /set network interface.*management-profile.*(http|telnet)/i.test(text)) {
        findings.push({ 
            severity: 'HIGH', 
            element: 'Management Profile', 
            issue: 'Plaintext HTTP/Telnet management enabled', 
            recommendation: 'Remove plaintext protocols from the interface management profile.',
            compliance: 'PCI-DSS Req 2.2.6 / CIS 4.1'
        });
    }
    
    // 2. XML Format - Block Level Processing
    if (text.includes('<?xml') || text.includes('<security>')) {
        const rulesBlockMatch = text.match(/<rules>([\s\S]*?)<\/rules>/i);
        if (rulesBlockMatch) {
            const entries = [...rulesBlockMatch[1].matchAll(/<entry name="([^"]+)">([\s\S]*?)<\/entry>/gi)];
            
            entries.forEach(entry => {
                const ruleName = entry[1];
                const body = entry[2];
                
                const isAllow = /<action>allow<\/action>/i.test(body);
                const fromAny = /<from>\s*<member>any<\/member>\s*<\/from>/i.test(body);
                const toAny = /<to>\s*<member>any<\/member>\s*<\/to>/i.test(body);
                const appAny = /<application>\s*<member>any<\/member>\s*<\/application>/i.test(body);
                const serviceAny = /<service>\s*<member>(any|application-default)<\/member>\s*<\/service>/i.test(body);
                const loggingDisabled = /<log-end>no<\/log-end>/i.test(body);

                if (isAllow && fromAny && toAny) {
                    findings.push({ 
                        severity: 'CRITICAL', 
                        element: `Rule: ${ruleName}`, 
                        issue: 'Permissive Access (Any-to-Any)', 
                        recommendation: 'Restrict zones and source/destination addresses.',
                        compliance: 'PCI-DSS Req 1.2.1 / NIST 800-41'
                    });
                }
                if (isAllow && loggingDisabled) {
                    findings.push({ 
                        severity: 'HIGH', 
                        element: `Rule: ${ruleName}`, 
                        issue: 'Traffic Logging Disabled on Allow Rule', 
                        recommendation: 'Enable session end logging to maintain a secure audit trail.',
                        compliance: 'PCI-DSS Req 10.2.1 / CIS 8.2'
                    });
                }
                if (isAllow && appAny && serviceAny) {
                    findings.push({ 
                        severity: 'MEDIUM', 
                        element: `Rule: ${ruleName}`, 
                        issue: 'Unrestricted Application & Service', 
                        recommendation: 'Define specific App-IDs instead of port-based Any.',
                        compliance: 'PCI-DSS Req 1.2.2 / CIS 4.4'
                    });
                }
            });
        }
    } else {
        // 3. CLI "Set" Format - Grouping by Rule Name
        const ruleLines = [...text.matchAll(/^\s*set rulebase security rules\s+"?([^"\n]+)"?\s+(.*)/gim)];
        const rules = {};
        
        ruleLines.forEach(match => {
            const name = match[1];
            if (!rules[name]) rules[name] = "";
            rules[name] += match[2] + "\n";
        });

        Object.keys(rules).forEach(ruleName => {
            const body = rules[ruleName];
            if (/action allow/i.test(body) && /from any/i.test(body) && /to any/i.test(body)) {
                findings.push({ 
                    severity: 'CRITICAL', 
                    element: `Rule: ${ruleName}`, 
                    issue: 'Permissive Access (Any-to-Any)', 
                    recommendation: 'Restrict zones and source/destination addresses.',
                    compliance: 'PCI-DSS Req 1.2.1 / NIST 800-41'
                });
            }
        });
    }

    return findings;
}

function auditMeraki(text) {
    const findings = [];
    
    // 1. Global Checks
    if (/"syslogDefaultRule"\s*:\s*false/i.test(text)) {
        findings.push({ 
            severity: 'HIGH', 
            element: 'Network Wide Settings', 
            issue: 'Default syslog logging disabled', 
            recommendation: 'Enable syslog logging for traffic visibility.',
            compliance: 'PCI-DSS Req 10.2.1 / CIS 8.2'
        });
    }

    // 2. JSON Object Block Extraction
    const ruleBlocks = text.match(/\{[^{}]*?\}/g) || [];
    
    ruleBlocks.forEach((body, index) => {
        if (/"policy"\s*:\s*"allow"/i.test(body)) {
            const srcAny = /"srcCidr"\s*:\s*"Any"/i.test(body);
            const destAny = /"destCidr"\s*:\s*"Any"/i.test(body);
            const srcPortAny = /"srcPort"\s*:\s*"Any"/i.test(body);
            const destPortAny = /"destPort"\s*:\s*"Any"/i.test(body);

            if (srcAny && destAny) {
                findings.push({ 
                    severity: 'CRITICAL', 
                    element: `L3 Rule Block ${index + 1}`, 
                    issue: 'Permissive Access (Any-to-Any)', 
                    recommendation: 'Restrict CIDR blocks in the Meraki Dashboard.',
                    compliance: 'PCI-DSS Req 1.2.1 / NIST 800-41'
                });
            }
            if (srcPortAny && destPortAny) {
                findings.push({ 
                    severity: 'MEDIUM', 
                    element: `L3 Rule Block ${index + 1}`, 
                    issue: 'Service port set to ALL', 
                    recommendation: 'Define explicit TCP/UDP ports.',
                    compliance: 'PCI-DSS Req 1.2.2 / CIS 4.4'
                });
            }
        }
    });

    return findings;
}

function auditSophos(text) {
    const findings = [];
    
    // 1. Global Checks
    if (/(Administration.*Device\s*Access.*HTTP\s*:\s*Enable|<ManageHTTP>Enable<\/ManageHTTP>)/i.test(text)) {
        findings.push({ 
            severity: 'HIGH', 
            element: 'Device Access', 
            issue: 'HTTP administration enabled', 
            recommendation: 'Disable HTTP access on WAN and LAN zones.',
            compliance: 'PCI-DSS Req 2.2.6 / CIS 4.1'
        });
    }

    // 2. XML Format Block Extraction
    const xmlRules = [...text.matchAll(/<FirewallRule>([\s\S]*?)<\/FirewallRule>/gi)];
    
    xmlRules.forEach((rule, index) => {
        const body = rule[1];
        const nameMatch = body.match(/<Name>([^<]+)<\/Name>/i);
        const ruleName = nameMatch ? nameMatch[1] : `Rule ${index + 1}`;

        const cleanBody = body.replace(/\n/g, ' ');
        
        const isAccept = /<Action>Accept<\/Action>/i.test(cleanBody);
        const hasSourceAny = /<SourceNetworks>.*Any.*<\/SourceNetworks>/i.test(cleanBody);
        const hasDestAny = /<DestinationNetworks>.*Any.*<\/DestinationNetworks>/i.test(cleanBody);
        const hasServiceAny = /<Services>.*Any.*<\/Services>/i.test(cleanBody);
        const loggingDisabled = /<LogTraffic>Disable<\/LogTraffic>/i.test(cleanBody);

        if (isAccept && hasSourceAny && hasDestAny) {
             findings.push({ 
                 severity: 'CRITICAL', 
                 element: `Rule: ${ruleName}`, 
                 issue: 'Permissive Access (Any-to-Any)', 
                 recommendation: 'Lock down source and destination networks explicitly.',
                 compliance: 'PCI-DSS Req 1.2.1 / NIST 800-41'
             });
        }
        if (isAccept && loggingDisabled) {
             findings.push({ 
                 severity: 'HIGH', 
                 element: `Rule: ${ruleName}`, 
                 issue: 'Traffic Logging Disabled on Allow Rule', 
                 recommendation: 'Enable rule-level logging to maintain compliance tracks.',
                 compliance: 'PCI-DSS Req 10.2.1 / CIS 8.2'
             });
        }
        if (isAccept && hasServiceAny) {
             findings.push({ 
                 severity: 'MEDIUM', 
                 element: `Rule: ${ruleName}`, 
                 issue: 'Service port set to ALL', 
                 recommendation: 'Define specific ports and services.',
                 compliance: 'PCI-DSS Req 1.2.2 / CIS 4.4'
             });
        }
    });

    return findings;
}
