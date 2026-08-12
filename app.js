document.addEventListener('DOMContentLoaded', () => {
    const fileInput = document.getElementById('configFile');
    const fileNameDisplay = document.getElementById('fileName');
    const runAuditBtn = document.getElementById('runAuditBtn');
    const resultsSection = document.getElementById('resultsSection');
    const resultsContent = document.getElementById('resultsContent');
    const downloadPdfBtn = document.getElementById('downloadPdfBtn');

    let fileContent = "";

    fileInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (file) {
            fileNameDisplay.textContent = file.name;
            const reader = new FileReader();
            reader.onload = (event) => { fileContent = event.target.result; };
            reader.readAsText(file);
        } else {
            fileNameDisplay.textContent = "No file chosen";
            fileContent = "";
        }
    });

    runAuditBtn.addEventListener('click', () => {
        if (!fileContent) { alert("Please upload a configuration file first."); return; }

        const vendor = document.getElementById('vendor').value;
        const modules = {
            Security: document.getElementById('auditSecurity').checked,
            Routing: document.getElementById('auditRouting').checked,
            'SD-WAN': document.getElementById('auditSdWan').checked,
            VPN: document.getElementById('auditVpn').checked
        };

        const results = analyzeConfig(fileContent, vendor, modules);
        displayReadableResults(results);
    });

    downloadPdfBtn.addEventListener('click', () => {
        const element = document.getElementById('resultsSection');
        downloadPdfBtn.style.display = 'none';

        const opt = {
            margin:       [0.5, 0.5, 0.5, 0.5],
            filename:     'Network_Compliance_Audit.pdf',
            image:        { type: 'jpeg', quality: 0.98 },
            html2canvas:  { scale: 2, useCORS: true },
            jsPDF:        { unit: 'in', format: 'legal', orientation: 'landscape' },
            pagebreak:    { mode: ['css', 'legacy'] }
        };

        html2pdf().set(opt).from(element).save().then(() => {
            downloadPdfBtn.style.display = 'block';
        });
    });

    // --- Core Evaluation Engine ---
    function analyzeConfig(config, vendor, modules) {
        let findings = { metrics: { critical: 0, high: 0, medium: 0, passed: 0 }, categories: {} };
        const lines = config.split('\n');
        
        if (modules.Security) findings.categories.Security = evaluatePolicies(lines, vendor, findings.metrics);
        if (modules.Routing) findings.categories.Routing = evaluateRouting(lines, vendor, findings.metrics);
        if (modules['SD-WAN']) findings.categories['SD-WAN'] = evaluateSdWan(lines, vendor, findings.metrics);
        if (modules.VPN) findings.categories.VPN = evaluateVpn(lines, vendor, findings.metrics);
        
        return findings;
    }

    // --- Smart Block Extractor (For Routing/VPN) ---
    function extractBlocks(lines, startKeywords, endKeyword) {
        let blocks = [];
        let currentBlock = [];
        let inBlock = false;

        lines.forEach(line => {
            const l = line.trim().toLowerCase();
            if (!inBlock && startKeywords.some(kw => l.startsWith(kw))) {
                inBlock = true;
                currentBlock = [];
            }
            if (inBlock) {
                currentBlock.push(line.trim());
                if (l === endKeyword || l === '!') {
                    blocks.push(currentBlock.join('\n'));
                    inBlock = false;
                }
            }
        });
        return blocks;
    }

    // --- Security Policies Evaluator (Granular Rule-by-Rule Analysis) ---
    function evaluatePolicies(lines, vendor, metrics) {
        let results = [];
        
        if (vendor === 'fortigate') {
            let inPolicyContext = false;
            let currentPolicyId = 'Unknown';
            let currentBlock = [];

            lines.forEach(line => {
                const l = line.trim().toLowerCase();
                
                // Enter Firewall Policy Context
                if (l === 'config firewall policy') {
                    inPolicyContext = true;
                } 
                // Exit Firewall Policy Context
                else if (inPolicyContext && l === 'end' && currentBlock.length === 0) {
                    inPolicyContext = false;
                } 
                // Inside Context Processing
                else if (inPolicyContext) {
                    if (l.startsWith('edit ')) {
                        // Analyze previous rule if one exists
                        if (currentBlock.length > 0) evaluateRuleBlock(currentPolicyId, currentBlock.join('\n'), results, metrics);
                        // Start new rule
                        currentPolicyId = l.split(' ')[1];
                        currentBlock = [];
                    } else if (l === 'next' || l === 'end') {
                        // Close and analyze current rule
                        if (currentBlock.length > 0) evaluateRuleBlock(currentPolicyId, currentBlock.join('\n'), results, metrics);
                        currentBlock = [];
                        if (l === 'end') inPolicyContext = false;
                    } else {
                        currentBlock.push(line.trim());
                    }
                }
            });
        } else {
            // Cisco / Generic logic (Line-by-line ACEs)
            lines.forEach(line => {
                const l = line.trim().toLowerCase();
                if (l.startsWith('access-list') || l.startsWith('permit') || l.startsWith('deny')) {
                    let parts = l.split(' ');
                    let ruleId = l.startsWith('access-list') ? parts[1] : 'Named-ACL/Interface-Rule';
                    evaluateRuleBlock(ruleId, l, results, metrics);
                }
            });
        }

        if (results.length === 0) {
            return [{ severity: 'info', finding: '<strong>No security policies detected.</strong>', configSnippet: '', recommendation: '-', compliance: '-' }];
        }
        return results;
    }

    // Helper to evaluate an individual Rule/Policy ID
    function evaluateRuleBlock(ruleId, blockText, results, metrics) {
        const b = blockText.toLowerCase();
        
        if ((b.includes('set action accept') || b.includes('permit')) && (b.includes('all') || b.includes('any'))) {
            metrics.critical++;
            results.push({
                severity: 'critical',
                finding: `<strong>Policy/Rule ID: ${ruleId}</strong><br><span style="color: #dc3545; font-size: 0.9em;">Issue: Overly permissive rule detected (Any/All traffic allowed).</span>`,
                configSnippet: '', // Intentionally blank so we don't display the code block
                recommendation: 'Restrict traffic to specific source/destination IPs and required ports. Implement least privilege access.',
                compliance: 'PCI DSS 4.0 (Req 1.2.1), CIS Benchmark'
            });
        } else if (b.includes('set action deny') || b.includes('deny')) {
            // Explicit denies are good. Log as pass but skip rendering to prevent dashboard clutter.
            metrics.passed++;
        } else {
            metrics.passed++;
            // Optional: You can comment out the push() below if you only want to display failures in the table
            results.push({
                severity: 'pass',
                finding: `<strong>Policy/Rule ID: ${ruleId}</strong><br><span style="color: #28a745; font-size: 0.9em;">Status: Policy reviewed and scope is constrained.</span>`,
                configSnippet: '', 
                recommendation: '-',
                compliance: 'PCI DSS 4.0 (Req 1.2)'
            });
        }
    }

    // Evaluator: VPN
    function evaluateVpn(lines, vendor, metrics) {
        let results = [];
        const blockEnd = vendor === 'fortigate' ? 'end' : '!';
        const startKeys = ['config vpn ipsec', 'config vpn ssl', 'crypto isakmp', 'crypto map'];
        
        const blocks = extractBlocks(lines, startKeys, blockEnd);
        if (blocks.length === 0) return [];

        blocks.forEach(block => {
            const b = block.toLowerCase();
            if (b.includes('des') || b.includes('md5') || b.includes('sha1')) {
                metrics.critical++;
                results.push({
                    severity: 'critical',
                    finding: '<strong>Weak cryptography (DES/3DES/MD5/SHA1) detected in VPN configuration.</strong>',
                    configSnippet: block,
                    recommendation: 'Upgrade to AES-256 for encryption and SHA-256/384 for hashing.',
                    compliance: 'PCI DSS 4.0 (Req 4.2), NIST SP 800-52'
                });
            } else if (b.includes('sslv3') || b.includes('tls1-0')) {
                metrics.high++;
                results.push({
                    severity: 'high',
                    finding: '<strong>Deprecated TLS/SSL protocol enabled.</strong>',
                    configSnippet: block,
                    recommendation: 'Force TLS 1.2 or TLS 1.3 only.',
                    compliance: 'PCI DSS 4.0 (Req 4.2)'
                });
            } else {
                metrics.passed++;
                results.push({
                    severity: 'pass',
                    finding: '<strong>VPN cryptography parameters meet baseline.</strong>',
                    configSnippet: block,
                    recommendation: '-',
                    compliance: 'PCI DSS 4.0 (Req 4.2)'
                });
            }
        });
        return results;
    }

    // Evaluator: Routing
    function evaluateRouting(lines, vendor, metrics) {
        let results = [];
        const blockEnd = vendor === 'fortigate' ? 'end' : '!';
        const startKeys = ['config router bgp', 'config router ospf', 'router bgp', 'router ospf'];
        
        const blocks = extractBlocks(lines, startKeys, blockEnd);
        if (blocks.length === 0) return [];

        blocks.forEach(block => {
            if (block.toLowerCase().includes('bgp') && !block.toLowerCase().includes('password')) {
                metrics.medium++;
                results.push({
                    severity: 'medium',
                    finding: '<strong>BGP routing configured without neighbor authentication.</strong>',
                    configSnippet: block,
                    recommendation: 'Configure MD5/SHA authentication for BGP neighbors to prevent route hijacking.',
                    compliance: 'CIS Benchmark, NIST SP 800-54'
                });
            } else {
                metrics.passed++;
                results.push({
                    severity: 'pass',
                    finding: '<strong>Routing parameters align with baseline.</strong>',
                    configSnippet: block,
                    recommendation: '-',
                    compliance: 'CIS Benchmark'
                });
            }
        });
        return results;
    }

    // Evaluator: SD-WAN
    function evaluateSdWan(lines, vendor, metrics) {
        let results = [];
        const blockEnd = vendor === 'fortigate' ? 'end' : '!';
        const startKeys = ['config system sdwan', 'sd-wan'];
        
        const blocks = extractBlocks(lines, startKeys, blockEnd);
        if (blocks.length === 0) return [];

        blocks.forEach(block => {
            metrics.passed++;
            results.push({
                severity: 'pass',
                finding: '<strong>SD-WAN zone/rule extracted successfully.</strong>',
                configSnippet: block,
                recommendation: 'Ensure SLA parameters are tightly bound to critical app traffic.',
                compliance: 'Best Practice'
            });
        });
        return results;
    }

    // --- Dynamic Renderer ---
    function displayReadableResults(findings) {
        resultsContent.innerHTML = '';
        const m = findings.metrics;
        
        // Update Dashboard
        document.getElementById('m-crit').textContent = m.critical;
        document.getElementById('m-high').textContent = m.high;
        document.getElementById('m-med').textContent = m.medium;
        document.getElementById('m-pass').textContent = m.passed;

        // Render Tables per module
        for (const [moduleName, moduleFindings] of Object.entries(findings.categories)) {
            if (moduleFindings.length === 0) continue;

            const sec = document.createElement('div');
            sec.className = 'module-section';
            sec.innerHTML = `<h3>${moduleName} Analysis</h3>`;

            const table = document.createElement('table');
            table.className = 'audit-table';
            
            // Table Header
            table.innerHTML = `
                <thead>
                    <tr>
                        <th style="width: 15%">Severity</th>
                        <th style="width: 45%">Finding / Configuration</th>
                        <th style="width: 25%">Recommendation</th>
                        <th style="width: 15%">Compliance</th>
                    </tr>
                </thead>
            `;
            
            const tbody = document.createElement('tbody');
            
            moduleFindings.forEach(item => {
                const tr = document.createElement('tr');
                
                // Severity Badge
                const tdSev = document.createElement('td');
                tdSev.innerHTML = `<span class="severity-badge sev-${item.severity}">${item.severity.toUpperCase()}</span>`;
                
                // Finding & Config Snippet
                const tdFinding = document.createElement('td');
                tdFinding.innerHTML = item.finding; // Now renders formatted HTML like <strong>Rule ID: X</strong>
                
                // Only renders if configSnippet actually has content
                if (item.configSnippet && item.configSnippet.trim() !== '') {
                    tdFinding.innerHTML += `<div class="config-snippet">${item.configSnippet.replace(/</g, "&lt;").replace(/>/g, "&gt;")}</div>`;
                }

                // Recommendation
                const tdRec = document.createElement('td');
                tdRec.textContent = item.recommendation;

                // Compliance Mapping
                const tdComp = document.createElement('td');
                tdComp.innerHTML = `<span style="font-size: 0.85em; color: #555;">${item.compliance}</span>`;
                
                tr.appendChild(tdSev);
                tr.appendChild(tdFinding);
                tr.appendChild(tdRec);
                tr.appendChild(tdComp);
                tbody.appendChild(tr);
            });
            
            table.appendChild(tbody);
            sec.appendChild(table);
            resultsContent.appendChild(sec);
        }

        resultsSection.style.display = 'block';
    }
});
