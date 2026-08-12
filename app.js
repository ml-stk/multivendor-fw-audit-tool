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

    // PDF Print Fix: Legal format, landscape, page-break CSS mode
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

    // --- Smart Block Extractor ---
    // Grabs hierarchical config blocks rather than single lines
    function extractBlocks(lines, startKeywords, endKeyword) {
        let blocks = [];
        let currentBlock = [];
        let inBlock = false;

        lines.forEach(line => {
            const l = line.trim().toLowerCase();
            
            // Check if line starts a block
            if (!inBlock && startKeywords.some(kw => l.startsWith(kw))) {
                inBlock = true;
                currentBlock = [];
            }
            
            if (inBlock) {
                currentBlock.push(line.trim());
                // Check if line ends a block
                if (l === endKeyword || l === '!') {
                    blocks.push(currentBlock.join('\n'));
                    inBlock = false;
                }
            }
        });
        return blocks;
    }

    // Evaluator: Security Policies
    function evaluatePolicies(lines, vendor, metrics) {
        let results = [];
        // FortiGate policies end with 'end', Cisco ACLs usually break by empty space or '!'
        const blockEnd = vendor === 'fortigate' ? 'end' : '!';
        const startKeys = vendor === 'fortigate' ? ['config firewall policy'] : ['access-list', 'ip access-list'];
        
        const blocks = extractBlocks(lines, startKeys, blockEnd);

        if (blocks.length === 0) {
            return [{ severity: 'info', finding: 'No security policy blocks detected.', configSnippet: '', recommendation: '-', compliance: '-' }];
        }

        blocks.forEach(block => {
            const b = block.toLowerCase();
            if ((b.includes('set action accept') || b.includes('permit')) && b.includes('all')) {
                metrics.critical++;
                results.push({
                    severity: 'critical',
                    finding: 'Overly permissive rule detected.',
                    configSnippet: block,
                    recommendation: 'Restrict traffic to specific IPs/ports. Implement least privilege access.',
                    compliance: 'PCI DSS 4.0 (Req 1.2.1), CIS Benchmark'
                });
            } else {
                metrics.passed++;
                results.push({
                    severity: 'pass',
                    finding: 'Policy reviewed: Scope is constrained.',
                    configSnippet: block,
                    recommendation: '-',
                    compliance: 'PCI DSS 4.0 (Req 1.2)'
                });
            }
        });
        return results;
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
                    finding: 'Weak cryptography (DES/3DES/MD5/SHA1) detected in VPN configuration.',
                    configSnippet: block,
                    recommendation: 'Upgrade to AES-256 and SHA-256/384.',
                    compliance: 'PCI DSS 4.0 (Req 4.2), NIST SP 800-52'
                });
            } else if (b.includes('sslv3') || b.includes('tls1-0')) {
                metrics.high++;
                results.push({
                    severity: 'high',
                    finding: 'Deprecated TLS/SSL protocol enabled.',
                    configSnippet: block,
                    recommendation: 'Force TLS 1.2 or TLS 1.3 only.',
                    compliance: 'PCI DSS 4.0 (Req 4.2)'
                });
            } else {
                metrics.passed++;
                results.push({
                    severity: 'pass',
                    finding: 'VPN cryptography parameters meet baseline.',
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
                    finding: 'BGP routing configured without neighbor authentication.',
                    configSnippet: block,
                    recommendation: 'Configure MD5/SHA authentication for BGP neighbors.',
                    compliance: 'CIS Benchmark, NIST SP 800-54'
                });
            } else {
                metrics.passed++;
                results.push({
                    severity: 'pass',
                    finding: 'Routing parameters align with baseline.',
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
                finding: 'SD-WAN zone/rule extracted successfully.',
                configSnippet: block,
                recommendation: 'Ensure SLA parameters are tightly bound to critical app traffic.',
                compliance: 'Vendor Best Practices'
            });
        });
        return results;
    }

    // --- Human-Readable UI Renderer ---
    function displayReadableResults(findings) {
        resultsSection.classList.remove('hidden');
        resultsContent.innerHTML = '';

        const scorecardHtml = `
            <div class="scorecard">
                <div class="score-card score-critical">Critical Risks: ${findings.metrics.critical}</div>
                <div class="score-card score-high">High Risks: ${findings.metrics.high}</div>
                <div class="score-card score-medium">Medium Risks: ${findings.metrics.medium}</div>
                <div class="score-card score-pass">Checks Passed: ${findings.metrics.passed}</div>
            </div>
        `;
        resultsContent.innerHTML += scorecardHtml;

        for (const [moduleName, dataArray] of Object.entries(findings.categories)) {
            if (dataArray.length === 0) continue;

            const block = document.createElement('div');
            block.className = 'result-block';
            
            const title = document.createElement('h3');
            title.textContent = `${moduleName} Security Posture`;
            block.appendChild(title);

            const table = document.createElement('table');
            table.className = 'audit-table';
            
            const thead = `
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Observation & Configuration</th>
                        <th>Recommendation & Remediation</th>
                        <th>Compliance</th>
                    </tr>
                </thead>
            `;
            table.innerHTML = thead;

            const tbody = document.createElement('tbody');
            
            dataArray.forEach(item => {
                const tr = document.createElement('tr');
                
                // Severity Badge
                const tdSeverity = document.createElement('td');
                tdSeverity.innerHTML = `<span class="badge ${item.severity}">${item.severity.toUpperCase()}</span>`;
                tr.appendChild(tdSeverity);

                // Finding & Config Snippet
                const tdFinding = document.createElement('td');
                tdFinding.innerHTML = `<strong>${item.finding}</strong>`;
                if (item.configSnippet) {
                    tdFinding.innerHTML += `<div class="config-snippet">${item.configSnippet.replace(/</g, "&lt;").replace(/>/g, "&gt;")}</div>`;
                }
                tr.appendChild(tdFinding);

                // Recommendation
                const tdRec = document.createElement('td');
                tdRec.innerHTML = item.recommendation;
                tr.appendChild(tdRec);

                // Compliance
                const tdComp = document.createElement('td');
                tdComp.textContent = item.compliance;
                tr.appendChild(tdComp);

                tbody.appendChild(tr);
            });

            table.appendChild(tbody);
            block.appendChild(table);
            resultsContent.appendChild(block);
        }
    }
});
