document.addEventListener('DOMContentLoaded', () => {
    const fileInput = document.getElementById('configFile');
    const fileNameDisplay = document.getElementById('fileName');
    const runAuditBtn = document.getElementById('runAuditBtn');
    const resultsSection = document.getElementById('resultsSection');
    const resultsContent = document.getElementById('resultsContent');
    const downloadPdfBtn = document.getElementById('downloadPdfBtn');

    let fileContent = "";

    // Handle file selection
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
        if (!fileContent) {
            alert("Please upload a configuration file first.");
            return;
        }

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
            margin:       0.5,
            filename:     'Network_Compliance_Audit.pdf',
            image:        { type: 'jpeg', quality: 0.98 },
            html2canvas:  { scale: 2 },
            jsPDF:        { unit: 'in', format: 'letter', orientation: 'landscape' } // Changed to landscape for wide tables
        };

        html2pdf().set(opt).from(element).save().then(() => {
            downloadPdfBtn.style.display = 'block';
        });
    });

    // --- Core Evaluation Engine ---
    function analyzeConfig(config, vendor, modules) {
        let findings = { metrics: { critical: 0, high: 0, medium: 0, passed: 0 }, categories: {} };
        
        if (modules.Security) findings.categories.Security = evaluatePolicies(config, vendor, findings.metrics);
        if (modules.Routing) findings.categories.Routing = evaluateRouting(config, vendor, findings.metrics);
        if (modules['SD-WAN']) findings.categories['SD-WAN'] = evaluateSdWan(config, vendor, findings.metrics);
        if (modules.VPN) findings.categories.VPN = evaluateVpn(config, vendor, findings.metrics);
        
        return findings;
    }

    // Evaluator: Security Policies
    function evaluatePolicies(config, vendor, metrics) {
        let results = [];
        const lines = config.split('\n');
        
        // Mock analysis logic for overly permissive rules
        let hasDenyAll = false;
        
        lines.forEach((line) => {
            const l = line.toLowerCase();
            if (l.includes('policy') || l.includes('permit') || l.includes('deny')) {
                if ((l.includes('permit') || l.includes('accept')) && l.includes('any') && (l.includes('all') || l.includes('any'))) {
                    metrics.critical++;
                    results.push({
                        severity: 'critical',
                        finding: 'Overly permissive "Any-Any" allow rule detected.',
                        recommendation: 'Restrict inbound/outbound traffic to specific source/destination IPs and required ports only. Implement least privilege access.',
                        cliFix: vendor === 'fortigate' ? 'set srcaddr "Specific_Subnet"\nset dstaddr "Specific_Destination"' : 'permit tcp host [SRC] host [DST] eq [PORT]',
                        compliance: 'PCI DSS 4.0 (Req 1.2, 7.1.2), CIS Benchmark Firewall Ruleset'
                    });
                }
                if (l.includes('deny') && l.includes('any')) {
                    hasDenyAll = true;
                }
            }
        });

        if (!hasDenyAll) {
            metrics.high++;
            results.push({
                severity: 'high',
                finding: 'Missing explicit "Deny-All" cleanup rule at the bottom of the ACL/Policy.',
                recommendation: 'Add an explicit deny rule to log and drop all unmatched traffic.',
                cliFix: vendor === 'fortigate' ? 'edit 0\nset action deny\nset logtraffic all' : 'deny ip any any log',
                compliance: 'PCI DSS 4.0 (Req 1.2), CIS Benchmark'
            });
        } else {
            metrics.passed++;
            results.push({ severity: 'pass', finding: 'Explicit Deny-All rule exists.', recommendation: '-', cliFix: '', compliance: 'PCI DSS 4.0 (Req 1.2)' });
        }
        return results;
    }

    // Evaluator: VPN Parameters
    function evaluateVpn(config, vendor, metrics) {
        let results = [];
        const lines = config.split('\n');
        
        lines.forEach((line) => {
            const l = line.toLowerCase();
            // Check for weak cryptographic protocols
            if (l.includes('crypto') || l.includes('vpn') || l.includes('proposal')) {
                if (l.includes('des') || l.includes('3des') || l.includes('md5') || l.includes('sha1')) {
                    metrics.critical++;
                    results.push({
                        severity: 'critical',
                        finding: `Weak encryption/hashing algorithm detected in VPN config: ${line.trim()}`,
                        recommendation: 'Upgrade immediately to AES-256 for encryption and SHA-256/SHA-384 for hashing. Disable insecure protocols.',
                        cliFix: vendor === 'fortigate' ? 'set proposal aes256-sha256' : 'crypto ikev2 proposal DEFAULT\n encryption aes-cbc-256\n integrity sha256',
                        compliance: 'PCI DSS 4.0 (Req 4.2 - Strong Cryptography), NIST SP 800-52 Rev 2'
                    });
                }
                if (l.includes('sslv3') || l.includes('tls1.0') || l.includes('tls 1.0')) {
                    metrics.high++;
                    results.push({
                        severity: 'high',
                        finding: 'Deprecated TLS/SSL version enabled for WebVPN/SSLVPN.',
                        recommendation: 'Disable SSLv3 and TLS 1.0/1.1. Mandate TLS 1.2 or TLS 1.3.',
                        cliFix: vendor === 'fortigate' ? 'set ssl-min-proto-version tls1-2' : 'ssl server-version tlsv1.2',
                        compliance: 'PCI DSS 4.0 (Req 4.2)'
                    });
                }
            }
        });

        if (results.length === 0) {
            metrics.passed++;
            results.push({ severity: 'pass', finding: 'No weak VPN cryptographic parameters detected.', recommendation: '-', cliFix: '', compliance: 'PCI DSS 4.0 (Req 4.2)' });
        }
        return results;
    }

    // Evaluator: Routing (Mocked for demonstration)
    function evaluateRouting(config, vendor, metrics) {
        let results = [];
        if (config.toLowerCase().includes('router bgp') && !config.toLowerCase().includes('password')) {
            metrics.medium++;
            results.push({
                severity: 'medium',
                finding: 'BGP routing protocol configured without neighbor authentication.',
                recommendation: 'Configure MD5 or SHA authentication for all BGP neighbors to prevent route hijacking.',
                cliFix: 'neighbor x.x.x.x password [STRONG_PASSWORD]',
                compliance: 'CIS Benchmark, NIST SP 800-54'
            });
        }
        return results.length ? results : [{ severity: 'pass', finding: 'Routing configurations align with baselines.', recommendation: '-', cliFix: '', compliance: 'N/A' }];
    }

    // Evaluator: SD-WAN (Mocked for demonstration)
    function evaluateSdWan(config, vendor, metrics) {
        let results = [];
        if (vendor === 'versa' && !config.toLowerCase().includes('sla-class')) {
            metrics.medium++;
            results.push({
                severity: 'medium',
                finding: 'SD-WAN traffic steering lacks explicit SLA class bindings.',
                recommendation: 'Define SLA parameters (latency, jitter, packet loss) to ensure reliable failover for critical applications.',
                cliFix: 'set sla-class "Critical-Apps" latency 150 jitter 30',
                compliance: 'Vendor Best Practices'
            });
        }
        return results.length ? results : [{ severity: 'pass', finding: 'SD-WAN parameters appear properly configured.', recommendation: '-', cliFix: '', compliance: 'N/A' }];
    }


    // --- Human-Readable UI Renderer ---
    function displayReadableResults(findings) {
        resultsSection.classList.remove('hidden');
        resultsContent.innerHTML = '';

        // Render Scorecard
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
                        <th>Observation / Finding</th>
                        <th>Recommendation & Remediation</th>
                        <th>Compliance Standard</th>
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

                // Finding
                const tdFinding = document.createElement('td');
                tdFinding.textContent = item.finding;
                tr.appendChild(tdFinding);

                // Recommendation & CLI Fix
                const tdRec = document.createElement('td');
                let recHtml = item.recommendation;
                if (item.cliFix) {
                    recHtml += `<span class="fix-code">${item.cliFix.replace(/\n/g, '<br>')}</span>`;
                }
                tdRec.innerHTML = recHtml;
                tr.appendChild(tdRec);

                // Compliance Mapping
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
