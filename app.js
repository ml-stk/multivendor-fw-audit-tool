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

    // Execute Audit
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

    // Generate PDF Action
    downloadPdfBtn.addEventListener('click', () => {
        const element = document.getElementById('resultsSection');
        // Hide the download button during PDF generation so it doesn't appear in the document
        downloadPdfBtn.style.display = 'none';

        const opt = {
            margin:       0.5,
            filename:     'Network_Audit_Report.pdf',
            image:        { type: 'jpeg', quality: 0.98 },
            html2canvas:  { scale: 2 },
            jsPDF:        { unit: 'in', format: 'letter', orientation: 'portrait' }
        };

        html2pdf().set(opt).from(element).save().then(() => {
            // Restore button after saving
            downloadPdfBtn.style.display = 'block';
        });
    });

    // Core Analysis Engine
    function analyzeConfig(config, vendor, modules) {
        let findings = {};
        if (modules.Security) findings.Security = extractPolicies(config, vendor);
        if (modules.Routing) findings.Routing = extractRouting(config, vendor);
        if (modules['SD-WAN']) findings['SD-WAN'] = extractSdWan(config, vendor);
        if (modules.VPN) findings.VPN = extractVpn(config, vendor);
        return findings;
    }

    // --- Parser Modules ---
    function extractPolicies(config, vendor) {
        let data = [];
        const lines = config.split('\n');
        lines.forEach((line, index) => {
            if (line.toLowerCase().includes('policy') || line.toLowerCase().includes('permit') || line.toLowerCase().includes('deny')) {
                data.push({ lineNum: index + 1, detail: line.trim() });
            }
        });
        return data;
    }

    function extractRouting(config, vendor) {
        let data = [];
        const lines = config.split('\n');
        lines.forEach((line, index) => {
            const l = line.toLowerCase();
            if (l.includes('router bgp') || l.includes('router ospf') || l.includes('ip route') || l.includes('config router static')) {
                let type = l.includes('bgp') ? 'BGP' : l.includes('ospf') ? 'OSPF' : 'Static Route';
                data.push({ lineNum: index + 1, protocol: type, detail: line.trim() });
            }
        });
        return data;
    }

    function extractSdWan(config, vendor) {
        let data = [];
        const lines = config.split('\n');
        let inSdWanContext = false;
        
        lines.forEach((line, index) => {
            const l = line.trim().toLowerCase();
            if (l === 'config system sdwan' || l.includes('sd-wan')) inSdWanContext = true;
            else if (inSdWanContext && l === 'end') inSdWanContext = false;

            if (inSdWanContext && l !== 'config system sdwan') {
                data.push({ lineNum: index + 1, detail: line.trim() });
            }
        });
        return data;
    }

    function extractVpn(config, vendor) {
        let data = [];
        const lines = config.split('\n');
        lines.forEach((line, index) => {
            const l = line.toLowerCase();
            if (l.includes('crypto isakmp') || l.includes('config vpn ipsec') || l.includes('webvpn') || l.includes('config vpn ssl web')) {
                let type = l.includes('ssl') || l.includes('webvpn') ? 'SSL/Client VPN' : 'IPsec/Site-to-Site';
                data.push({ lineNum: index + 1, type: type, detail: line.trim() });
            }
        });
        return data;
    }

    // --- Human-Readable UI Renderer ---
    function displayReadableResults(findings) {
        resultsSection.classList.remove('hidden');
        resultsContent.innerHTML = '';

        for (const [moduleName, dataArray] of Object.entries(findings)) {
            const block = document.createElement('div');
            block.className = 'result-block';
            
            const title = document.createElement('h3');
            title.textContent = `${moduleName} Configuration`;
            block.appendChild(title);

            if (dataArray.length === 0) {
                const noData = document.createElement('p');
                noData.className = 'summary-text';
                noData.textContent = `No ${moduleName.toLowerCase()} configurations were detected in the uploaded file.`;
                block.appendChild(noData);
            } else {
                const summary = document.createElement('p');
                summary.className = 'summary-text';
                summary.textContent = `Identified ${dataArray.length} relevant configuration entries.`;
                block.appendChild(summary);

                const table = document.createElement('table');
                table.className = 'audit-table';
                
                // Build dynamic headers based on the module
                let headers = [];
                if (moduleName === 'Routing') headers = ['Line', 'Protocol', 'Configuration Detail'];
                else if (moduleName === 'VPN') headers = ['Line', 'VPN Type', 'Configuration Detail'];
                else headers = ['Line', 'Configuration Detail'];

                const thead = document.createElement('thead');
                const trHead = document.createElement('tr');
                headers.forEach(text => {
                    const th = document.createElement('th');
                    th.textContent = text;
                    trHead.appendChild(th);
                });
                thead.appendChild(trHead);
                table.appendChild(thead);

                const tbody = document.createElement('tbody');
                // Limit to first 20 entries to prevent massive tables, but note the truncation
                const displayLimit = 20;
                const itemsToDisplay = dataArray.slice(0, displayLimit);

                itemsToDisplay.forEach(item => {
                    const tr = document.createElement('tr');
                    
                    const tdLine = document.createElement('td');
                    tdLine.textContent = item.lineNum;
                    tr.appendChild(tdLine);

                    if (moduleName === 'Routing') {
                        const tdProto = document.createElement('td');
                        tdProto.textContent = item.protocol;
                        tr.appendChild(tdProto);
                    }
                    if (moduleName === 'VPN') {
                        const tdType = document.createElement('td');
                        tdType.textContent = item.type;
                        tr.appendChild(tdType);
                    }

                    const tdDetail = document.createElement('td');
                    // Clean up string formatting for readability
                    tdDetail.textContent = item.detail.replace(/[{}]/g, ''); 
                    tr.appendChild(tdDetail);

                    tbody.appendChild(tr);
                });

                table.appendChild(tbody);
                block.appendChild(table);

                if (dataArray.length > displayLimit) {
                    const truncationNotice = document.createElement('p');
                    truncationNotice.style.fontSize = '0.9em';
                    truncationNotice.style.color = '#888';
                    truncationNotice.textContent = `* Showing first ${displayLimit} entries. ${dataArray.length - displayLimit} additional lines hidden for readability.`;
                    block.appendChild(truncationNotice);
                }
            }

            resultsContent.appendChild(block);
        }
    }
});
