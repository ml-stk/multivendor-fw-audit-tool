document.addEventListener('DOMContentLoaded', () => {
    const fileInput = document.getElementById('configFile');
    const fileNameDisplay = document.getElementById('fileName');
    const runAuditBtn = document.getElementById('runAuditBtn');
    const resultsSection = document.getElementById('resultsSection');
    const resultsContent = document.getElementById('resultsContent');

    let fileContent = "";

    // Handle file selection
    fileInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (file) {
            fileNameDisplay.textContent = file.name;
            const reader = new FileReader();
            reader.onload = (event) => {
                fileContent = event.target.result;
            };
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
            security: document.getElementById('auditSecurity').checked,
            routing: document.getElementById('auditRouting').checked,
            sdwan: document.getElementById('auditSdWan').checked,
            vpn: document.getElementById('auditVpn').checked
        };

        const results = analyzeConfig(fileContent, vendor, modules);
        displayResults(results);
    });

    // Core Analysis Engine
    function analyzeConfig(config, vendor, modules) {
        let findings = {};

        if (modules.security) {
            findings.security = extractPolicies(config, vendor);
        }
        if (modules.routing) {
            findings.routing = extractRouting(config, vendor);
        }
        if (modules.sdwan) {
            findings.sdwan = extractSdWan(config, vendor);
        }
        if (modules.vpn) {
            findings.vpn = extractVpn(config, vendor);
        }

        return findings;
    }

    // --- Parser Modules ---

    function extractPolicies(config, vendor) {
        let policies = [];
        // Basic match example (can be expanded for object groups)
        const lines = config.split('\n');
        lines.forEach(line => {
            if (line.toLowerCase().includes('policy') || line.toLowerCase().includes('permit') || line.toLowerCase().includes('deny')) {
                policies.push(line.trim());
            }
        });
        return policies.length ? policies.slice(0, 10) : ["No standard security policies detected."]; // Truncated for demo
    }

    function extractRouting(config, vendor) {
        const routingData = { bgp: [], ospf: [], static: [] };
        const lines = config.split('\n');
        
        lines.forEach(line => {
            const l = line.toLowerCase();
            if (l.includes('router bgp')) routingData.bgp.push(line.trim());
            if (l.includes('router ospf')) routingData.ospf.push(line.trim());
            if (l.includes('ip route') || l.includes('config router static')) routingData.static.push(line.trim());
        });
        return routingData;
    }

    function extractSdWan(config, vendor) {
        const sdwanRules = [];
        const lines = config.split('\n');
        
        let inSdWanContext = false;
        lines.forEach(line => {
            const l = line.trim().toLowerCase();
            // Vendor specific context switching
            if (l === 'config system sdwan' || l.includes('sd-wan')) {
                inSdWanContext = true;
            } else if (inSdWanContext && l === 'end') {
                inSdWanContext = false;
            }

            if (inSdWanContext) {
                sdwanRules.push(line.trim());
            }
        });
        return sdwanRules.length ? sdwanRules : ["No SD-WAN configurations detected."];
    }

    function extractVpn(config, vendor) {
        const vpnData = { ipsec: [], ssl: [] };
        const lines = config.split('\n');
        
        lines.forEach(line => {
            const l = line.toLowerCase();
            if (l.includes('crypto isakmp') || l.includes('config vpn ipsec')) vpnData.ipsec.push(line.trim());
            if (l.includes('webvpn') || l.includes('config vpn ssl web')) vpnData.ssl.push(line.trim());
        });
        return vpnData;
    }

    // --- UI Renderer ---

    function displayResults(findings) {
        resultsSection.classList.remove('hidden');
        resultsContent.innerHTML = '';

        for (const [module, data] of Object.entries(findings)) {
            const block = document.createElement('div');
            block.className = 'result-block';
            
            const title = document.createElement('h3');
            title.textContent = module.charAt(0).toUpperCase() + module.slice(1) + ' Analysis';
            block.appendChild(title);

            const pre = document.createElement('pre');
            pre.textContent = JSON.stringify(data, null, 2);
            block.appendChild(pre);

            resultsContent.appendChild(block);
        }
    }
});
