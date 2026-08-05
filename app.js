document.getElementById('configFile').addEventListener('change', function(event) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function(e) {
        const text = e.target.result;
        runAudit(text);
    };
    reader.readAsText(file);
});

let globalFindings = [];

function runAudit(configText) {
    const lines = configText.split('\n');
    let inPolicyBlock = false;
    let currentPolicy = null;
    globalFindings = [];

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();

        // State Machine: Track context
        if (line.startsWith("config firewall policy")) {
            inPolicyBlock = true;
            continue;
        } else if (line === "end" && inPolicyBlock) {
            inPolicyBlock = false;
            continue;
        }

        // Parse Policies
        if (inPolicyBlock) {
            if (line.startsWith("edit ")) {
                currentPolicy = {
                    id: line.split(/\s+/)[1],
                    logtraffic: "disable",
                    action: "deny",
                    srcaddr: "",
                    dstaddr: "",
                    service: ""
                };
            } else if (line.startsWith("set ") && currentPolicy) {
                const parts = line.split(/\s+/);
                if (parts.length >= 3) {
                    const key = parts[1];
                    const val = line.substring(line.indexOf(parts[2])).replace(/"/g, '');
                    currentPolicy[key] = val;
                }
            } else if (line === "next" && currentPolicy) {
                evaluatePolicy(currentPolicy);
                currentPolicy = null;
            }
        }

        // Parse System Settings (Management Access)
        if (line.startsWith("set allowaccess")) {
            const lowerLine = line.toLowerCase();
            if (lowerLine.includes("telnet") || lowerLine.includes("http ")) {
                globalFindings.push({
                    severity: "CRITICAL",
                    element: "System Interface",
                    issue: "Insecure management protocol (Telnet/HTTP) enabled.",
                    recommendation: "Remove insecure protocols from allowaccess. Use SSH/HTTPS only."
                });
            }
        }
    }

    renderResults();
}

function evaluatePolicy(pol) {
    if (pol.action !== "accept") return;

    // Check 1: Any-Any Allow Rules
    if (pol.srcaddr.includes("all") && pol.dstaddr.includes("all")) {
        globalFindings.push({
            severity: "CRITICAL",
            element: `Policy ${pol.id}`,
            issue: "Permissive Access (Any-to-Any)",
            recommendation: "Restrict source and destination addresses to specific subnets."
        });
    }

    // Check 2: Missing Logging (Crucial for PCI-DSS)
    if (pol.logtraffic === "disable") {
        globalFindings.push({
            severity: "HIGH",
            element: `Policy ${pol.id}`,
            issue: "Traffic Logging Disabled on Allow Rule",
            recommendation: "Set logtraffic to 'all' or 'utm' to ensure an audit trail is maintained."
        });
    }

    // Check 3: Unrestricted Services
    if (pol.service.includes("ALL") || pol.service.includes("ANY")) {
        globalFindings.push({
            severity: "MEDIUM",
            element: `Policy ${pol.id}`,
            issue: "Service port set to ALL",
            recommendation: "Define explicit TCP/UDP ports required for the application."
        });
    }
}

function renderResults() {
    document.getElementById('resultsArea').classList.remove('hidden');
    const tableBody = document.getElementById('tableBody');
    const summaryBox = document.getElementById('summaryBox');
    
    tableBody.innerHTML = '';

    if (globalFindings.length === 0) {
        summaryBox.className = 'summary-box summary-success';
        summaryBox.innerText = '✅ Clean bill of health! No baseline violations found.';
        document.getElementById('findingsTable').style.display = 'none';
        document.getElementById('exportBtn').style.display = 'none';
        return;
    }

    summaryBox.className = 'summary-box summary-error';
    summaryBox.innerText = `⚠️ Found ${globalFindings.length} potential security issues.`;
    document.getElementById('findingsTable').style.display = 'table';
    document.getElementById('exportBtn').style.display = 'inline-block';

    globalFindings.forEach(finding => {
        const row = document.createElement('tr');
        const severityClass = `severity-${finding.severity.toLowerCase()}`;
        
        row.innerHTML = `
            <td><span class="badge ${severityClass}">${finding.severity}</span></td>
            <td><strong>${finding.element}</strong></td>
            <td>${finding.issue}</td>
            <td>${finding.recommendation}</td>
        `;
        tableBody.appendChild(row);
    });
}

// Export to CSV Functionality
document.getElementById('exportBtn').addEventListener('click', () => {
    let csvContent = "data:text/csv;charset=utf-8,Severity,Element,Security Issue,Recommendation\n";
    
    globalFindings.forEach(f => {
        const issue = f.issue.replace(/"/g, '""');
        const rec = f.recommendation.replace(/"/g, '""');
        csvContent += `${f.severity},${f.element},"${issue}","${rec}"\n`;
    });

    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", "fortigate_audit_report.csv");
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
});