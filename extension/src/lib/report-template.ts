/**
 * S2N Scanner - HTML Report Template generator
 */

import type { ScanHistoryItem } from '@/types/scan'

/**
 * 통계 데이터를 포함한 예쁜 HTML 리포트 생성
 */
export function generateHtmlReport(scan: ScanHistoryItem): string {
    const findingsListHtml = scan.findings.map(finding => `
        <div class="finding-card border rounded-lg p-4 mb-4 shadow-sm bg-white break-words">
            <div class="flex justify-between items-start mb-2">
                <h3 class="text-lg font-semibold text-gray-900">${finding.title}</h3>
                <span class="px-2 py-1 text-xs font-bold rounded-full severity-${finding.severity.toLowerCase()} text-white">
                    ${finding.severity}
                </span>
            </div>
            <div class="text-sm text-gray-600 mb-4 whitespace-pre-wrap">${finding.description}</div>
            
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm bg-gray-50 p-3 rounded-md">
                ${finding.url ? `<div><strong>URL:</strong> <span class="text-blue-600">${finding.url}</span></div>` : ''}
                ${finding.method ? `<div><strong>Method:</strong> ${finding.method}</div>` : ''}
                ${finding.plugin ? `<div><strong>Plugin:</strong> ${finding.plugin}</div>` : ''}
                ${finding.parameter ? `<div><strong>Parameter:</strong> ${finding.parameter}</div>` : ''}
                ${finding.cweId ? `<div><strong>CWE:</strong> ${finding.cweId}</div>` : ''}
                ${finding.cvssScore !== undefined ? `<div><strong>CVSS Score:</strong> ${finding.cvssScore}</div>` : ''}
            </div>

            ${finding.evidence ? `
                <div class="mt-4">
                    <strong class="text-sm">Evidence:</strong>
                    <pre class="bg-gray-800 text-gray-100 p-3 rounded-md mt-1 overflow-x-auto text-xs">${finding.evidence}</pre>
                </div>
            ` : ''}
             ${finding.reference ? `
                <div class="mt-4 text-sm">
                    <strong>Reference:</strong> <a href="${finding.reference}" target="_blank" class="text-blue-500 hover:underline">${finding.reference}</a>
                </div>
            ` : ''}
        </div>
    `).join('')

    return `
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>S2N Scanner Report - ${scan.targetUrl}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        .severity-critical { background-color: #ef4444; } /* red-500 */
        .severity-high { background-color: #f97316; } /* orange-500 */
        .severity-medium { background-color: #eab308; } /* yellow-500 */
        .severity-low { background-color: #3b82f6; } /* blue-500 */
        .severity-info { background-color: #6b7280; } /* gray-500 */
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
    </style>
</head>
<body class="bg-gray-100 text-gray-800 p-8">
    <div class="max-w-5xl mx-auto">
        <!-- Header -->
        <header class="bg-white p-6 rounded-lg shadow-sm mb-8 flex justify-between items-center border-t-4 border-blue-600">
            <div>
                <h1 class="text-3xl font-bold text-gray-900 mb-2">S2N Vulnerability Scan Report</h1>
                <p class="text-gray-500">Generated on ${new Date(scan.timestamp).toLocaleString()}</p>
            </div>
            <div class="text-right">
                <div class="text-sm font-semibold text-gray-600">Target</div>
                <div class="text-lg font-bold text-blue-700 break-all">${scan.targetUrl}</div>
                <div class="text-sm text-gray-500 mt-1">Status: ${scan.status.toUpperCase()}</div>
            </div>
        </header>

        <!-- Summary Statistics -->
        <section class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
            <div class="bg-white p-4 rounded-lg shadow-sm border-l-4 border-red-500">
                <div class="text-sm text-gray-500 font-semibold mb-1">Critical & High</div>
                <div class="text-2xl font-bold text-gray-900">
                    ${(scan.summary.severityCounts.CRITICAL || 0) + (scan.summary.severityCounts.HIGH || 0)}
                </div>
            </div>
            <div class="bg-white p-4 rounded-lg shadow-sm border-l-4 border-yellow-500">
                <div class="text-sm text-gray-500 font-semibold mb-1">Medium</div>
                <div class="text-2xl font-bold text-gray-900">${scan.summary.severityCounts.MEDIUM || 0}</div>
            </div>
             <div class="bg-white p-4 rounded-lg shadow-sm border-l-4 border-blue-500">
                <div class="text-sm text-gray-500 font-semibold mb-1">Low & Info</div>
                <div class="text-2xl font-bold text-gray-900">
                     ${(scan.summary.severityCounts.LOW || 0) + (scan.summary.severityCounts.INFO || 0)}
                </div>
            </div>
            <div class="bg-white p-4 rounded-lg shadow-sm border-l-4 border-purple-500">
                <div class="text-sm text-gray-500 font-semibold mb-1">Total Findings</div>
                <div class="text-2xl font-bold text-gray-900">${scan.summary.totalFindings}</div>
            </div>
        </section>

        <!-- Findings List -->
        <section>
            <h2 class="text-2xl font-bold text-gray-800 mb-4 border-b pb-2">Detailed Findings</h2>
            ${scan.findings.length > 0 ? findingsListHtml : '<div class="bg-white p-8 text-center text-gray-500 rounded-lg shadow-sm">No vulnerabilities found. Awesome!</div>'}
        </section>
        
        <footer class="mt-12 text-center text-sm text-gray-500 pb-8">
            <p>S2N Scanner Extension • Automatic Vulnerability Discovery</p>
        </footer>
    </div>
</body>
</html>
    `
}
