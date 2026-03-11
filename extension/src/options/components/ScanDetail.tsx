/**
 * S2N Scanner - Scan Detail Component
 */

import { useState, useMemo } from 'react'
import type { ScanHistoryItem } from '@/types/scan'
import { FindingTable } from './FindingTable'
import { exportFindingsToJson, exportFindingsToHtml } from '@/lib/export'

interface ScanDetailProps {
    scan: ScanHistoryItem
    onBack: () => void
}

export function ScanDetail({ scan, onBack }: ScanDetailProps) {
    const [searchQuery, setSearchQuery] = useState('')
    const [severityFilter, setSeverityFilter] = useState<string>('ALL')

    const filteredFindings = useMemo(() => {
        return scan.findings.filter(f => {
            const matchesSearch = 
                (f.title.toLowerCase().includes(searchQuery.toLowerCase())) ||
                (f.url?.toLowerCase().includes(searchQuery.toLowerCase())) ||
                (f.description.toLowerCase().includes(searchQuery.toLowerCase()))
                
            const matchesSeverity = severityFilter === 'ALL' || f.severity === severityFilter

            return matchesSearch && matchesSeverity
        })
    }, [scan.findings, searchQuery, severityFilter])

    const totalFindings = scan.findings.length
    const criticalHighCount = (scan.summary.severityCounts.CRITICAL || 0) + (scan.summary.severityCounts.HIGH || 0)
    const mediumCount = scan.summary.severityCounts.MEDIUM || 0
    const lowInfoCount = (scan.summary.severityCounts.LOW || 0) + (scan.summary.severityCounts.INFO || 0)

    return (
        <div className="space-y-6 animate-in fade-in zoom-in-95 duration-200">
            {/* Header Controls */}
            <div className="flex items-center justify-between">
                <button 
                    onClick={onBack}
                    className="text-sm font-medium text-muted-foreground hover:text-foreground flex items-center transition-colors"
                >
                    <span className="mr-1">←</span> 뒤로 가기
                </button>

                <div className="flex space-x-2">
                    <button 
                        onClick={() => exportFindingsToJson(scan)}
                        className="px-3 py-1.5 text-xs font-semibold bg-secondary text-secondary-foreground rounded shadow-sm hover:bg-secondary/80 transition-colors border"
                    >
                        JSON 내보내기
                    </button>
                    <button 
                        onClick={() => exportFindingsToHtml(scan)}
                        className="px-3 py-1.5 text-xs font-semibold bg-primary text-primary-foreground rounded shadow-sm hover:bg-primary/90 transition-colors"
                    >
                        HTML 리포트 다운로드
                    </button>
                </div>
            </div>

            {/* Scan Info Card */}
            <div className="bg-card border rounded-lg p-6 shadow-sm">
                <div className="mb-4">
                    <div className="flex items-center space-x-2 text-sm text-muted-foreground mb-1">
                        <span>{new Date(scan.timestamp).toLocaleString()}</span>
                        <span>•</span>
                        <span className="uppercase font-semibold text-foreground">{scan.status}</span>
                    </div>
                    <h2 className="text-2xl font-bold break-all text-secondary-foreground">{scan.targetUrl}</h2>
                </div>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-4 border-t">
                    <div className="pt-2 border-t-4 border-red-500 rounded-sm">
                        <div className="text-xs text-muted-foreground font-semibold">CRITICAL & HIGH</div>
                        <div className="text-2xl font-bold">{criticalHighCount}</div>
                    </div>
                    <div className="pt-2 border-t-4 border-yellow-500 rounded-sm">
                        <div className="text-xs text-muted-foreground font-semibold">MEDIUM</div>
                        <div className="text-2xl font-bold">{mediumCount}</div>
                    </div>
                    <div className="pt-2 border-t-4 border-blue-500 rounded-sm">
                        <div className="text-xs text-muted-foreground font-semibold">LOW & INFO</div>
                        <div className="text-2xl font-bold">{lowInfoCount}</div>
                    </div>
                    <div className="pt-2 border-t-4 border-purple-500 rounded-sm">
                        <div className="text-xs text-muted-foreground font-semibold">TOTAL FINDINGS</div>
                        <div className="text-2xl font-bold">{totalFindings}</div>
                    </div>
                </div>
            </div>

            {/* Filtering */}
            <div className="bg-card border rounded-lg p-4 shadow-sm flex flex-col md:flex-row gap-4 items-center">
                <div className="flex-1 w-full">
                    <input 
                        type="text" 
                        placeholder="이름, URL, 설명 검색..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        className="w-full px-3 py-2 border rounded-md bg-background text-sm focus:outline-none focus:ring-1 focus:ring-primary"
                    />
                </div>
                <div className="w-full md:w-64">
                    <select 
                        value={severityFilter}
                        onChange={(e) => setSeverityFilter(e.target.value)}
                        className="w-full px-3 py-2 border rounded-md bg-background text-sm focus:outline-none focus:ring-1 focus:ring-primary"
                    >
                        <option value="ALL">모든 위험도 (All)</option>
                        <option value="CRITICAL">CRITICAL</option>
                        <option value="HIGH">HIGH</option>
                        <option value="MEDIUM">MEDIUM</option>
                        <option value="LOW">LOW</option>
                        <option value="INFO">INFO</option>
                    </select>
                </div>
            </div>

            {/* Findings Table */}
            <FindingTable findings={filteredFindings} />
        </div>
    )
}
