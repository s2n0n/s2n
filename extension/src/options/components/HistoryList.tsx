/**
 * S2N Scanner - History List Component
 */

import type { ScanHistoryItem } from '@/types/scan'

interface HistoryListProps {
    history: ScanHistoryItem[]
    onSelectScan: (scan: ScanHistoryItem) => void
    onDelete?: (scanId: string) => void
}

export function HistoryList({ history, onSelectScan, onDelete }: HistoryListProps) {
    if (history.length === 0) {
        return (
            <div className="text-center p-12 text-muted-foreground bg-accent/20 border border-dashed rounded-lg animate-in fade-in">
                <p className="mb-2">저장된 스캔 히스토리가 없습니다.</p>
                <p className="text-sm">테스트 대상 사이트를 팝업에서 스캔하면 여기에 결과가 기록됩니다.</p>
            </div>
        )
    }

    return (
        <div className="space-y-4 animate-in fade-in duration-300">
            {history.map((scan) => {
                const criticalCount = scan.summary.severityCounts.CRITICAL || 0
                const highCount = scan.summary.severityCounts.HIGH || 0
                const issueCount = criticalCount + highCount

                return (
                    <div 
                        key={scan.scanId} 
                        className="bg-card border rounded-lg p-5 shadow-sm hover:shadow-md transition-shadow cursor-pointer flex flex-col md:flex-row gap-4 items-start md:items-center relative group"
                        onClick={() => onSelectScan(scan)}
                    >
                        {/* Status Indicator Bar */}
                        <div className={`absolute left-0 top-0 bottom-0 w-1 rounded-l-lg ${
                            scan.status === 'failed' ? 'bg-red-500' :
                            (issueCount > 0 ? 'bg-orange-500' : 'bg-emerald-500')
                        }`} />

                        <div className="flex-1 min-w-0">
                            <div className="flex items-center space-x-2 text-xs text-muted-foreground mb-1">
                                <span>{new Date(scan.timestamp).toLocaleString()}</span>
                                <span>•</span>
                                <span className={`uppercase font-semibold ${
                                    scan.status === 'failed' ? 'text-red-500' : 
                                    (scan.status === 'completed' ? 'text-emerald-500' : '')
                                }`}>
                                    {scan.status}
                                </span>
                            </div>
                            <h3 className="text-lg font-bold text-card-foreground truncate">{scan.targetUrl}</h3>
                        </div>

                        <div className="flex flex-wrap gap-3 mt-2 md:mt-0 items-center text-sm">
                            <div className="text-center px-4 py-1 border rounded bg-secondary/50">
                                <div className="text-muted-foreground text-[10px] font-bold uppercase">Time</div>
                                <div>{scan.summary.durationSeconds}s</div>
                            </div>
                            <div className="text-center px-4 py-1 border rounded bg-secondary/50">
                                <div className="text-muted-foreground text-[10px] font-bold uppercase">Critical/High</div>
                                <div className={issueCount > 0 ? 'text-red-600 font-bold dark:text-red-400' : ''}>{issueCount}</div>
                            </div>
                            <div className="text-center px-4 py-1 border rounded bg-secondary/50">
                                <div className="text-muted-foreground text-[10px] font-bold uppercase">Total</div>
                                <div className="font-semibold">{scan.summary.totalFindings}</div>
                            </div>
                            
                            {onDelete && (
                                <button
                                    onClick={(e) => {
                                        e.stopPropagation()
                                        onDelete(scan.scanId)
                                    }}
                                    className="md:opacity-0 group-hover:opacity-100 p-2 text-muted-foreground hover:text-red-500 transition-all rounded hover:bg-red-100 dark:hover:bg-red-900/30"
                                    title="히스토리 삭제"
                                    aria-label="Delete scan history"
                                >
                                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 6h18"></path><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"></path><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"></path></svg>
                                </button>
                            )}
                        </div>
                    </div>
                )
            })}
        </div>
    )
}
