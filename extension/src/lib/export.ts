/**
 * S2N Scanner - Report Generate & Export Utility
 */

import type { ScanHistoryItem } from '@/types/scan'
import { generateHtmlReport } from './report-template'

/**
 * 스캔 결과를 JSON 파일로 내보내기
 */
export function exportFindingsToJson(scan: ScanHistoryItem) {
    const dataStr = JSON.stringify(scan, null, 2)
    const blob = new Blob([dataStr], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    
    // 다운로드 트리거
    const a = document.createElement('a')
    a.href = url
    a.download = `s2n_report_${scan.scanId}.json`
    document.body.appendChild(a)
    a.click()
    
    // 정리
    setTimeout(() => {
        document.body.removeChild(a)
        URL.revokeObjectURL(url)
    }, 100)
}

/**
 * 스캔 결과를 HTML 리포트 문서로 내보내기
 */
export function exportFindingsToHtml(scan: ScanHistoryItem) {
    const htmlStr = generateHtmlReport(scan)
    const blob = new Blob([htmlStr], { type: 'text/html' })
    const url = URL.createObjectURL(blob)
    
    // 다운로드 트리거
    const a = document.createElement('a')
    a.href = url
    a.download = `s2n_report_${scan.scanId}.html`
    document.body.appendChild(a)
    a.click()
    
    // 정리
    setTimeout(() => {
        document.body.removeChild(a)
        URL.revokeObjectURL(url)
    }, 100)
}
