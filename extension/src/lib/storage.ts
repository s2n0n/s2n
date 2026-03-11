/**
 * S2N Scanner - Local Storage Utility
 */

import type { ScanHistoryItem } from '@/types/scan'

const STORAGE_KEY = 's2n_scan_history'

/**
 * 히스토리 전체 로드
 */
export async function getScanHistory(): Promise<ScanHistoryItem[]> {
    return new Promise((resolve) => {
        chrome.storage.local.get([STORAGE_KEY], (result) => {
            const history = result[STORAGE_KEY]
            resolve(Array.isArray(history) ? history : [])
        })
    })
}

/**
 * 새로운 스캔 결과를 히스토리에 추가
 * 최신순 정렬을 위해 배열 앞에 추가 (unshift)
 */
export async function saveScanHistory(item: ScanHistoryItem): Promise<void> {
    const history = await getScanHistory()
    history.unshift(item)
    return new Promise((resolve) => {
        chrome.storage.local.set({ [STORAGE_KEY]: history }, () => resolve())
    })
}

/**
 * 히스토리 중 특정 항목만 삭제
 */
export async function deleteScanHistoryItem(scanId: string): Promise<void> {
    const history = await getScanHistory()
    const newHistory = history.filter(item => item.scanId !== scanId)
    return new Promise((resolve) => {
        chrome.storage.local.set({ [STORAGE_KEY]: newHistory }, () => resolve())
    })
}

/**
 * 전체 히스토리 삭제
 */
export async function clearScanHistory(): Promise<void> {
    return new Promise((resolve) => {
        chrome.storage.local.remove([STORAGE_KEY], () => resolve())
    })
}
