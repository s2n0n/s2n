/**
 * S2N Scanner - Background Service Worker
 *
 * Chrome Extension의 백그라운드에서 실행되며,
 * Popup/Options UI와 Native Messaging Host(native_host.py) 사이의
 * 메시지 브릿지 및 스캔 로직 오케스트레이션을 담당합니다.
 */

import { sendNativeMessage, connectNative, disconnectNative } from '@/lib/nativeMessaging'
import { INITIAL_SCAN_STATE } from '@/types/scan'
import type { ScanState, Finding, ProgressInfo, ScanSummary } from '@/types/scan'
import { saveScanHistory } from '@/lib/storage'

// ============================================================================
// 전역 상태 (Global State)
// ============================================================================

// 팝업이 닫혀도 스캔 상태를 유지하기 위해 Service Worker의 전역 변수로 관리합니다.
let currentScanState: ScanState = { ...INITIAL_SCAN_STATE }
let nativePort: chrome.runtime.Port | null = null

// 상태 변경을 팝업이나 기타 뷰로 브로드캐스트
function broadcastStateUpdate() {
    chrome.runtime.sendMessage({
        type: 'state_update',
        state: currentScanState,
    }).catch(() => {
        // 팝업이 닫혀 있어서 메시지를 받을 수 없는 상황은 정상입니다.
    })
}


// ============================================================================
// Native Port 콜백 처리
// ============================================================================

function handleNativeMessage(response: any) {
    if (response.status === 'error') {
        console.error('[Background] Native host error:', response.error)
        currentScanState.status = 'failed'
        currentScanState.error = response.error || 'Unknown error from native host'
        broadcastStateUpdate()
        return
    }

    const { action, data } = response

    switch (action) {
        case 'scan_started':
            currentScanState.status = 'scanning'
            currentScanState.error = null
            currentScanState.progress = { current: 0, total: 100, percent: 0, message: 'Initializing scan...' }
            broadcastStateUpdate()
            break

        case 'scan_progress':
            const progressInfo = data as ProgressInfo
            currentScanState.progress = progressInfo
            broadcastStateUpdate()
            break

        case 'scan_finding':
            const finding = data as Finding
            currentScanState.findings.push(finding)
            broadcastStateUpdate()
            break

        case 'scan_completed':
            currentScanState.status = 'completed'
            currentScanState.summary = data.summary as ScanSummary
            // 스캔 완료 시점의 마지막 진행률 100% 보장
            if (currentScanState.progress) {
                currentScanState.progress.percent = 100
                currentScanState.progress.message = 'Scan completed'
            }
            broadcastStateUpdate()
            disconnectNative(nativePort)
            nativePort = null

            // 히스토리에 자동 저장
            const historyItem = {
                scanId: `scan_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`,
                targetUrl: currentScanState.targetUrl,
                timestamp: new Date().toISOString(),
                status: currentScanState.status,
                summary: currentScanState.summary!,
                findings: currentScanState.findings
            }
            saveScanHistory(historyItem).catch((err) => {
                console.error('[Background] Failed to save scan history:', err)
            })
            break

        case 'scan_failed':
        case 'scan_stopped':
            currentScanState.status = 'failed'
            currentScanState.error = data?.error || 'Scan stopped'
            broadcastStateUpdate()
            disconnectNative(nativePort)
            nativePort = null
            break
            
        case 'pong':
        case 'version':
            // start/stop 외의 단발성 메시지는 sendNativeMessage를 통해 처리되므로 무시
            break

        default:
            console.warn('[Background] Unknown action from native host:', action)
    }
}

function handleNativeDisconnect(error?: string) {
    console.warn('[Background] Native port disconnected. Error:', error)
    if (currentScanState.status === 'scanning' || currentScanState.status === 'validating') {
        currentScanState.status = 'failed'
        currentScanState.error = error || 'Lost connection to native host during scan.'
        broadcastStateUpdate()
    }
    nativePort = null
}


// ============================================================================
// Popup/Options ↔ Background 메시지 핸들러
// ============================================================================

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    
    // 1. 단발성 테스트/설정 기능
    if (message.type === 'ping') {
        sendNativeMessage({ action: 'ping' })
            .then((response) => sendResponse({ success: true, data: response }))
            .catch((err) => sendResponse({ success: false, error: err instanceof Error ? err.message : 'Unknown error' }))
        return true
    }

    if (message.type === 'get_version') {
        sendNativeMessage({ action: 'get_version' })
            .then((response) => sendResponse({ success: true, data: response }))
            .catch((err) => sendResponse({ success: false, error: err instanceof Error ? err.message : 'Unknown error' }))
        return true
    }

    // 2. 스캔 상태 동기화
    if (message.type === 'get_scan_state') {
        sendResponse(currentScanState)
        return false // 동기 응답
    }

    // 3. 스캔 제어
    if (message.type === 'start_scan') {
        if (currentScanState.status === 'scanning') {
            sendResponse({ success: false, error: 'Scan already in progress' })
            return false
        }

        const { targetUrl, plugins } = message.payload

        // 상태 초기화
        currentScanState = {
            ...INITIAL_SCAN_STATE,
            status: 'validating',
            targetUrl,
            selectedPlugins: plugins,
        }
        broadcastStateUpdate()

        // Native Port 생성
        if (nativePort) disconnectNative(nativePort)
        nativePort = connectNative({
            onMessage: handleNativeMessage,
            onDisconnect: handleNativeDisconnect,
        })
        
        // 스캔 시작 요청 전송
        nativePort.postMessage({
            action: 'start_scan',
            data: { target_url: targetUrl, plugins },
        })

        sendResponse({ success: true })
        return false
    }

    if (message.type === 'stop_scan') {
        if (nativePort) {
            nativePort.postMessage({ action: 'stop_scan' })
        }
        currentScanState.status = 'idle'
        currentScanState.progress = null
        broadcastStateUpdate()
        sendResponse({ success: true })
        return false
    }

    return false
})

console.log('[S2N] Background service worker loaded.')
