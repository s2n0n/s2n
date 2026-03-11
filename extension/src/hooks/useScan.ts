import { useState, useEffect } from 'react'
import { INITIAL_SCAN_STATE } from '@/types/scan'
import type { ScanState } from '@/types/scan'

function deduplicateFindings(state: ScanState): ScanState {
    const seen = new Set<string>()
    const findings = state.findings.filter((f) => {
        const key = f.id ?? `${f.title}__${f.url}__${f.severity}`
        if (seen.has(key)) return false
        seen.add(key)
        return true
    })
    return { ...state, findings }
}

export function useScan() {
    const [state, setState] = useState<ScanState>(INITIAL_SCAN_STATE)

    useEffect(() => {
        chrome.runtime.sendMessage({ type: 'get_scan_state' }, (response: ScanState) => {
            if (response) {
                setState(deduplicateFindings(response))
            }
        })

        const handleMessage = (message: any) => {
            if (message.type === 'state_update') {
                setState(deduplicateFindings(message.state))
            }
        }

        chrome.runtime.onMessage.addListener(handleMessage)
        return () => chrome.runtime.onMessage.removeListener(handleMessage)
    }, [])

    const startScan = (targetUrl: string, plugins: string[]) => {
        // ✅ background 응답 오기 전에 이전 findings 보이는 것 방지
        // 로컬 state를 즉시 초기화
        setState({
            ...INITIAL_SCAN_STATE,
            status: 'validating',
            targetUrl,
            selectedPlugins: plugins,
        })
        chrome.runtime.sendMessage({ type: 'start_scan', payload: { targetUrl, plugins } })
    }

    const stopScan = () => {
        // ✅ 홈으로 돌아갈 때도 즉시 초기화
        setState(INITIAL_SCAN_STATE)
        chrome.runtime.sendMessage({ type: 'stop_scan' })
    }

    return { state, startScan, stopScan }
}