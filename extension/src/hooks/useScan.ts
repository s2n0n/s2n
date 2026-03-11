import { useState, useEffect } from 'react'
import { INITIAL_SCAN_STATE } from '@/types/scan'
import type { ScanState } from '@/types/scan'

export function useScan() {
    const [state, setState] = useState<ScanState>(INITIAL_SCAN_STATE)

    useEffect(() => {
        // 1. 최초 로드 시 background에 현재 상태 요청
        chrome.runtime.sendMessage({ type: 'get_scan_state' }, (response: ScanState) => {
            if (response) {
                setState(response)
            }
        })

        // 2. background로부터 상태 업데이트 브로드캐스트 수신
        const handleMessage = (message: any) => {
            if (message.type === 'state_update') {
                setState(message.state)
            }
        }

        chrome.runtime.onMessage.addListener(handleMessage)

        return () => {
            chrome.runtime.onMessage.removeListener(handleMessage)
        }
    }, [])

    const startScan = (targetUrl: string, plugins: string[]) => {
        chrome.runtime.sendMessage({
            type: 'start_scan',
            payload: { targetUrl, plugins },
        })
    }

    const stopScan = () => {
        chrome.runtime.sendMessage({ type: 'stop_scan' })
    }

    return {
        state,
        startScan,
        stopScan,
    }
}
