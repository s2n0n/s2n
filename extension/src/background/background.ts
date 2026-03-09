/**
 * S2N Scanner - Background Service Worker
 *
 * Chrome Extension의 백그라운드에서 실행되며,
 * Popup/Options UI와 Native Messaging Host(native_host.py) 사이의
 * 메시지 브릿지 역할을 담당합니다.
 */

const NATIVE_HOST_NAME = 'com.s2n.scanner'

// Popup/Options로부터 메시지 수신
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message.type === 'ping') {
        // 핑퐁 테스트: Native Host 연결 확인
        try {
            chrome.runtime.sendNativeMessage(
                NATIVE_HOST_NAME,
                { action: 'ping' },
                (response) => {
                    if (chrome.runtime.lastError) {
                        sendResponse({
                            success: false,
                            error: chrome.runtime.lastError.message,
                        })
                    } else {
                        sendResponse({ success: true, data: response })
                    }
                },
            )
        } catch (err) {
            sendResponse({
                success: false,
                error: err instanceof Error ? err.message : 'Unknown error',
            })
        }
        return true // 비동기 응답을 위해 true 반환
    }

    return false
})

console.log('[S2N] Background service worker loaded.')
