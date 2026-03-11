import { useState, useEffect } from 'react'
import type { FormEvent } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Checkbox } from '@/components/ui/checkbox'
import { Progress } from '@/components/ui/progress'
import { Badge } from '@/components/ui/badge'
import { Label } from '@/components/ui/label'
import { ScrollArea } from '@/components/ui/scroll-area'
import { useScan } from '@/hooks/useScan'
import { AVAILABLE_PLUGINS } from '@/types/scan'
import type { Severity } from '@/types/scan'
import { Play, Square, Loader2, AlertTriangle, Shield, CheckCircle2, X } from 'lucide-react'

// Severity 뱃지 컬러 맵핑
const severityColors: Record<Severity, string> = {
    CRITICAL: 'bg-red-500/10 text-red-500 border-red-500/20',
    HIGH: 'bg-orange-500/10 text-orange-500 border-orange-500/20',
    MEDIUM: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
    LOW: 'bg-blue-500/10 text-blue-500 border-blue-500/20',
    INFO: 'bg-zinc-500/10 text-zinc-500 border-zinc-500/20',
}

export function PopupApp() {
    const { state, startScan, stopScan } = useScan()
    const [url, setUrl] = useState('')
    const [selectedPlugins, setSelectedPlugins] = useState<string[]>(AVAILABLE_PLUGINS.map(p => p.id))
    const [isDarkMode, setIsDarkMode] = useState(
        window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)').matches : false
    )

    const isScanning = state.status === 'validating' || state.status === 'scanning'
    const isCompleted = state.status === 'completed'

    // 현재 탭 액티브 시 URL 자동 할당 및 시스템 테마 변경에 따른 로고 전환
    useEffect(() => {
        if (!url && chrome?.tabs) {
            chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                const currentTabUrl = tabs[0]?.url
                if (currentTabUrl && currentTabUrl.startsWith('http')) {
                    setUrl(currentTabUrl)
                }
            })
        }
        
        if (window.matchMedia) {
            const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)')
            const handler = (e: MediaQueryListEvent) => setIsDarkMode(e.matches)
            mediaQuery.addEventListener('change', handler)
            return () => mediaQuery.removeEventListener('change', handler)
        }
    }, [])

    const handleStart = (e: FormEvent) => {
        e.preventDefault()
        if (!url) return
        startScan(url, selectedPlugins)
    }

    const togglePlugin = (pluginId: string) => {
        setSelectedPlugins((prev) =>
            prev.includes(pluginId) ? prev.filter((id) => id !== pluginId) : [...prev, pluginId]
        )
    }

    return (
        <div className="flex flex-col w-[420px] h-[540px] bg-background text-foreground overflow-hidden font-sans border border-border shadow-2xl relative">
            
            {/* Background Glow Effect */}
            <div className="absolute top-[-50px] left-[-50px] w-[200px] h-[200px] bg-primary/10 rounded-full blur-[80px] pointer-events-none" />
            <div className="absolute bottom-[-50px] right-[-50px] w-[200px] h-[200px] bg-blue-500/10 rounded-full blur-[80px] pointer-events-none" />

            {/* Header */}
            <header className="flex items-center gap-3 px-5 py-4 border-b border-border bg-card/60 backdrop-blur-md z-10 sticky top-0">
                <div className="flex-shrink-0 w-9 h-9 flex items-center justify-center bg-primary/5 rounded-xl border border-primary/20 shadow-sm relative overflow-hidden group">
                    <div className="absolute inset-0 bg-gradient-to-tr from-primary/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
                    {/* JS 기반 OS 테마 감지 로고 교체 (Tailwind의 dark: 클래스 충돌 방지) */}
                    <img src={isDarkMode ? "icons/logo1.png" : "icons/logo2.png"} alt="S2N Logo" className="w-5 h-5 object-contain" />
                </div>
                <div>
                    <h1 className="text-sm font-semibold tracking-tight text-foreground/90">S2N Security</h1>
                    <div className="flex items-center gap-1.5 mt-0.5">
                        <span className="relative flex h-2 w-2">
                          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                          <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500"></span>
                        </span>
                        <p className="text-[10px] text-muted-foreground font-medium">Native Engine</p>
                    </div>
                </div>
                {state.status === 'idle' && (
                    <Badge variant="secondary" className="ml-auto text-[10px] uppercase font-semibold bg-background border border-border">
                        Ready
                    </Badge>
                )}
                {isScanning && (
                    <Badge variant="default" className="ml-auto text-[10px] uppercase flex items-center gap-1 shadow-sm">
                        <Loader2 className="w-3 h-3 animate-spin" /> Scanning
                    </Badge>
                )}
            </header>

            {/* Main Content Area */}
            <ScrollArea className="flex-1 px-5 py-4 z-10">
                
                {state.error && (
                    <div className="mb-5 p-3.5 text-xs bg-red-500/10 border border-red-500/20 text-red-600 dark:text-red-400 rounded-xl flex items-start justify-between gap-2.5 shadow-sm animate-in slide-in-from-top-2">
                        <div className="flex items-start gap-2.5">
                            <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                            <span className="leading-snug">{state.error}</span>
                        </div>
                        <button type="button" onClick={stopScan} className="text-red-500/60 hover:text-red-500 transition-colors">
                            <X className="w-4 h-4" />
                        </button>
                    </div>
                )}

                {/* --- 스캔 대기 상태 (idle, failed) --- */}
                {(!isScanning && !isCompleted) && (
                    <form onSubmit={handleStart} className="space-y-6 flex flex-col h-full animate-in fade-in duration-500">
                        <div className="space-y-2.5">
                            <Label htmlFor="targetUrl" className="text-xs font-semibold text-foreground/80">Target URL</Label>
                            <Input
                                id="targetUrl"
                                type="url"
                                placeholder="https://example.com"
                                value={url}
                                onChange={(e) => setUrl(e.target.value)}
                                className="h-10 text-sm bg-background border-border/60 hover:border-border transition-colors focus-visible:ring-1 focus-visible:ring-primary/50 shadow-sm rounded-lg"
                                required
                            />
                        </div>

                        <div className="space-y-3 flex-1">
                            <div className="flex items-center justify-between px-0.5">
                                <Label className="text-xs font-semibold text-foreground/80">Scan Configuration</Label>
                                <div className="flex items-center gap-2">
                                    <button
                                        type="button"
                                        onClick={() => setSelectedPlugins(selectedPlugins.length === AVAILABLE_PLUGINS.length ? [] : AVAILABLE_PLUGINS.map(p => p.id))}
                                        className="text-[10px] text-primary/80 hover:text-primary transition-colors font-medium cursor-pointer"
                                    >
                                        {selectedPlugins.length === AVAILABLE_PLUGINS.length ? 'Deselect All' : 'Select All'}
                                    </button>
                                    <Badge variant="secondary" className="px-1.5 py-0 h-4 text-[9px] bg-muted/50">{selectedPlugins.length}</Badge>
                                </div>
                            </div>
                            
                            <div className="grid grid-cols-2 gap-2">
                                {AVAILABLE_PLUGINS.map((plugin) => (
                                    <Label
                                        key={plugin.id}
                                        htmlFor={`plugin-${plugin.id}`}
                                        className={`
                                            flex items-center space-x-2.5 p-3 rounded-xl border transition-all cursor-pointer select-none
                                            ${selectedPlugins.includes(plugin.id) 
                                                ? 'bg-primary/5 border-primary/30 shadow-sm' 
                                                : 'bg-background hover:bg-muted/30 border-border/50 hover:border-border'}
                                        `}
                                        title={plugin.description}
                                    >
                                        <Checkbox
                                            id={`plugin-${plugin.id}`}
                                            checked={selectedPlugins.includes(plugin.id)}
                                            onCheckedChange={() => togglePlugin(plugin.id)}
                                            className="rounded-md"
                                        />
                                        <div className="flex flex-col gap-0.5">
                                            <span className="text-xs font-semibold">{plugin.name}</span>
                                        </div>
                                    </Label>
                                ))}
                            </div>
                        </div>

                        <div className="pt-2 pb-1">
                            <Button 
                                type="submit" 
                                size="lg"
                                className="w-full gap-2 rounded-xl font-semibold shadow-md hover:shadow-lg transition-all"
                                disabled={!url || selectedPlugins.length === 0}
                            >
                                <Play className="w-4 h-4 fill-current" /> Initialize Scan
                            </Button>
                        </div>
                    </form>
                )}

                {/* --- 스캔 진행 중 (scanning, validating) --- */}
                {isScanning && (
                    <div className="space-y-5 animate-in fade-in zoom-in-[0.98] duration-400">
                        <div className="p-4 border border-border/60 rounded-xl bg-card/50 backdrop-blur-sm shadow-sm space-y-4 relative overflow-hidden">
                            <div className="absolute top-0 left-0 w-1/2 h-[1px] bg-gradient-to-r from-transparent via-primary/50 to-transparent" />
                            
                            <div className="flex justify-between items-end">
                                <div className="space-y-1.5">
                                    <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-widest">Target Engine</p>
                                    <div className="flex items-center gap-1.5">
                                        <div className="w-1.5 h-1.5 rounded-full bg-blue-500 animate-pulse" />
                                        <p className="text-sm font-semibold truncate max-w-[180px] text-foreground/90">{state.targetUrl}</p>
                                    </div>
                                </div>
                                <div className="text-right space-y-1">
                                    <p className="text-2xl font-bold text-primary tabular-nums tracking-tight">
                                        {Math.round(state.progress?.percent || 0)}<span className="text-sm text-primary/60 ml-0.5">%</span>
                                    </p>
                                </div>
                            </div>
                            
                            <Progress value={state.progress?.percent || 0} className="h-2 rounded-full bg-primary/10 overflow-hidden" />
                            
                            <p className="text-xs text-muted-foreground/80 flex items-center gap-2">
                                <Loader2 className="w-3 h-3 animate-spin text-muted-foreground" />
                                <span className="truncate">{state.progress?.message || 'Warming up scanner subsystem...'}</span>
                            </p>
                        </div>

                        <div className="space-y-3">
                            <div className="flex items-center justify-between px-1">
                                <h3 className="text-xs font-semibold text-foreground/80">Real-time Telemetry</h3>
                                {state.findings.length > 0 && (
                                    <span className="text-[10px] text-muted-foreground animate-pulse">Live</span>
                                )}
                            </div>
                            
                            <div className="space-y-2">
                                {state.findings.length === 0 ? (
                                    <div className="flex flex-col items-center justify-center py-8 text-muted-foreground border border-dashed border-border/60 rounded-xl bg-background/50">
                                        <Shield className="w-8 h-8 opacity-20 mb-3 stroke-1" />
                                        <p className="text-xs font-medium">Monitoring system traffic...</p>
                                        <p className="text-[10px] opacity-60 mt-1">No vulnerabilities detected yet.</p>
                                    </div>
                                ) : (
                                    <div className="flex flex-col gap-2">
                                        {state.findings.slice().reverse().slice(0, 5).map((finding, idx) => (
                                            <div key={idx} className="flex flex-col gap-1.5 p-3 rounded-lg border border-border/50 bg-card hover:bg-muted/20 transition-colors shadow-sm text-xs animate-in slide-in-from-right-4">
                                                <div className="flex items-center justify-between">
                                                    <Badge variant="outline" className={`text-[9px] px-1.5 py-0 h-4 border uppercase tracking-wider font-bold ${severityColors[finding.severity] || severityColors.INFO}`}>
                                                        {finding.severity}
                                                    </Badge>
                                                    <span className="text-[10px] font-medium text-muted-foreground bg-muted/50 px-1.5 rounded">{finding.plugin}</span>
                                                </div>
                                                <p className="font-medium text-foreground/90 truncate pr-2">{finding.title}</p>
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>
                        </div>

                        <div className="pt-2">
                            <Button 
                                variant="outline" 
                                className="w-full gap-2 rounded-xl text-muted-foreground hover:text-red-500 hover:border-red-500/30 hover:bg-red-500/5 transition-all" 
                                onClick={stopScan}
                            >
                                <Square className="w-3.5 h-3.5" /> Terminate Operation
                            </Button>
                        </div>
                    </div>
                )}

                {/* --- 스캔 완료 (completed) --- */}
                {isCompleted && (
                    <div className="space-y-6 animate-in slide-in-from-bottom-4 duration-500 pb-2">
                        <div className="text-center py-6 space-y-3 relative">
                            <div className="absolute inset-0 bg-green-500/5 rounded-3xl blur-xl" />
                            <div className="w-16 h-16 bg-green-500/10 text-green-500 rounded-full flex items-center justify-center mx-auto mb-4 relative shadow-inner border border-green-500/20">
                                <CheckCircle2 className="w-8 h-8" />
                            </div>
                            <h2 className="text-xl font-bold tracking-tight">Scan Completed</h2>
                            <p className="text-xs text-muted-foreground truncate px-4 max-w-[300px] mx-auto bg-muted/30 py-1 rounded-full">{state.targetUrl}</p>
                        </div>

                        <div className="grid grid-cols-2 gap-3">
                            <div className="p-4 border rounded-xl border-border/60 bg-card text-center space-y-1.5 shadow-sm hover:shadow-md transition-shadow">
                                <p className="text-[10px] text-muted-foreground font-semibold uppercase tracking-wider">Total Findings</p>
                                <p className={`text-3xl font-extrabold ${state.summary?.totalFindings ? 'text-red-500' : 'text-foreground'}`}>
                                    {state.summary?.totalFindings || 0}
                                </p>
                            </div>
                            <div className="p-4 border rounded-xl border-border/60 bg-card text-center space-y-1.5 shadow-sm hover:shadow-md transition-shadow">
                                <p className="text-[10px] text-muted-foreground font-semibold uppercase tracking-wider">Duration</p>
                                <p className="text-3xl font-extrabold tracking-tight">
                                    {state.summary?.durationSeconds.toFixed(1)}<span className="text-sm text-muted-foreground ml-1">sec</span>
                                </p>
                            </div>
                        </div>

                        <div className="space-y-3 p-4 border border-border/50 rounded-xl bg-muted/10">
                            <h3 className="text-xs font-semibold text-foreground/80">Severity Breakdown</h3>
                            <div className="flex flex-wrap gap-2">
                                {Object.entries(state.summary?.severityCounts || {}).map(([sev, count]) => {
                                    if (count === 0) return null;
                                    const s = sev as Severity;
                                    const colorMap = {
                                        CRITICAL: 'bg-red-500 text-white border-red-600',
                                        HIGH: 'bg-orange-500 text-white border-orange-600',
                                        MEDIUM: 'bg-yellow-500 text-white border-yellow-600',
                                        LOW: 'bg-blue-500 text-white border-blue-600',
                                        INFO: 'bg-zinc-400 text-white border-zinc-500'
                                    }
                                    return (
                                        <Badge key={sev} variant="outline" className={`flex gap-1.5 py-1 px-2.5 rounded-lg shadow-sm font-medium ${colorMap[s] || colorMap.INFO}`}>
                                            <span className="text-[10px]">{sev}</span>
                                            <span className="text-[10px] bg-black/20 px-1.5 py-0.5 rounded-md min-w-[20px] text-center">{count}</span>
                                        </Badge>
                                    )
                                })}
                                {Object.values(state.summary?.severityCounts || {}).every(c => c === 0) && (
                                    <p className="text-xs text-muted-foreground w-full text-center py-2">System is secure.</p>
                                )}
                            </div>
                        </div>

                        <div className="pt-2">
                            <Button 
                                variant="default"
                                size="lg"
                                className="w-full rounded-xl font-bold shadow-md"
                                onClick={() => window.location.reload()}
                            >
                                Initiate New Scan
                            </Button>
                        </div>
                    </div>
                )}

            </ScrollArea>
        </div>
    )
}
