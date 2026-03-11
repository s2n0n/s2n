import { useState } from 'react'
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
import { ShieldAlert, ShieldCheck, Play, Square, Loader2, AlertTriangle } from 'lucide-react'

// Severity 뱃지 컬러 맵핑
const severityColors: Record<Severity, string> = {
    CRITICAL: 'bg-red-600 hover:bg-red-700 text-white',
    HIGH: 'bg-orange-500 hover:bg-orange-600 text-white',
    MEDIUM: 'bg-yellow-500 hover:bg-yellow-600 text-white',
    LOW: 'bg-blue-500 hover:bg-blue-600 text-white',
    INFO: 'bg-gray-400 hover:bg-gray-500 text-white',
}

export function PopupApp() {
    const { state, startScan, stopScan } = useScan()
    const [url, setUrl] = useState('')
    const [selectedPlugins, setSelectedPlugins] = useState<string[]>(AVAILABLE_PLUGINS.map(p => p.id))

    const isScanning = state.status === 'validating' || state.status === 'scanning'
    const isCompleted = state.status === 'completed'

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
        <div className="flex flex-col w-[400px] h-[580px] bg-background text-foreground overflow-hidden">
            {/* Header */}
            <header className="flex items-center gap-2 p-4 border-b border-border bg-card">
                <div className="p-2 bg-primary/10 rounded-full">
                    <ShieldAlert className="w-5 h-5 text-primary" />
                </div>
                <div>
                    <h1 className="text-sm font-bold tracking-tight">S2N Security Scanner</h1>
                    <p className="text-[10px] text-muted-foreground">Native Engine connected</p>
                </div>
                {state.status === 'idle' && (
                    <Badge variant="outline" className="ml-auto text-[10px] uppercase border-green-500/30 text-green-500">
                        Ready
                    </Badge>
                )}
                {isScanning && (
                    <Badge variant="outline" className="ml-auto text-[10px] uppercase border-blue-500/30 text-blue-500 flex items-center gap-1">
                        <Loader2 className="w-3 h-3 animate-spin" /> Scanning
                    </Badge>
                )}
            </header>

            {/* Main Content Area */}
            <ScrollArea className="flex-1 p-4">
                
                {state.error && (
                    <div className="mb-4 p-3 text-xs bg-red-500/10 border border-red-500/20 text-red-600 rounded-md flex items-start gap-2">
                        <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                        <span>{state.error}</span>
                    </div>
                )}

                {/* --- 스캔 대기 상태 (idle, failed) --- */}
                {(!isScanning && !isCompleted) && (
                    <form onSubmit={handleStart} className="space-y-6">
                        <div className="space-y-2">
                            <Label htmlFor="targetUrl" className="text-xs font-semibold">Target URL</Label>
                            <Input
                                id="targetUrl"
                                type="url"
                                placeholder="https://example.com"
                                value={url}
                                onChange={(e) => setUrl(e.target.value)}
                                className="h-9 text-sm focus-visible:ring-primary"
                                required
                            />
                        </div>

                        <div className="space-y-3">
                            <div className="flex items-center justify-between">
                                <Label className="text-xs font-semibold">Scan Plugins</Label>
                                <span className="text-[10px] text-muted-foreground">{selectedPlugins.length} selected</span>
                            </div>
                            <div className="grid grid-cols-2 gap-2 bg-muted/40 p-3 rounded-md border border-border">
                                {AVAILABLE_PLUGINS.map((plugin) => (
                                    <div key={plugin.id} className="flex items-center space-x-2">
                                        <Checkbox
                                            id={`plugin-${plugin.id}`}
                                            checked={selectedPlugins.includes(plugin.id)}
                                            onCheckedChange={() => togglePlugin(plugin.id)}
                                        />
                                        <Label
                                            htmlFor={`plugin-${plugin.id}`}
                                            className="text-xs font-medium leading-none cursor-pointer"
                                            title={plugin.description}
                                        >
                                            {plugin.name}
                                        </Label>
                                    </div>
                                ))}
                            </div>
                        </div>

                        <Button 
                            type="submit" 
                            className="w-full gap-2 transition-all"
                            disabled={!url || selectedPlugins.length === 0}
                        >
                            <Play className="w-4 h-4" /> Start Scan
                        </Button>
                    </form>
                )}

                {/* --- 스캔 진행 중 (scanning, validating) --- */}
                {isScanning && (
                    <div className="space-y-6 animate-in fade-in zoom-in-95 duration-300">
                        <div className="p-4 border border-border rounded-lg bg-card shadow-sm space-y-4">
                            <div className="flex justify-between items-end">
                                <div className="space-y-1">
                                    <p className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider">Target</p>
                                    <p className="text-sm font-semibold truncate max-w-[200px]" title={state.targetUrl}>{state.targetUrl}</p>
                                </div>
                                <div className="text-right space-y-1">
                                    <p className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider">Progress</p>
                                    <p className="text-sm font-bold text-primary">{Math.round(state.progress?.percent || 0)}%</p>
                                </div>
                            </div>
                            
                            <Progress value={state.progress?.percent || 0} className="h-2" />
                            
                            <p className="text-xs text-muted-foreground text-center truncate">
                                {state.progress?.message || 'Warming up scanner...'}
                            </p>
                        </div>

                        <div className="space-y-3">
                            <h3 className="text-xs font-semibold flex items-center justify-between border-b pb-2">
                                <span>Real-time Findings</span>
                                <Badge variant="secondary" className="px-1.5 min-w-[20px] justify-center">{state.findings.length}</Badge>
                            </h3>
                            
                            <div className="space-y-2">
                                {state.findings.length === 0 ? (
                                    <div className="flex flex-col items-center justify-center py-6 text-muted-foreground">
                                        <ShieldCheck className="w-8 h-8 opacity-20 mb-2" />
                                        <p className="text-xs">No vulnerabilities found yet</p>
                                    </div>
                                ) : (
                                    state.findings.slice().reverse().slice(0, 5).map((finding, idx) => (
                                        <div key={idx} className="flex flex-col gap-1 p-2.5 rounded border border-border bg-card shadow-sm text-xs">
                                            <div className="flex items-center justify-between">
                                                <Badge className={`text-[10px] px-1 py-0 h-4 ${severityColors[finding.severity] || severityColors.INFO}`}>
                                                    {finding.severity}
                                                </Badge>
                                                <span className="text-[10px] text-muted-foreground">{finding.plugin}</span>
                                            </div>
                                            <p className="font-medium truncate">{finding.title}</p>
                                        </div>
                                    ))
                                )}
                            </div>
                        </div>

                        <Button 
                            variant="destructive" 
                            className="w-full gap-2" 
                            onClick={stopScan}
                        >
                            <Square className="w-4 h-4" /> Stop Scan
                        </Button>
                    </div>
                )}

                {/* --- 스캔 완료 (completed) --- */}
                {isCompleted && (
                    <div className="space-y-6 animate-in slide-in-from-bottom-2 duration-400">
                        <div className="text-center py-4 space-y-2">
                            <div className="w-12 h-12 bg-green-500/10 text-green-500 rounded-full flex items-center justify-center mx-auto mb-3">
                                <ShieldCheck className="w-6 h-6" />
                            </div>
                            <h2 className="text-lg font-bold">Scan Completed</h2>
                            <p className="text-xs text-muted-foreground truncate px-4">{state.targetUrl}</p>
                        </div>

                        <div className="grid grid-cols-2 gap-3">
                            <div className="p-3 border rounded border-border bg-card text-center space-y-1 shadow-sm">
                                <p className="text-[10px] text-muted-foreground uppercase">Total Findings</p>
                                <p className="text-2xl font-bold">{state.summary?.totalFindings || 0}</p>
                            </div>
                            <div className="p-3 border rounded border-border bg-card text-center space-y-1 shadow-sm">
                                <p className="text-[10px] text-muted-foreground uppercase">Duration</p>
                                <p className="text-2xl font-bold">{state.summary?.durationSeconds.toFixed(1)}s</p>
                            </div>
                        </div>

                        <div className="space-y-2">
                            <h3 className="text-xs font-semibold px-1">Severity Breakdown</h3>
                            <div className="flex flex-wrap gap-2">
                                {Object.entries(state.summary?.severityCounts || {}).map(([sev, count]) => {
                                    if (count === 0) return null;
                                    const s = sev as Severity;
                                    return (
                                        <Badge key={sev} variant="outline" className="flex gap-1.5 py-1">
                                            <span className={`w-2 h-2 rounded-full ${s === 'CRITICAL' ? 'bg-red-600' : s === 'HIGH' ? 'bg-orange-500' : s === 'MEDIUM' ? 'bg-yellow-500' : s === 'LOW' ? 'bg-blue-500' : 'bg-gray-400'}`}></span>
                                            <span className="text-[10px] font-medium">{sev}</span>
                                            <span className="text-[10px] ml-1">{count}</span>
                                        </Badge>
                                    )
                                })}
                            </div>
                        </div>

                        <Button 
                            variant="default"
                            className="w-full"
                            onClick={() => window.location.reload()}
                        >
                            New Scan
                        </Button>
                    </div>
                )}

            </ScrollArea>
        </div>
    )
}
