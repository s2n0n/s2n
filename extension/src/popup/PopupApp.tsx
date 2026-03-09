import { Button } from '@/components/ui/button'

export function PopupApp() {
    return (
        <div className="flex flex-col gap-4 p-4 bg-background text-foreground min-h-[500px]">
            <header className="flex items-center gap-2 border-b border-border pb-3">
                <h1 className="text-lg font-bold tracking-tight">S2N Scanner</h1>
                <span className="ml-auto text-xs text-muted-foreground">v0.1.0</span>
            </header>

            <main className="flex-1 flex flex-col items-center justify-center gap-3">
                <p className="text-sm text-muted-foreground">스캔 기능 준비 중</p>
                <Button variant="default" size="sm">
                    스캔 시작
                </Button>
            </main>

            <footer className="text-center text-xs text-muted-foreground pt-2 border-t border-border">
                Phase 1 - Extension 스켈레톤
            </footer>
        </div>
    )
}
