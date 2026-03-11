export function OptionsApp() {
    return (
        <div className="min-h-screen bg-background text-foreground p-8">
            <header className="max-w-4xl mx-auto border-b border-border pb-4 mb-6">
                <h1 className="text-2xl font-bold tracking-tight">S2N Scanner</h1>
                <p className="text-sm text-muted-foreground mt-1">설정 및 스캔 히스토리</p>
            </header>

            <main className="max-w-4xl mx-auto">
                <div className="grid grid-cols-3 gap-2 mb-6">
                    <button className="px-3 py-2 text-sm rounded-md bg-secondary text-secondary-foreground hover:bg-accent transition-colors">
                        히스토리
                    </button>
                    <button className="px-3 py-2 text-sm rounded-md bg-secondary text-secondary-foreground hover:bg-accent transition-colors">
                        설정
                    </button>
                    <button className="px-3 py-2 text-sm rounded-md bg-secondary text-secondary-foreground hover:bg-accent transition-colors">
                        내보내기
                    </button>
                </div>
                <p className="text-sm text-muted-foreground">콘텐츠 영역 준비 중</p>
            </main>
        </div>
    )
}
