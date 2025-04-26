import typer
from rich.console import Console
from kelidnama.scanner import scan_path, scan_parallel, filter_results

app = typer.Typer()
console = Console()

@app.command()
def scan(paths: list[str] = typer.Option(..., "--path", help="مسیرهای پروژه‌ای که می‌خواهید اسکن کنید"),
         filter_type: str = typer.Option(None, help="فیلتر کردن بر اساس نوع حساسیت")):
    """
    اسکن مسیرهای مشخص‌شده برای یافتن کلیدها، رمزها و اطلاعات حساس
    """
    console.print(f"[bold yellow]🔍 در حال اسکن مسیرها: [cyan]{paths}[/]")
    all_results = scan_parallel(paths)

    if filter_type:
        all_results = filter_results(all_results, filter_type)

    if not all_results:
        console.print("[green]✅ هیچ داده حساسی پیدا نشد!")
    else:
        for item in all_results:
            file, reason = item
            console.print(f"[red]⚠️ {file} → {reason}")

if __name__ == "__main__":
    app()