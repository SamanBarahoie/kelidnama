import os
import json
import yaml
import logging
import typer
from rich.console import Console
from threading import Thread

# تنظیمات لاگ
logging.basicConfig(filename='kelidnama.log', level=logging.INFO)

# ایجاد کنسول برای چاپ به ترمینال
console = Console()

# ایجاد شی Typer
app = typer.Typer()

# تابع برای بارگذاری تنظیمات از فایل پیکربندی
def load_config(config_path="config.yaml"):
    with open(config_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
    return config

# بارگذاری تنظیمات
config = load_config()

# استفاده از تنظیمات در کد
sensitive_keywords = config.get("sensitive_keywords", ["AWS", "password", "token", "secret"])
ignored_extensions = config.get("ignored_extensions", [".png", ".jpg", ".exe"])

# تعریف تابع جستجو در داده‌های حساس
def find_sensitive_info(data):
    results = []
    # جستجو در دیکشنری‌ها و لیست‌ها
    if isinstance(data, dict):
        for key, value in data.items():
            if any(keyword in str(value) for keyword in sensitive_keywords):
                results.append((key, "Found sensitive data"))
    elif isinstance(data, list):
        for item in data:
            if any(keyword in str(item) for keyword in sensitive_keywords):
                results.append(("List item", "Found sensitive data"))
    return results


# اسکن فایل JSON
def scan_json_file(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
        return find_sensitive_info(data)


# اسکن فایل YAML
def scan_yaml_file(file_path):
    with open(file_path, 'r') as f:
        data = yaml.safe_load(f)
        return find_sensitive_info(data)


# اسکن فایل متنی
def scan_text_file(file_path):
    with open(file_path, 'r') as f:
        content = f.read()
        # جستجو برای کلمات حساس در فایل متنی
        results = []
        for keyword in sensitive_keywords:
            if keyword in content:
                results.append((file_path, f"Found {keyword}"))
        return results


# تابع اسکن مسیر
def scan_path(path):
    results = []
    if os.path.isfile(path):
        results.extend(scan_file(path))
    elif os.path.isdir(path):
        for root, _, files in os.walk(path):
            for file in files:
                # اگر فایل از پسوندهایی که باید نادیده گرفته شوند برخوردار باشد، اسکن نمی‌شود.
                if any(file.endswith(ext) for ext in ignored_extensions):
                    continue
                results.extend(scan_file(os.path.join(root, file)))
    return results


# تابع اسکن فایل‌ها
def scan_file(file_path):
    if file_path.endswith(".json"):
        return scan_json_file(file_path)
    elif file_path.endswith(".yaml") or file_path.endswith(".yml"):
        return scan_yaml_file(file_path)
    else:
        return scan_text_file(file_path)


# تابع لاگ‌گذاری اطلاعات
def log_error(message):
    logging.error(message)


def log_info(message):
    logging.info(message)


# فیلتر کردن نتایج بر اساس حساسیت
def filter_results(results, filter_type):
    return [result for result in results if filter_type in result[1]]


# اسکن چندین مسیر به صورت همزمان (با استفاده از threading)
def scan_parallel(paths):
    threads = []
    results = []
    for path in paths:
        thread = Thread(target=lambda p=path: results.extend(scan_path(p)))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()
    return results


# تابع اصلی اسکن
@app.command()
def scan(paths: list[str] = typer.Option(..., help="فایل‌های مختلف برای اسکن"),
         filter_type: str = typer.Option(None, help="فیلتر کردن بر اساس نوع حساسیت")):
    all_results = []
    # اسکن به صورت موازی برای چندین مسیر
    all_results = scan_parallel(paths)

    if filter_type:
        all_results = filter_results(all_results, filter_type)

    # نمایش نتایج
    if not all_results:
        console.print("[green]✅ هیچ داده حساس پیدا نشد!")
    else:
        for item in all_results:
            file, reason = item
            console.print(f"[red]⚠️ {file} → {reason}")

