# analyzer/test_logs.py
import json
import pandas as pd
from pathlib import Path
from parsers.logs_parser import LogsParser

def main():
    # УКАЖИ ПУТЬ К ТВОЕМУ ФАЙЛУ logs.json
    logs_path = Path("/home/ascol/vkr/betaVersion/arfS3rcher/output/old/virtualka/logs.json")
    if not logs_path.exists():
        print(f"[!] File not found: {logs_path}")
        return

    parser = LogsParser()
    result = parser.parse(str(logs_path))

    # 1. Статистика сервисов
    df_svc = pd.DataFrame(result["services"])
    print(f"✅ Loaded {len(df_svc)} services")
    print(df_svc["category"].value_counts())
    print("\n🔴 Top 5 Suspicious Services (Risk > 20):")
    print(df_svc[df_svc["risk_score"] > 20][["PSChildName", "ImagePath", "risk_score", "tags"]].head(5))

    # 2. Статистика UserAssist
    df_ua = pd.DataFrame(result["user_assist"])
    print(f"\n✅ Loaded {len(df_ua)} UserAssist entries")
    print(df_ua["category"].value_counts())
    print("\n🌐 Network & Removable Paths:")
    paths = df_ua[df_ua["category"].isin(["network_path", "removable_media", "pentest_tool"])]
    print(paths[["decoded_name", "category", "tags"]].head(10))

if __name__ == "__main__":
    main()
