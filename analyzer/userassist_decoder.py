import base64
import codecs
import json
import sys

def decode_rot13(s):
    return codecs.decode(s, 'rot_13')

def parse_userassist(raw_json_path, output_path):
    with open(raw_json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    results = []
    for entry in data:
        name = decode_rot13(entry['Name']) if isinstance(entry['Name'], str) else entry['Name']
        raw_val = entry.get('RawValue', {})
        # Пример: извлечение счетчика запусков (обычно 12-й байт в REG_BINARY)
        if 'Count' in raw_val and isinstance(raw_val['Count'], list):
            # Упрощенная логика: в реальности парсинг зависит от версии Windows
            pass
        results.append({"decoded_name": name, "raw_metadata": raw_val})

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    parse_userassist(sys.argv[1], sys.argv[2])
