#!/usr/bin/env python3
"""Fetch UIBE career events and update events.json.

The UIBE career site returns AES-encrypted JSON from its public event endpoint.
This script mirrors the site's own browser-side decryption, normalizes records,
and preserves explicitly-added third-party records as unverified supplements.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from zoneinfo import ZoneInfo

import requests
from Crypto.Cipher import AES
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


ROOT = Path(__file__).resolve().parent
DATA_FILE = ROOT / "events.json"
TIMEZONE = ZoneInfo("Asia/Shanghai")
LIST_ENDPOINT = "https://career.uibe.edu.cn/front/zp_query/zphQuery.do"
LIST_PAGE = "https://career.uibe.edu.cn/front/channel.jspa?channelId=766&parentId=625"
DETAIL_PAGE = "https://career.uibe.edu.cn/front/zph.jspa?tid={}"
AES_KEY = b"abcdef0123456789"
AES_IV = b"0123456789abcdef"
PAGE_SIZE = 20
MAX_PAGES = int(os.getenv("UIBE_MAX_PAGES", "20"))
HISTORY_DAYS = int(os.getenv("UIBE_HISTORY_DAYS", "45"))

FINANCE_KEYWORDS = (
    "银行",
    "证券",
    "基金",
    "保险",
    "信托",
    "金融",
    "融资",
    "担保",
    "期货",
    "资管",
    "资产管理",
    "财富",
    "投资",
    "会计师事务所",
)
ONLINE_KEYWORDS = ("线上", "在线", "空中宣讲", "腾讯会议", "直播", "zoom", "teams")


def make_session() -> requests.Session:
    retry = Retry(
        total=4,
        connect=4,
        read=4,
        backoff_factor=1.2,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(("GET", "POST")),
    )
    session = requests.Session()
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.headers.update(
        {
            "User-Agent": "Mozilla/5.0 (compatible; UIBERecruitmentTracker/1.0; +https://github.com/hsam20250912-hash/uibe-campus-recruitment)",
            "Accept": "text/plain, */*; q=0.01",
            "Origin": "https://career.uibe.edu.cn",
            "Referer": LIST_PAGE,
            "X-Requested-With": "XMLHttpRequest",
        }
    )
    return session


def decrypt_payload(ciphertext: str) -> dict[str, Any]:
    """Decrypt the public API response exactly as the official page does."""
    compact = re.sub(r"\s+", "", ciphertext)
    encrypted = base64.b64decode(compact)
    decrypted = AES.new(AES_KEY, AES.MODE_CBC, AES_IV).decrypt(encrypted)
    raw = decrypted.rstrip(b"\x00").decode("utf-8")
    return json.loads(raw)


def millis_to_iso(value: Any) -> str:
    if value in (None, ""):
        return ""
    try:
        return datetime.fromtimestamp(int(value) / 1000, TIMEZONE).isoformat(timespec="seconds")
    except (TypeError, ValueError, OSError):
        return ""


def clean_text(value: Any) -> str:
    return re.sub(r"\s+", " ", html.unescape(str(value or ""))).strip()


def is_online(address: str, title: str) -> bool:
    combined = f"{address} {title}".lower()
    if urlparse(address).scheme in {"http", "https"}:
        return True
    return any(keyword.lower() in combined for keyword in ONLINE_KEYWORDS)


def normalize_official(item: dict[str, Any]) -> dict[str, Any] | None:
    event_id = clean_text(item.get("tid"))
    start = millis_to_iso(item.get("startTime"))
    if not event_id or not start:
        return None

    title = clean_text(item.get("title") or item.get("name"))
    company = clean_text(item.get("name"))
    address = clean_text(item.get("address")) or "地点待公布"
    combined = f"{title} {company}"
    cancelled = bool(re.search(r"取消|撤销|不再举办", combined))
    postponed = bool(re.search(r"延期|时间调整|改期", combined))

    return {
        "id": f"uibe-{event_id}",
        "title": title,
        "company": company,
        "start": start,
        "end": millis_to_iso(item.get("endTime")) or start,
        "location": address,
        "format": "线上" if is_online(address, title) else "线下",
        "source_name": "对外经济贸易大学招生就业处",
        "source_url": DETAIL_PAGE.format(event_id),
        "source_type": "official",
        "confirmation": "官方已核验",
        "event_state": "cancelled" if cancelled else ("postponed" if postponed else "scheduled"),
        "is_financial": any(keyword in combined for keyword in FINANCE_KEYWORDS),
        "published_at": millis_to_iso(item.get("createTime")),
        "updated_at": millis_to_iso(item.get("updateTime")),
    }


def fetch_official_events() -> tuple[list[dict[str, Any]], list[str]]:
    session = make_session()
    events: dict[str, dict[str, Any]] = {}
    warnings: list[str] = []
    pages_to_fetch = MAX_PAGES

    for page in range(1, pages_to_fetch + 1):
        try:
            payload = None
            last_error: Exception | None = None
            for attempt in range(3):
                try:
                    response = session.post(
                        LIST_ENDPOINT,
                        data={"fl2": "4", "curPage": str(page)},
                        timeout=(15, 35),
                    )
                    response.raise_for_status()
                    payload = decrypt_payload(response.text)
                    break
                except Exception as exc:
                    last_error = exc
                    if attempt < 2:
                        time.sleep(1.2 * (attempt + 1))
            if payload is None:
                raise RuntimeError("页面响应连续三次无法解码") from last_error
            if payload.get("msg") != "Y":
                raise ValueError(f"API returned msg={payload.get('msg')!r}")

            if page == 1:
                remote_pages = int(payload.get("pageCount") or 1)
                pages_to_fetch = min(MAX_PAGES, remote_pages)

            rows = payload.get("data") or []
            if not rows:
                break
            for row in rows:
                event = normalize_official(row)
                if event:
                    events[event["id"]] = event
        except Exception as exc:  # Keep already-fetched pages usable.
            warnings.append(f"第 {page} 页抓取失败：{type(exc).__name__}")
            if page == 1:
                raise RuntimeError("贸大官方宣讲会接口暂时无法读取") from exc
            break

    return list(events.values()), warnings


def load_existing() -> dict[str, Any]:
    if not DATA_FILE.exists():
        return {"meta": {}, "events": []}
    try:
        with DATA_FILE.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
        if isinstance(value, dict) and isinstance(value.get("events"), list):
            return value
    except (OSError, json.JSONDecodeError):
        pass
    return {"meta": {}, "events": []}


def comparable(event: dict[str, Any]) -> str:
    ignored = {"published_at", "updated_at"}
    data = {key: event.get(key) for key in sorted(event) if key not in ignored}
    return json.dumps(data, ensure_ascii=False, sort_keys=True)


def is_recent(event: dict[str, Any], cutoff: datetime) -> bool:
    raw = event.get("start")
    if not raw:
        return False
    try:
        when = datetime.fromisoformat(str(raw))
        if when.tzinfo is None:
            when = when.replace(tzinfo=TIMEZONE)
        return when >= cutoff
    except (TypeError, ValueError):
        return False


def preserve_supplements(existing: list[dict[str, Any]], cutoff: datetime) -> list[dict[str, Any]]:
    kept: list[dict[str, Any]] = []
    for event in existing:
        if event.get("source_type") == "official" or not is_recent(event, cutoff):
            continue
        copied = dict(event)
        copied["source_type"] = "third_party"
        copied["confirmation"] = "待确认"
        kept.append(copied)
    return kept


def short_label(event: dict[str, Any]) -> str:
    title = clean_text(event.get("title"))
    return title if len(title) <= 34 else title[:33] + "…"


def build_output(
    fetched: list[dict[str, Any]],
    previous: dict[str, Any],
    warnings: list[str],
) -> dict[str, Any]:
    now = datetime.now(TIMEZONE)
    cutoff = now - timedelta(days=HISTORY_DAYS)
    previous_events = {
        str(event.get("id")): event
        for event in previous.get("events", [])
        if isinstance(event, dict) and event.get("id")
    }

    official = [event for event in fetched if is_recent(event, cutoff)]
    supplements = preserve_supplements(list(previous_events.values()), cutoff)
    merged = {event["id"]: event for event in supplements}
    merged.update({event["id"]: event for event in official})
    events = sorted(merged.values(), key=lambda event: (event.get("start", ""), event.get("title", "")))

    added = [event for event in events if event["id"] not in previous_events]
    updated = [
        event
        for event in events
        if event["id"] in previous_events and comparable(event) != comparable(previous_events[event["id"]])
    ]
    current_ids = set(merged)
    removed = [
        event
        for event_id, event in previous_events.items()
        if event_id not in current_ids and is_recent(event, cutoff)
    ]

    details: list[str] = []
    details.extend(f"新增：{short_label(event)}" for event in added[:4])
    details.extend(f"更新：{short_label(event)}" for event in updated[:4])
    details.extend(f"移出近期列表：{short_label(event)}" for event in removed[:2])
    if not details:
        details.append("今日暂未发现新增或改期信息")
    details.extend(warnings[:2])

    digest_source = "\n".join(comparable(event) for event in events)
    return {
        "meta": {
            "title": "贸大秋招宣讲日历",
            "last_updated": now.isoformat(timespec="seconds"),
            "timezone": "Asia/Shanghai",
            "official_source": LIST_PAGE,
            "source_status": "部分页面抓取异常，已保留可用数据" if warnings else "官方渠道同步正常",
            "records": len(events),
            "data_digest": hashlib.sha256(digest_source.encode("utf-8")).hexdigest()[:16],
            "change_summary": {
                "date": now.date().isoformat(),
                "added": len(added),
                "updated": len(updated),
                "removed": len(removed),
                "details": details,
            },
            "notes": [
                "官方来源优先：对外经济贸易大学招生就业处宣讲会频道。",
                "第三方补充记录会统一标注“待确认”，请以学校或企业最终通知为准。",
            ],
        },
        "events": events,
    }


def main() -> int:
    previous = load_existing()
    try:
        fetched, warnings = fetch_official_events()
        output = build_output(fetched, previous, warnings)
    except Exception as exc:
        if not previous.get("events"):
            print(f"更新失败：{exc}", file=sys.stderr)
            return 1
        now = datetime.now(TIMEZONE)
        output = previous
        output.setdefault("meta", {})["last_updated"] = now.isoformat(timespec="seconds")
        output["meta"]["source_status"] = "官方渠道暂时无法访问，当前展示上次成功数据"
        output["meta"]["change_summary"] = {
            "date": now.date().isoformat(),
            "added": 0,
            "updated": 0,
            "removed": 0,
            "details": [f"同步暂时失败：{type(exc).__name__}；已保留上次成功数据"],
        }

    with DATA_FILE.open("w", encoding="utf-8") as handle:
        json.dump(output, handle, ensure_ascii=False, indent=2)
        handle.write("\n")

    print(
        f"已写入 {len(output.get('events', []))} 条活动；"
        f"{output.get('meta', {}).get('source_status', '')}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
