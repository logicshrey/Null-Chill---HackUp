from __future__ import annotations

import asyncio
import math
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

import requests

from utils.config import (
    DATA_SENSITIVITY_SCORES,
    DEHASHED_API_KEY,
    DEHASHED_EMAIL,
    GITHUB_TOKEN,
    INTELX_API_BASE,
    INTELX_API_KEY,
    PASTEBIN_API_KEY,
    PLATFORM_REPUTATION_SCORES,
    PUBLIC_INTEL_MAX_ITEMS,
    PUBLIC_INTEL_REQUEST_TIMEOUT,
    TELEGRAM_API_HASH,
    TELEGRAM_API_ID,
    TELEGRAM_SESSION_STRING,
)


EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
HANDLE_PATTERN = re.compile(r"(?<!\w)@([A-Za-z0-9_]{3,32})\b")
DOMAIN_PATTERN = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
USERNAME_ASSIGNMENT_PATTERN = re.compile(r"(?i)\b(?:username|user|login|handle)\s*[:=]\s*([A-Za-z0-9._@-]{3,64})")
PASSWORD_SIGNAL_PATTERN = re.compile(r"(?i)\b(?:password|passwd|pwd|hash|hashes)\b")
PHONE_SIGNAL_PATTERN = re.compile(r"(?i)\b(?:phone|mobile|msisdn)\b")
IP_SIGNAL_PATTERN = re.compile(r"(?i)\b(?:ip|ipv4|ipv6)\b")
THREAT_SIGNAL_PATTERN = re.compile(
    r"(?i)\b(?:credential|credentials|password|combo|leak|breach|dump|database|phishing|otp|stealer|"
    r"malware|ransomware|account|access|admin|panel|logs|fullz|hash|cookies?)\b"
)


class IntelligenceSourceError(RuntimeError):
    """Raised when a source cannot be queried safely or correctly."""


@dataclass
class RawSourceHit:
    source: str
    text: str
    date_found: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AggregatedFinding:
    organization: str
    source: str
    platforms: list[str]
    text: str
    emails: list[str]
    usernames: list[str]
    type: str
    risk_score: float
    date_found: str
    volume: int
    raw_items: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class BaseIntelClient:
    name = "Unknown"

    def collect(self, query: str) -> list[RawSourceHit]:
        raise NotImplementedError


class TelegramIntelClient(BaseIntelClient):
    name = "Telegram"

    def collect(self, query: str) -> list[RawSourceHit]:
        if not TELEGRAM_API_ID or not TELEGRAM_API_HASH:
            raise IntelligenceSourceError("Telegram credentials are not configured.")
        if not TELEGRAM_SESSION_STRING:
            raise IntelligenceSourceError("Telegram requires a Telethon session string for authenticated access.")
        try:
            return asyncio.run(self._collect_async(query))
        except Exception as exc:
            raise IntelligenceSourceError(f"Telegram collection failed: {exc}") from exc

    async def _collect_async(self, query: str) -> list[RawSourceHit]:
        from telethon import TelegramClient
        from telethon.sessions import StringSession

        hits: list[RawSourceHit] = []
        async with TelegramClient(StringSession(TELEGRAM_SESSION_STRING), TELEGRAM_API_ID, TELEGRAM_API_HASH) as client:
            async for message in client.iter_messages(None, search=query, limit=PUBLIC_INTEL_MAX_ITEMS):
                message_text = getattr(message, "message", "") or ""
                if not message_text.strip():
                    continue
                hits.append(
                    RawSourceHit(
                        source=self.name,
                        text=message_text.strip(),
                        date_found=self._resolve_date(getattr(message, "date", None)),
                        metadata={
                            "message_id": getattr(message, "id", None),
                            "chat_id": getattr(getattr(message, "peer_id", None), "channel_id", None),
                        },
                    )
                )
        return hits

    @staticmethod
    def _resolve_date(value: Any) -> str:
        if value is None:
            return datetime.now(timezone.utc).date().isoformat()
        if hasattr(value, "date"):
            return value.date().isoformat()
        return str(value)[:10]


class PastebinIntelClient(BaseIntelClient):
    name = "Pastebin"
    timeline_url = "https://scrape.pastebin.com/api_scraping.php"
    item_url = "https://scrape.pastebin.com/api_scrape_item.php"

    def collect(self, query: str) -> list[RawSourceHit]:
        session = requests.Session()
        hits: list[RawSourceHit] = []
        try:
            # Pastebin's public scraping API is the only supported public-data interface for reading pastes.
            response = session.get(
                self.timeline_url,
                params={"limit": min(PUBLIC_INTEL_MAX_ITEMS, 25)},
                timeout=PUBLIC_INTEL_REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            recent_items = response.json()
        except Exception as exc:
            hint = " Pastebin scraping may require an approved IP and account privileges."
            if PASTEBIN_API_KEY:
                hint += " Developer API keys alone do not grant public search access."
            raise IntelligenceSourceError(f"Pastebin timeline lookup failed:{hint} ({exc})") from exc

        normalized_query = query.lower()
        for item in recent_items[:PUBLIC_INTEL_MAX_ITEMS]:
            paste_key = item.get("key")
            if not paste_key:
                continue

            try:
                content_response = session.get(
                    self.item_url,
                    params={"i": paste_key},
                    timeout=PUBLIC_INTEL_REQUEST_TIMEOUT,
                )
                content_response.raise_for_status()
            except Exception:
                continue

            content = content_response.text.strip()
            if not content:
                continue

            if normalized_query not in content.lower() and normalized_query not in str(item.get("title", "")).lower():
                continue

            hits.append(
                RawSourceHit(
                    source=self.name,
                    text=content,
                    date_found=self._resolve_timestamp(item.get("date")),
                    metadata={
                        "paste_key": paste_key,
                        "title": item.get("title"),
                        "syntax": item.get("syntax"),
                    },
                )
            )
        return hits

    @staticmethod
    def _resolve_timestamp(value: Any) -> str:
        if value in (None, ""):
            return datetime.now(timezone.utc).date().isoformat()
        try:
            return datetime.fromtimestamp(int(value), tz=timezone.utc).date().isoformat()
        except Exception:
            return datetime.now(timezone.utc).date().isoformat()


class DehashedIntelClient(BaseIntelClient):
    name = "Dehashed"
    search_url = "https://api.dehashed.com/v2/search"

    def collect(self, query: str) -> list[RawSourceHit]:
        if not DEHASHED_API_KEY:
            raise IntelligenceSourceError("Dehashed API key is not configured.")
        if not DEHASHED_EMAIL:
            raise IntelligenceSourceError("Dehashed requires the account email alongside the API key.")

        response = requests.get(
            self.search_url,
            headers={"Accept": "application/json"},
            params={"query": self._build_query(query), "size": PUBLIC_INTEL_MAX_ITEMS},
            auth=(DEHASHED_EMAIL, DEHASHED_API_KEY),
            timeout=PUBLIC_INTEL_REQUEST_TIMEOUT,
        )
        try:
            response.raise_for_status()
        except Exception as exc:
            raise IntelligenceSourceError(f"Dehashed query failed: {exc}") from exc

        payload = response.json()
        entries = payload.get("entries", [])
        hits = []
        for entry in entries[:PUBLIC_INTEL_MAX_ITEMS]:
            text = self._entry_to_text(entry)
            hits.append(
                RawSourceHit(
                    source=self.name,
                    text=text,
                    date_found=self._resolve_date(entry),
                    metadata=entry,
                )
            )
        return hits

    @staticmethod
    def _build_query(query: str) -> str:
        if "." in query and " " not in query:
            return f"domain:{query}"
        return query

    @staticmethod
    def _resolve_date(entry: dict[str, Any]) -> str:
        for key in ("obtained_from", "added_date", "date", "last_seen"):
            value = entry.get(key)
            if isinstance(value, str) and value:
                return value[:10]
        return datetime.now(timezone.utc).date().isoformat()

    @staticmethod
    def _entry_to_text(entry: dict[str, Any]) -> str:
        parts = []
        for key in ("email", "username", "database_name", "hashed_password", "password", "name", "ip_address"):
            value = entry.get(key)
            if value:
                parts.append(f"{key}={value}")
        return " ".join(parts)


class GitHubIntelClient(BaseIntelClient):
    name = "GitHub"
    code_search_url = "https://api.github.com/search/code"
    issue_search_url = "https://api.github.com/search/issues"

    def collect(self, query: str) -> list[RawSourceHit]:
        if not GITHUB_TOKEN:
            raise IntelligenceSourceError("GitHub token is not configured.")

        session = requests.Session()
        session.headers.update(
            {
                "Accept": "application/vnd.github.text-match+json, application/vnd.github+json",
                "Authorization": f"Bearer {GITHUB_TOKEN}",
                "X-GitHub-Api-Version": "2022-11-28",
            }
        )

        code_hits = self._search_code(session, query)
        issue_hits = self._search_issues(session, query)
        return [*code_hits, *issue_hits][: PUBLIC_INTEL_MAX_ITEMS * 2]

    def _search_code(self, session: requests.Session, query: str) -> list[RawSourceHit]:
        search_query = self._build_code_query(query)
        response = session.get(
            self.code_search_url,
            params={"q": search_query, "per_page": PUBLIC_INTEL_MAX_ITEMS},
            timeout=PUBLIC_INTEL_REQUEST_TIMEOUT,
        )
        try:
            response.raise_for_status()
        except Exception as exc:
            raise IntelligenceSourceError(f"GitHub code search failed: {exc}") from exc

        payload = response.json()
        items = payload.get("items", [])
        hits: list[RawSourceHit] = []
        for item in items[:PUBLIC_INTEL_MAX_ITEMS]:
            repository = item.get("repository", {})
            text_matches = item.get("text_matches", [])
            snippet = " ".join(match.get("fragment", "") for match in text_matches if match.get("fragment"))
            text = " ".join(
                part
                for part in (
                    item.get("name"),
                    item.get("path"),
                    repository.get("full_name"),
                    snippet,
                    item.get("html_url"),
                )
                if part
            )
            hits.append(
                RawSourceHit(
                    source=self.name,
                    text=text,
                    date_found=datetime.now(timezone.utc).date().isoformat(),
                    metadata={
                        "search_type": "code",
                        "repository": repository.get("full_name"),
                        "html_url": item.get("html_url"),
                        "path": item.get("path"),
                        "score": item.get("score"),
                    },
                )
            )
        return hits

    def _search_issues(self, session: requests.Session, query: str) -> list[RawSourceHit]:
        search_query = self._build_issue_query(query)
        response = session.get(
            self.issue_search_url,
            params={"q": search_query, "per_page": PUBLIC_INTEL_MAX_ITEMS},
            timeout=PUBLIC_INTEL_REQUEST_TIMEOUT,
        )
        try:
            response.raise_for_status()
        except Exception as exc:
            raise IntelligenceSourceError(f"GitHub issue search failed: {exc}") from exc

        payload = response.json()
        items = payload.get("items", [])
        hits: list[RawSourceHit] = []
        for item in items[:PUBLIC_INTEL_MAX_ITEMS]:
            body = str(item.get("body", "") or "")[:1200]
            text = " ".join(
                part
                for part in (
                    item.get("title"),
                    body,
                    item.get("html_url"),
                )
                if part
            )
            hits.append(
                RawSourceHit(
                    source=self.name,
                    text=text,
                    date_found=self._resolve_issue_date(item),
                    metadata={
                        "search_type": "issues",
                        "html_url": item.get("html_url"),
                        "state": item.get("state"),
                        "repository_url": item.get("repository_url"),
                        "score": item.get("score"),
                    },
                )
            )
        return hits

    @staticmethod
    def _build_code_query(query: str) -> str:
        exact_query = f"\"{query}\""
        return f"{exact_query} in:file"

    @staticmethod
    def _build_issue_query(query: str) -> str:
        exact_query = f"\"{query}\""
        return exact_query

    @staticmethod
    def _resolve_issue_date(item: dict[str, Any]) -> str:
        value = item.get("updated_at") or item.get("created_at")
        if isinstance(value, str) and value:
            return value[:10]
        return datetime.now(timezone.utc).date().isoformat()


class IntelXIntelClient(BaseIntelClient):
    name = "IntelX"
    search_path = "/intelligent/search"
    result_path = "/intelligent/search/result"
    info_path = "/authenticate/info"

    def collect(self, query: str) -> list[RawSourceHit]:
        if not INTELX_API_KEY:
            raise IntelligenceSourceError("IntelX API key is not configured.")

        session = requests.Session()
        session.headers.update(
            {
                "x-key": INTELX_API_KEY,
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )

        try:
            self._validate_access(session)
            search_id = self._start_search(session, query)
            return self._fetch_results(session, search_id, query)
        except IntelligenceSourceError:
            raise
        except Exception as exc:
            raise IntelligenceSourceError(f"IntelX collection failed: {exc}") from exc

    def _validate_access(self, session: requests.Session) -> None:
        response = session.get(f"{INTELX_API_BASE}{self.info_path}", timeout=PUBLIC_INTEL_REQUEST_TIMEOUT)
        try:
            response.raise_for_status()
        except Exception as exc:
            raise IntelligenceSourceError(f"IntelX authentication failed: {exc}") from exc

    def _start_search(self, session: requests.Session, query: str) -> str:
        payload = {
            "term": query,
            "maxresults": max(1, PUBLIC_INTEL_MAX_ITEMS),
            "media": 0,
            "target": 0,
            "terminate": [],
            "timeout": min(60, max(5, int(PUBLIC_INTEL_REQUEST_TIMEOUT))),
        }
        response = session.post(
            f"{INTELX_API_BASE}{self.search_path}",
            json=payload,
            timeout=PUBLIC_INTEL_REQUEST_TIMEOUT,
        )
        try:
            response.raise_for_status()
        except Exception as exc:
            raise IntelligenceSourceError(f"IntelX search failed: {exc}") from exc

        search_id = response.json().get("id")
        if not search_id:
            raise IntelligenceSourceError("IntelX search did not return a search ID.")
        return str(search_id)

    def _fetch_results(self, session: requests.Session, search_id: str, query: str) -> list[RawSourceHit]:
        response = session.get(
            f"{INTELX_API_BASE}{self.result_path}",
            params={"id": search_id},
            timeout=max(PUBLIC_INTEL_REQUEST_TIMEOUT, 20),
        )
        try:
            response.raise_for_status()
        except Exception as exc:
            raise IntelligenceSourceError(f"IntelX result retrieval failed: {exc}") from exc

        payload = response.json()
        records = payload.get("records", [])
        hits: list[RawSourceHit] = []
        for record in records[:PUBLIC_INTEL_MAX_ITEMS]:
            text = self._record_to_text(record, query)
            hits.append(
                RawSourceHit(
                    source=self.name,
                    text=text,
                    date_found=self._resolve_record_date(record),
                    metadata={
                        "bucket": record.get("bucket"),
                        "name": record.get("name"),
                        "media": record.get("media"),
                        "type": record.get("type"),
                        "systemid": record.get("systemid"),
                        "storageid": record.get("storageid"),
                        "search_type": "intelx",
                    },
                )
            )
        return hits

    @staticmethod
    def _record_to_text(record: dict[str, Any], query: str) -> str:
        key_values = record.get("keyvalues") or []
        keyvalue_text = " ".join(
            f"{item.get('key')}={item.get('value')}"
            for item in key_values
            if isinstance(item, dict) and (item.get("key") or item.get("value"))
        )
        parts = [
            str(record.get("name", "") or ""),
            str(record.get("description", "") or ""),
            str(record.get("bucket", "") or ""),
            keyvalue_text,
            query,
        ]
        return " ".join(part for part in parts if part).strip()

    @staticmethod
    def _resolve_record_date(record: dict[str, Any]) -> str:
        value = record.get("date") or record.get("added")
        if isinstance(value, str) and value:
            return value[:10]
        return datetime.now(timezone.utc).date().isoformat()


class ExternalIntelligenceService:
    """Collects public intelligence and normalizes it into a dashboard-ready structure."""

    def __init__(self) -> None:
        self.clients: list[BaseIntelClient] = [
            TelegramIntelClient(),
            GitHubIntelClient(),
            IntelXIntelClient(),
            PastebinIntelClient(),
            DehashedIntelClient(),
        ]

    def collect(self, query: str) -> dict[str, Any]:
        normalized_query = str(query or "").strip()
        findings: list[AggregatedFinding] = []
        warnings: list[str] = []

        for client in self.clients:
            try:
                hits = client.collect(normalized_query)
            except IntelligenceSourceError as exc:
                warnings.append(str(exc))
                continue

            hits = [hit for hit in hits if self._is_relevant_hit(normalized_query, hit)]
            if not hits:
                warnings.append(f"{client.name} returned no high-confidence threat-relevant hits for query {normalized_query}.")
                continue

            findings.append(self._aggregate_hits(normalized_query, client.name, hits))

        platforms = [finding.source for finding in findings]
        for finding in findings:
            finding.platforms = platforms

        return {
            "organization": normalized_query,
            "platforms": platforms,
            "findings": [finding.to_dict() for finding in findings],
            "warnings": warnings,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    @staticmethod
    def build_demo_collection(query: str) -> dict[str, Any]:
        """Return synthetic but schema-compatible source intelligence for safe UI testing."""
        normalized_query = str(query or "").strip()
        safe_domain = ExternalIntelligenceService._safe_demo_domain(normalized_query)
        date_found = datetime.now(timezone.utc).date().isoformat()
        platforms = ["Telegram Demo", "Pastebin Demo", "Dehashed Demo"]

        findings = [
            {
                "organization": normalized_query,
                "source": "Telegram Demo",
                "platforms": platforms,
                "text": (
                    f"Demo monitoring signal for {normalized_query}: actor advertising combo access for "
                    f"admin@{safe_domain} with recovery workflow discussion in a Telegram-style channel."
                ),
                "emails": [f"admin@{safe_domain}", f"ops@{safe_domain}"],
                "usernames": [f"{ExternalIntelligenceService._slugify(normalized_query)}_ops", "sessionbroker_demo"],
                "type": "Credential Leak",
                "risk_score": 0.82,
                "date_found": date_found,
                "volume": 3,
                "raw_items": [
                    {
                        "text": f"Demo Telegram post referencing {normalized_query} account combo access.",
                        "date_found": date_found,
                        "metadata": {"demo": True, "channel": "telegram_demo_channel"},
                    }
                ],
            },
            {
                "organization": normalized_query,
                "source": "Pastebin Demo",
                "platforms": platforms,
                "text": (
                    f"Demo paste snippet mentioning {normalized_query} support records, email list "
                    f"breach notice, and exposed usernames tied to {safe_domain}."
                ),
                "emails": [f"support@{safe_domain}"],
                "usernames": [f"{ExternalIntelligenceService._slugify(normalized_query)}_support"],
                "type": "Database Dump",
                "risk_score": 0.74,
                "date_found": date_found,
                "volume": 2,
                "raw_items": [
                    {
                        "text": f"Demo Pastebin text containing synthetic records for {normalized_query}.",
                        "date_found": date_found,
                        "metadata": {"demo": True, "paste_key": "demo-paste-001"},
                    }
                ],
            },
            {
                "organization": normalized_query,
                "source": "Dehashed Demo",
                "platforms": platforms,
                "text": (
                    f"Demo breach record for {normalized_query} showing recycled credentials, hash references, "
                    f"and account takeover exposure for users on {safe_domain}."
                ),
                "emails": [f"security@{safe_domain}"],
                "usernames": [f"{ExternalIntelligenceService._slugify(normalized_query)}_sec"],
                "type": "Credential Leak",
                "risk_score": 0.91,
                "date_found": date_found,
                "volume": 4,
                "raw_items": [
                    {
                        "text": f"Demo Dehashed record for {normalized_query}.",
                        "date_found": date_found,
                        "metadata": {"demo": True, "dataset": "dehashed_demo"},
                    }
                ],
            },
        ]

        return {
            "organization": normalized_query,
            "platforms": platforms,
            "findings": findings,
            "warnings": ["Demo mode enabled: synthetic source intelligence was generated for safe UI testing."],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "demo_mode": True,
        }

    def _aggregate_hits(self, organization: str, source: str, hits: list[RawSourceHit]) -> AggregatedFinding:
        emails = self._unique(self._extract_emails(hits))
        usernames = self._unique(self._extract_usernames(hits))
        combined_text = "\n\n".join(hit.text for hit in hits if hit.text.strip())
        breach_type = self._classify_breach_type(combined_text, hits)
        data_types = self._detect_data_types(combined_text, emails, usernames, hits)
        risk_score = self._calculate_risk_score(source, data_types, len(hits))
        dates = [hit.date_found for hit in hits if hit.date_found]

        return AggregatedFinding(
            organization=organization,
            source=source,
            platforms=[source],
            text=combined_text,
            emails=emails,
            usernames=usernames,
            type=breach_type,
            risk_score=risk_score,
            date_found=min(dates) if dates else datetime.now(timezone.utc).date().isoformat(),
            volume=len(hits),
            raw_items=[
                {
                    "text": hit.text,
                    "date_found": hit.date_found,
                    "metadata": hit.metadata,
                }
                for hit in hits
            ],
        )

    @staticmethod
    def _is_relevant_hit(query: str, hit: RawSourceHit) -> bool:
        normalized_query = str(query or "").strip().lower()
        haystack_parts = [hit.text, *[str(value) for value in hit.metadata.values() if value is not None]]
        haystack = " ".join(haystack_parts).lower()
        emails = EMAIL_PATTERN.findall(haystack)
        domains = DOMAIN_PATTERN.findall(haystack)
        usernames = HANDLE_PATTERN.findall(haystack)
        has_threat_signal = bool(THREAT_SIGNAL_PATTERN.search(haystack))
        has_sensitive_signal = bool(emails or usernames or PASSWORD_SIGNAL_PATTERN.search(haystack))
        search_type = str(hit.metadata.get("search_type", "")).lower()

        # Domain queries should match the exact domain or emails on that domain.
        if "." in normalized_query and " " not in normalized_query:
            exact_domain_match = normalized_query in {domain.lower() for domain in domains}
            email_domain_match = any(email.lower().endswith(f"@{normalized_query}") for email in emails)
            github_code_match = hit.source == "GitHub" and search_type == "code" and exact_domain_match
            intelx_match = hit.source == "IntelX" and normalized_query in haystack
            return github_code_match or intelx_match or exact_domain_match or email_domain_match or (
                normalized_query in haystack and has_threat_signal
            )

        # Organization-name queries must mention the org and also contain threat/exposure signals.
        org_match = normalized_query in haystack
        return org_match and (has_threat_signal or has_sensitive_signal)

    @staticmethod
    def _extract_emails(hits: list[RawSourceHit]) -> list[str]:
        results: list[str] = []
        for hit in hits:
            results.extend(EMAIL_PATTERN.findall(hit.text))
            for value in hit.metadata.values():
                if isinstance(value, str):
                    results.extend(EMAIL_PATTERN.findall(value))
        return results

    @staticmethod
    def _extract_usernames(hits: list[RawSourceHit]) -> list[str]:
        results: list[str] = []
        for hit in hits:
            results.extend(HANDLE_PATTERN.findall(hit.text))
            results.extend(USERNAME_ASSIGNMENT_PATTERN.findall(hit.text))
            username = hit.metadata.get("username")
            if isinstance(username, str) and username:
                results.append(username)
        return [username.lstrip("@") for username in results if username]

    @staticmethod
    def _classify_breach_type(text: str, hits: list[RawSourceHit]) -> str:
        lowered = text.lower()
        metadata_blob = " ".join(str(hit.metadata) for hit in hits).lower()
        combined = f"{lowered} {metadata_blob}"

        if any(keyword in combined for keyword in ("hash", "password", "combo", "credential", "account", "login")):
            return "Credential Leak"
        if any(keyword in combined for keyword in ("dump", "database", "records", "breach", "leak")):
            return "Database Dump"
        if any(keyword in combined for keyword in ("phishing", "otp", "spoof", "fake portal")):
            return "Phishing"
        if any(keyword in combined for keyword in ("stealer", "loader", "crypter", "malware", "ransomware")):
            return "Malware Sale"
        return "Credential Leak"

    @staticmethod
    def _detect_data_types(text: str, emails: list[str], usernames: list[str], hits: list[RawSourceHit]) -> list[str]:
        lowered = text.lower()
        data_types: list[str] = []

        if emails:
            data_types.append("email addresses")
        if usernames:
            data_types.append("usernames")
        if PASSWORD_SIGNAL_PATTERN.search(lowered):
            data_types.append("credentials")
        if "hashed_password" in lowered or "hash" in lowered:
            data_types.append("hashed passwords")
        if PHONE_SIGNAL_PATTERN.search(lowered):
            data_types.append("phone numbers")
        if IP_SIGNAL_PATTERN.search(lowered):
            data_types.append("ip addresses")

        if not data_types:
            for hit in hits:
                if any(key in hit.metadata for key in ("password", "hashed_password", "email")):
                    data_types.append("credentials")
                    break

        return ExternalIntelligenceService._unique(data_types) or ["undetermined"]

    @staticmethod
    def _calculate_risk_score(source: str, data_types: list[str], volume: int) -> float:
        platform_score = PLATFORM_REPUTATION_SCORES.get(source, 0.45)
        sensitivity_score = max(DATA_SENSITIVITY_SCORES.get(data_type, 0.35) for data_type in data_types)
        volume_score = min(1.0, math.log1p(max(1, volume)) / math.log(12))
        risk_score = (platform_score * 0.4) + (sensitivity_score * 0.4) + (volume_score * 0.2)
        return round(min(1.0, risk_score), 2)

    @staticmethod
    def _unique(values: list[str]) -> list[str]:
        seen: set[str] = set()
        results: list[str] = []
        for value in values:
            normalized = str(value or "").strip()
            if not normalized:
                continue
            lowered = normalized.lower()
            if lowered in seen:
                continue
            seen.add(lowered)
            results.append(normalized)
        return results

    @staticmethod
    def _slugify(value: str) -> str:
        slug = re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().lower()).strip("-")
        return slug or "org"

    @staticmethod
    def _safe_demo_domain(query: str) -> str:
        if "." in query and " " not in query:
            return query.lower()
        return f"{ExternalIntelligenceService._slugify(query)}.example"
