"""
MailTrace AI - IOC Extractor Service
Feature 4: IOC Extraction
"""

import re
import ipaddress
from urllib.parse import urlparse, urlunparse
from html.parser import HTMLParser
import hashlib
from typing import Dict, List, Optional, Tuple, Any, Set

from backend.models.ioc import (
    UrlIoc,
    DomainIoc,
    IpIoc,
    EmailIoc,
    HashIoc,
    HostnameIoc,
    AttachmentIoc,
    IocSummary,
    IocExtractionResult
)
from backend.models.forensics import ForensicEvidenceResult
from backend.services.email_forensics import analyze_email_forensics


# Regular expressions for IOC extraction
URL_REGEX = re.compile(r"\b(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)
EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
IPV4_CANDIDATE_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_CANDIDATE_REGEX = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:)*::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}\b")

# Strict hex hash regex with exact word boundaries
MD5_REGEX = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_REGEX = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_REGEX = re.compile(r"\b[a-fA-F0-9]{64}\b")

# Common second-level TLD suffixes for root domain extraction
SECOND_LEVEL_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk",
    "com.au", "net.au", "org.au", "edu.au",
    "co.in", "net.in", "org.in", "gov.in",
    "com.br", "co.jp", "ne.jp", "com.sg"
}


class SimpleHtmlLinkExtractor(HTMLParser):
    """Safely extracts href and src attributes from HTML without executing or downloading."""
    def __init__(self):
        super().__init__()
        self.links: List[Tuple[str, str]] = []  # (url, context/anchor)
        self.current_href: Optional[str] = None
        self.current_text: List[str] = []

    def handle_starttag(self, tag, attrs):
        attr_dict = dict(attrs)
        if tag == "a" and "href" in attr_dict:
            self.current_href = attr_dict["href"]
            self.current_text = []
        elif tag in ["img", "script", "iframe", "link", "source"] and "src" in attr_dict:
            self.links.append((attr_dict["src"], f"HTML <{tag} src>"))
        elif tag == "link" and "href" in attr_dict:
            self.links.append((attr_dict["href"], "HTML <link href>"))

    def handle_data(self, data):
        if self.current_href is not None:
            self.current_text.append(data.strip())

    def handle_endtag(self, tag):
        if tag == "a" and self.current_href:
            context = " ".join(self.current_text).strip() or "HTML anchor link"
            self.links.append((self.current_href, context))
            self.current_href = None
            self.current_text = []


class IocExtractorService:
    """
    Robust extraction, normalization, and deduplication engine for Indicators of Compromise (IOCs).
    Preserves original representations, classifies network scopes, and tracks provenance.
    """

    def normalize_url(self, raw_url: str) -> Tuple[str, Optional[str], Optional[str], Optional[str], Optional[str]]:
        """
        Normalizes a URL string:
        - Ensures scheme (default http if www.)
        - Lowercases scheme and hostname
        - Strips harmless trailing dot
        - Strips default ports (:80, :443)
        Returns (normalized_url, scheme, hostname, path, query)
        """
        url_to_parse = raw_url.strip()
        if url_to_parse.lower().startswith("www."):
            url_to_parse = f"http://{url_to_parse}"

        try:
            parsed = urlparse(url_to_parse)
            scheme = (parsed.scheme or "http").lower()
            hostname = (parsed.hostname or "").lower().rstrip(".")

            # Default port normalization
            port = parsed.port
            netloc = hostname
            if port:
                if (scheme == "http" and port != 80) or (scheme == "https" and port != 443):
                    netloc = f"{hostname}:{port}"

            path = parsed.path or "/"
            query = parsed.query or None

            normalized = urlunparse((
                scheme,
                netloc,
                path,
                parsed.params,
                query or "",
                ""  # Fragment stripped for canonical deduplication
            ))

            return normalized, scheme, hostname, path, query
        except Exception:
            return raw_url.strip().lower(), None, None, None, None

    def extract_root_domain(self, hostname: str) -> str:
        """
        Extracts the registrable root domain from a hostname (e.g. login.example.com -> example.com).
        Preserves lookalike domains without modification.
        """
        if not hostname:
            return ""

        clean_host = hostname.lower().strip().rstrip(".")
        
        # If IP address, root domain is None
        try:
            ipaddress.ip_address(clean_host)
            return ""
        except ValueError:
            pass

        parts = clean_host.split(".")
        if len(parts) <= 2:
            return clean_host

        # Check for compound TLDs like co.uk or com.au
        compound_check = ".".join(parts[-2:])
        if compound_check in SECOND_LEVEL_TLDS and len(parts) >= 3:
            return ".".join(parts[-3:])

        return ".".join(parts[-2:])

    def extract_urls(self, body_text: str, html_text: str = "") -> List[UrlIoc]:
        """
        Extracts URLs from plain text and HTML anchors/sources, normalizes and deduplicates.
        """
        url_map: Dict[str, UrlIoc] = {}

        # 1. Plain text regex
        if body_text:
            for match in URL_REGEX.finditer(body_text):
                raw = match.group(0).rstrip(".,;!?'\")>]} ")
                norm, scheme, host, path, query = self.normalize_url(raw)
                if not norm:
                    continue

                if norm in url_map:
                    if "email_body" not in url_map[norm].sources:
                        url_map[norm].sources.append("email_body")
                else:
                    url_map[norm] = UrlIoc(
                        value=raw,
                        normalized=norm,
                        scheme=scheme,
                        hostname=host,
                        path=path,
                        query=query,
                        sources=["email_body"],
                        context="Plain text email body"
                    )

        # 2. HTML links
        if html_text:
            parser = SimpleHtmlLinkExtractor()
            try:
                parser.feed(html_text)
                for raw_link, ctx in parser.links:
                    raw = raw_link.strip()
                    if raw.startswith(("javascript:", "mailto:", "tel:", "#")):
                        continue

                    norm, scheme, host, path, query = self.normalize_url(raw)
                    if not norm:
                        continue

                    if norm in url_map:
                        if "html_body" not in url_map[norm].sources:
                            url_map[norm].sources.append("html_body")
                    else:
                        url_map[norm] = UrlIoc(
                            value=raw,
                            normalized=norm,
                            scheme=scheme,
                            hostname=host,
                            path=path,
                            query=query,
                            sources=["html_body"],
                            context=ctx
                        )
            except Exception:
                pass

        return list(url_map.values())

    def extract_ips(self, text_corpus: str, relay_hops: List[Any]) -> List[IpIoc]:
        """
        Extracts and validates IPv4 and IPv6 addresses, classifying scopes (public, private, loopback).
        """
        ip_map: Dict[str, IpIoc] = {}

        def record_ip(ip_str: str, source_label: str, ctx: Optional[str] = None):
            clean_ip = ip_str.strip()
            try:
                ip_obj = ipaddress.ip_address(clean_ip)
                val = str(ip_obj)

                if ip_obj.is_loopback:
                    scope = "loopback"
                elif ip_obj.is_private:
                    scope = "private"
                elif ip_obj.is_link_local:
                    scope = "link-local"
                elif ip_obj.is_reserved:
                    scope = "reserved"
                elif ip_obj.is_multicast:
                    scope = "multicast"
                else:
                    scope = "public"

                if val in ip_map:
                    if source_label not in ip_map[val].sources:
                        ip_map[val].sources.append(source_label)
                else:
                    ip_map[val] = IpIoc(
                        value=val,
                        version=ip_obj.version,
                        scope=scope,
                        sources=[source_label],
                        context=ctx
                    )
            except ValueError:
                pass

        # 1. Received relay hops from Feature 3
        for hop in relay_hops:
            if hasattr(hop, "from_ip") and hop.from_ip:
                record_ip(hop.from_ip, f"received_hop_{getattr(hop, 'hop_number', 1)}", f"Relay from {getattr(hop, 'from_host', 'host')}")

        # 2. Text corpus (body & headers)
        if text_corpus:
            for match in IPV4_CANDIDATE_REGEX.finditer(text_corpus):
                record_ip(match.group(0), "email_text", "Observed in text")
            for match in IPV6_CANDIDATE_REGEX.finditer(text_corpus):
                record_ip(match.group(0), "email_text", "Observed in text")

        return list(ip_map.values())

    def extract_emails(self, headers: Dict[str, Any], body_text: str = "") -> List[EmailIoc]:
        """
        Extracts email addresses from headers and body, deconstructing local_part and domain.
        """
        email_map: Dict[str, EmailIoc] = {}

        def record_email(raw_str: str, source_name: str):
            if not raw_str:
                return
            matches = EMAIL_REGEX.finditer(str(raw_str))
            for m in matches:
                full_addr = m.group(0).strip().lower()
                domain_part = m.group(1).lower()
                local_part = full_addr.split("@")[0]

                if full_addr in email_map:
                    if source_name not in email_map[full_addr].sources:
                        email_map[full_addr].sources.append(source_name)
                else:
                    email_map[full_addr] = EmailIoc(
                        value=full_addr,
                        local_part=local_part,
                        domain=domain_part,
                        sources=[source_name],
                        context=f"Found in {source_name}"
                    )

        # Header fields
        for hdr in ["From", "To", "Cc", "Bcc", "Reply-To", "Return-Path", "Sender"]:
            val = headers.get(hdr) or headers.get(hdr.lower())
            if val:
                record_email(str(val), f"{hdr.lower().replace('-', '_')}_header")

        # Body text
        if body_text:
            record_email(body_text, "email_body")

        return list(email_map.values())

    def extract_domains_and_hostnames(
        self, 
        urls: List[UrlIoc], 
        emails: List[EmailIoc], 
        relay_hops: List[Any], 
        headers: Dict[str, Any]
    ) -> Tuple[List[DomainIoc], List[HostnameIoc]]:
        """
        Extracts domains, root domains, and hostnames with IDN/Punycode detection.
        """
        domain_map: Dict[str, DomainIoc] = {}
        hostname_map: Dict[str, HostnameIoc] = {}

        def record_domain(dom_str: str, src: str, ctx: Optional[str] = None):
            if not dom_str:
                return
            clean = dom_str.lower().strip().rstrip(".")
            # Ignore plain IPs
            try:
                ipaddress.ip_address(clean)
                return
            except ValueError:
                pass

            if not clean or "." not in clean:
                return

            root = self.extract_root_domain(clean)
            is_punycode = clean.startswith("xn--") or ".xn--" in clean
            unicode_dom = None
            if is_punycode:
                try:
                    unicode_dom = clean.encode("ascii").decode("idna")
                except Exception:
                    pass

            if clean in domain_map:
                if src not in domain_map[clean].sources:
                    domain_map[clean].sources.append(src)
            else:
                domain_map[clean] = DomainIoc(
                    value=clean,
                    registered_domain=root or clean,
                    is_punycode=is_punycode,
                    unicode_domain=unicode_dom,
                    sources=[src],
                    context=ctx
                )

        def record_hostname(host_str: str, src: str, ctx: Optional[str] = None):
            if not host_str:
                return
            clean = host_str.lower().strip().rstrip(".")
            try:
                ipaddress.ip_address(clean)
                return
            except ValueError:
                pass

            if not clean:
                return

            if clean in hostname_map:
                if src not in hostname_map[clean].sources:
                    hostname_map[clean].sources.append(src)
            else:
                hostname_map[clean] = HostnameIoc(
                    value=clean,
                    sources=[src],
                    context=ctx
                )

        # 1. From URLs
        for u in urls:
            if u.hostname:
                record_domain(u.hostname, "url", f"URL hostname ({u.scheme}://...)")
                record_hostname(u.hostname, "url", f"Extracted from {u.normalized}")

        # 2. From Emails
        for e in emails:
            if e.domain:
                record_domain(e.domain, "email_address", f"Domain of {e.value}")

        # 3. From Relay Hops
        for hop in relay_hops:
            if hasattr(hop, "from_host") and hop.from_host:
                record_domain(hop.from_host, "received_relay", f"Reported in hop {getattr(hop, 'hop_number', 1)}")
                record_hostname(hop.from_host, "received_relay", f"Hop {getattr(hop, 'hop_number', 1)} sender host")
            if hasattr(hop, "by_host") and hop.by_host:
                record_domain(hop.by_host, "received_relay", f"Receiving MTA hop {getattr(hop, 'hop_number', 1)}")
                record_hostname(hop.by_host, "received_relay", f"Hop {getattr(hop, 'hop_number', 1)} receiving MTA")

        return list(domain_map.values()), list(hostname_map.values())

    def extract_hashes(self, text_corpus: str, attachments: List[Any]) -> Tuple[List[HashIoc], List[AttachmentIoc]]:
        """
        Strictly extracts MD5, SHA-1, and SHA-256 hashes from text and computes hashes for attachments.
        """
        hash_map: Dict[str, HashIoc] = {}
        attachment_iocs: List[AttachmentIoc] = []

        def record_hash(h_val: str, algo: str, src: str, ctx: Optional[str] = None):
            clean = h_val.strip().lower()
            if clean in hash_map:
                if src not in hash_map[clean].sources:
                    hash_map[clean].sources.append(src)
            else:
                hash_map[clean] = HashIoc(
                    value=clean,
                    algorithm=algo,
                    sources=[src],
                    context=ctx
                )

        # 1. Process attachments
        for att in attachments:
            fname = getattr(att, "filename", "unnamed")
            sha256_val = getattr(att, "sha256_hash", None)
            mime_type = getattr(att, "mime_type", "application/octet-stream")
            size_bytes = getattr(att, "size_bytes", 0)
            indicators = getattr(att, "indicators", [])

            if sha256_val:
                record_hash(sha256_val, "SHA256", "attachment", f"Payload hash of '{fname}'")

            attachment_iocs.append(AttachmentIoc(
                filename=fname,
                mime_type=mime_type,
                size_bytes=size_bytes,
                sha256=sha256_val or "",
                indicators=indicators
            ))

        # 2. Strict regex scan on text corpus
        if text_corpus:
            # We match SHA-256 first (64 chars), SHA-1 (40 chars), MD5 (32 chars)
            # using lookarounds to avoid matching substrings of longer hex tokens
            for match in re.finditer(r"(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])", text_corpus):
                record_hash(match.group(0), "SHA256", "email_text", "Extracted 64-character hex hash")

            for match in re.finditer(r"(?<![a-fA-F0-9])[a-fA-F0-9]{40}(?![a-fA-F0-9])", text_corpus):
                record_hash(match.group(0), "SHA1", "email_text", "Extracted 40-character hex hash")

            for match in re.finditer(r"(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])", text_corpus):
                record_hash(match.group(0), "MD5", "email_text", "Extracted 32-character hex hash")

        return list(hash_map.values()), attachment_iocs

    def extract_from_forensics(self, forensics: ForensicEvidenceResult, raw_eml: str = "") -> IocExtractionResult:
        """
        Master orchestration for Feature 4: Extracts all IOCs from Feature 3 output and raw email.
        """
        headers = forensics.headers or {}
        body_text = forensics.mime_analysis.plain_text_preview or ""
        relay_hops = forensics.relay_path or []
        attachments = forensics.attachments or []

        # Combined text corpus for regex scanning
        full_text = f"{forensics.subject}\n{body_text}\n{forensics.raw_headers_text}\n{raw_eml}"

        # 1. URLs
        urls = self.extract_urls(body_text=full_text, html_text=raw_eml if "<html>" in raw_eml.lower() else "")

        # 2. Email addresses
        emails = self.extract_emails(headers, body_text)

        # 3. Domains & Hostnames
        domains, hostnames = self.extract_domains_and_hostnames(urls, emails, relay_hops, headers)

        # 4. IP Addresses
        ips = self.extract_ips(full_text, relay_hops)

        # 5. Hashes & Attachments
        hashes, att_iocs = self.extract_hashes(full_text, attachments)

        # Summary
        summary = IocSummary(
            urls=len(urls),
            domains=len(domains),
            ips=len(ips),
            emails=len(emails),
            hashes=len(hashes),
            hostnames=len(hostnames),
            attachments=len(att_iocs)
        )

        return IocExtractionResult(
            summary=summary,
            urls=urls,
            domains=domains,
            ips=ips,
            emails=emails,
            hashes=hashes,
            hostnames=hostnames,
            attachments=att_iocs
        )

    def extract_from_raw_eml(self, raw_input: bytes | str) -> Tuple[ForensicEvidenceResult, IocExtractionResult]:
        """
        Convenience pipeline: parses raw EML via Feature 3 forensics and then extracts Feature 4 IOCs.
        """
        forensics = analyze_email_forensics(raw_input)
        raw_str = raw_input if isinstance(raw_input, str) else raw_input.decode("utf-8", errors="replace")
        iocs = self.extract_from_forensics(forensics, raw_str)
        return forensics, iocs


# Global default service instance
default_ioc_service = IocExtractorService()


def extract_iocs(raw_input: bytes | str, forensic_data: Optional[ForensicEvidenceResult] = None) -> IocExtractionResult:
    """Convenience helper for extracting IOCs."""
    raw_str = raw_input if isinstance(raw_input, str) else raw_input.decode("utf-8", errors="replace")
    if forensic_data is None:
        forensic_data = analyze_email_forensics(raw_input)
    return default_ioc_service.extract_from_forensics(forensic_data, raw_str)
