"""
MailTrace AI - Email Forensics Engine Service
Feature 3: Email Forensics
"""

import re
import email
import email.policy
from email.utils import parseaddr, parsedate_to_datetime
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any

from backend.models.forensics import (
    RelayHop,
    RoutingAnalysis,
    SpfEvidence,
    DkimEvidence,
    DmarcEvidence,
    AuthenticationForensics,
    SenderIdentityForensics,
    AttachmentForensics,
    MimeAnalysis,
    ForensicAnomaly,
    ForensicEvidenceResult
)
from backend.models.threat import EmailAnalysisInput
from backend.services.identity_signals import _parse_sender, KNOWN_ORGANIZATIONS


DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".vbs", ".hta", ".iso", ".bat", ".cmd", 
    ".ps1", ".js", ".wsf", ".jar", ".msi", ".pif", ".reg", ".dll"
}

MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm"}

IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_REGEX = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


class EmailForensicsService:
    """
    Forensic Engine for deep inspection of raw RFC 822 .eml content.
    Reconstructs transmission path, authenticates identity alignment,
    parses cryptographic evidence, and inspects attachments.
    """

    def parse_raw_message(self, raw_input: bytes | str) -> Tuple[email.message.EmailMessage, bytes, str]:
        """
        Parses raw email bytes or string into an EmailMessage object.
        Preserves raw bytes and calculates cryptographic SHA-256 evidence hash.
        """
        if isinstance(raw_input, str):
            raw_bytes = raw_input.encode("utf-8", errors="replace")
            raw_text = raw_input
        else:
            raw_bytes = raw_input
            raw_text = raw_input.decode("utf-8", errors="replace")

        evidence_hash = hashlib.sha256(raw_bytes).hexdigest()
        
        try:
            msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
        except Exception:
            msg = email.message_from_string(raw_text, policy=email.policy.compat32)

        return msg, raw_bytes, evidence_hash

    def extract_headers_map(self, msg: email.message.EmailMessage) -> Tuple[Dict[str, Any], str]:
        """Extracts and normalizes major headers, preserving raw header text."""
        headers_map: Dict[str, Any] = {}
        raw_lines: List[str] = []

        for key in msg.keys():
            val = str(msg[key])
            headers_map[key] = val
            raw_lines.append(f"{key}: {val}")

        raw_headers_text = "\r\n".join(raw_lines)
        return headers_map, raw_headers_text

    def analyze_sender_identity(self, headers: Dict[str, Any], body_text: str = "") -> Tuple[SenderIdentityForensics, List[ForensicAnomaly]]:
        """
        Examines From, Reply-To, Return-Path, and Sender for identity alignment.
        """
        anomalies: List[ForensicAnomaly] = []

        from_header = headers.get("From") or headers.get("from") or ""
        reply_to_header = headers.get("Reply-To") or headers.get("reply-to") or ""
        return_path_header = headers.get("Return-Path") or headers.get("return-path") or ""
        sender_header = headers.get("Sender") or headers.get("sender") or ""

        disp_name, from_addr, from_domain = _parse_sender(from_header)
        _, reply_addr, reply_domain = _parse_sender(reply_to_header)
        _, return_addr, return_domain = _parse_sender(return_path_header)
        _, sender_addr, _ = _parse_sender(sender_header)

        inconsistencies: List[str] = []

        # 1. Reply-To mismatch
        reply_to_mismatch = False
        if reply_domain and from_domain and reply_domain != from_domain:
            reply_to_mismatch = True
            inconsistencies.append(f"Reply-To domain (@{reply_domain}) does not match From domain (@{from_domain})")
            anomalies.append(ForensicAnomaly(
                type="REPLY_TO_MISMATCH",
                severity="HIGH",
                description=f"Reply-To address <{reply_addr}> directs replies to a different domain than From <{from_addr}>."
            ))
        elif reply_addr and from_addr and reply_addr != from_addr:
            reply_to_mismatch = True
            inconsistencies.append(f"Reply-To address <{reply_addr}> differs from From address <{from_addr}>")
            anomalies.append(ForensicAnomaly(
                type="REPLY_TO_MISMATCH",
                severity="MEDIUM",
                description=f"Reply-To <{reply_addr}> differs from From <{from_addr}>."
            ))

        # 2. Return-Path mismatch
        return_path_mismatch = False
        if return_domain and from_domain and return_domain != from_domain:
            return_path_mismatch = True
            inconsistencies.append(f"Envelope Return-Path domain (@{return_domain}) differs from header From domain (@{from_domain})")
            anomalies.append(ForensicAnomaly(
                type="RETURN_PATH_MISMATCH",
                severity="MEDIUM",
                description=f"Envelope Return-Path <{return_addr}> differs from From <{from_addr}>."
            ))

        # 3. Display Name brand mismatch
        display_name_mismatch = False
        lower_disp = disp_name.lower()
        for org in KNOWN_ORGANIZATIONS:
            if org in lower_disp and org.replace(" ", "") not in from_domain:
                display_name_mismatch = True
                inconsistencies.append(f"Display name '{disp_name}' references '{org}' but sending domain is @{from_domain}")
                anomalies.append(ForensicAnomaly(
                    type="DISPLAY_NAME_SPOOF",
                    severity="HIGH",
                    description=f"Friendly display name claims affiliation with '{org.title()}', but sender domain is @{from_domain}."
                ))
                break

        identity = SenderIdentityForensics(
            from_address=from_addr,
            display_name=disp_name,
            from_domain=from_domain,
            reply_to_address=reply_addr if reply_addr else None,
            reply_to_domain=reply_domain if reply_domain else None,
            return_path_address=return_addr if return_addr else None,
            return_path_domain=return_domain if return_domain else None,
            sender_address=sender_addr if sender_addr else None,
            reply_to_mismatch=reply_to_mismatch,
            return_path_mismatch=return_path_mismatch,
            display_name_mismatch=display_name_mismatch,
            inconsistencies=inconsistencies
        )

        return identity, anomalies

    def reconstruct_smtp_relay_path(self, msg: email.message.EmailMessage) -> Tuple[List[RelayHop], RoutingAnalysis, List[ForensicAnomaly]]:
        """
        Parses all 'Received:' headers in chronological order (originating MTA to destination).
        Extracts hostnames, IP addresses, protocols, ciphers, and transit intervals.
        """
        anomalies: List[ForensicAnomaly] = []
        raw_received = msg.get_all("Received") or []

        # Received headers are prepended top-to-bottom.
        # Bottom-most Received header = Hop 1 (earliest externally observed relay).
        chronological_received = list(reversed(raw_received))
        
        hops: List[RelayHop] = []
        observed_ips: List[str] = []
        observed_hosts: List[str] = []
        previous_dt: Optional[datetime] = None

        from_regex = re.compile(r"from\s+([^\s\(]+)(?:\s+\((?:[^\)]*?\[)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?[^\)]*\))?", re.IGNORECASE)
        by_regex = re.compile(r"by\s+([^\s\(]+)", re.IGNORECASE)
        with_regex = re.compile(r"with\s+([^\s;]+)", re.IGNORECASE)
        cipher_regex = re.compile(r"(?:cipher|using\s+TLS[^\s;]*|version=TLS[^\s;]*)", re.IGNORECASE)

        for idx, rec_str in enumerate(chronological_received, start=1):
            clean_rec = " ".join(rec_str.split())
            
            # Extract date after semicolon
            date_raw = None
            date_dt = None
            date_iso = None
            if ";" in rec_str:
                parts = rec_str.rsplit(";", 1)
                date_raw = parts[-1].strip()
                try:
                    date_dt = parsedate_to_datetime(date_raw)
                    date_iso = date_dt.isoformat()
                except Exception:
                    pass

            from_host = None
            from_ip = None
            f_match = from_regex.search(clean_rec)
            if f_match:
                from_host = f_match.group(1).rstrip(";")
                from_ip = f_match.group(2)
            if not from_ip:
                ip_search = IP_REGEX.search(clean_rec)
                if ip_search:
                    from_ip = ip_search.group(0)

            by_host = None
            b_match = by_regex.search(clean_rec)
            if b_match:
                by_host = b_match.group(1).rstrip(";")

            protocol = None
            p_match = with_regex.search(clean_rec)
            if p_match:
                protocol = p_match.group(1).upper()

            tls_cipher = None
            c_match = cipher_regex.search(clean_rec)
            if c_match:
                tls_cipher = c_match.group(0)

            delay_seconds = None
            if previous_dt and date_dt:
                delay = (date_dt - previous_dt).total_seconds()
                delay_seconds = round(delay, 2)
                if delay < -60:  # Negative hop interval > 1 min
                    anomalies.append(ForensicAnomaly(
                        type="TIMESTAMP_ANOMALY",
                        severity="MEDIUM",
                        description=f"Negative transit delay ({delay_seconds}s) between hop {idx-1} and hop {idx} indicates clock skew or irregular routing."
                    ))
                elif delay > 86400:  # Delay > 24 hours
                    anomalies.append(ForensicAnomaly(
                        type="UNUSUAL_RELAY_DELAY",
                        severity="LOW",
                        description=f"Hop {idx} experienced abnormal transit delay of {delay_seconds}s."
                    ))
            if date_dt:
                previous_dt = date_dt

            if from_ip and from_ip not in observed_ips:
                observed_ips.append(from_ip)
            if from_host and from_host not in observed_hosts:
                observed_hosts.append(from_host)
            if by_host and by_host not in observed_hosts:
                observed_hosts.append(by_host)

            hops.append(RelayHop(
                hop_number=idx,
                from_host=from_host,
                from_ip=from_ip,
                by_host=by_host,
                protocol=protocol,
                tls_cipher=tls_cipher,
                timestamp_raw=date_raw,
                timestamp_iso=date_iso,
                delay_seconds=delay_seconds
            ))

        # Build visual representation
        path_nodes: List[str] = ["Internet Source"]
        for h in hops:
            label = h.from_ip or h.from_host or "relay"
            if label not in path_nodes:
                path_nodes.append(label)
        if hops and hops[-1].by_host:
            path_nodes.append(hops[-1].by_host)
        path_nodes.append("Recipient Mailbox")
        visual_path = " -> ".join(path_nodes)

        originating_candidate = None
        if hops:
            first_hop = hops[0]
            ip_desc = first_hop.from_ip or "unresolved IP"
            host_desc = first_hop.from_host or "unknown host"
            originating_candidate = f"{ip_desc} ({host_desc}) [Earliest externally observed relay]"

        routing = RoutingAnalysis(
            hop_count=len(hops),
            observed_ips=observed_ips,
            observed_hostnames=observed_hosts,
            originating_infrastructure_candidate=originating_candidate,
            relay_path_visual=visual_path
        )

        return hops, routing, anomalies

    def parse_authentication_evidence(self, headers: Dict[str, Any], raw_headers_text: str) -> Tuple[AuthenticationForensics, List[ForensicAnomaly]]:
        """
        Extracts SPF, DKIM, and DMARC evidence from headers.
        """
        anomalies: List[ForensicAnomaly] = []
        raw_auth_headers: List[str] = []

        for key, val in headers.items():
            k_lower = key.lower()
            if any(k_lower.startswith(prefix) for prefix in ["authentication-results", "received-spf", "dkim-signature", "arc-"]):
                raw_auth_headers.append(f"{key}: {val}")

        auth_text = " ".join(raw_auth_headers).lower()

        # 1. SPF Parsing
        spf_res = "unknown"
        spf_domain = None
        spf_ip = None
        spf_match = re.search(r"\bspf=(pass|fail|softfail|neutral|none|permerror|temperror)\b", auth_text)
        if spf_match:
            spf_res = spf_match.group(1)
        elif "received-spf" in headers:
            r_spf = headers["received-spf"].lower()
            r_match = re.search(r"^(pass|fail|softfail|neutral|none|permerror|temperror)", r_spf.strip())
            if r_match:
                spf_res = r_match.group(1)

        domain_match = re.search(r"smtp\.mailfrom=([^\s;]+)", auth_text)
        if domain_match:
            spf_domain = domain_match.group(1)
        ip_match = re.search(r"(?:sender\s+ip\s+is\s+|ip=)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", auth_text)
        if ip_match:
            spf_ip = ip_match.group(1)

        if spf_res in ["fail", "softfail", "permerror"]:
            anomalies.append(ForensicAnomaly(
                type="SPF_AUTHENTICATION_FAILURE",
                severity="HIGH" if spf_res == "fail" else "MEDIUM",
                description=f"SPF record check evaluated as '{spf_res.upper()}'. Sending IP is not authorized."
            ))

        spf_evidence = SpfEvidence(
            result=spf_res,
            domain=spf_domain,
            sender_ip=spf_ip,
            source_header="Authentication-Results" if spf_match else ("Received-SPF" if "received-spf" in headers else None)
        )

        # 2. DKIM Parsing
        dkim_res = "unknown"
        dkim_domain = None
        dkim_selector = None
        dkim_algo = None
        has_dkim_sig = "DKIM-Signature" in headers or "dkim-signature" in headers

        dkim_match = re.search(r"\bdkim=(pass|fail|neutral|permerror|temperror)\b", auth_text)
        if dkim_match:
            dkim_res = dkim_match.group(1)
        elif has_dkim_sig:
            dkim_res = "neutral"

        dkim_sig_val = headers.get("DKIM-Signature") or headers.get("dkim-signature") or ""
        d_match = re.search(r"\bd=([^\s;]+)", dkim_sig_val)
        if d_match:
            dkim_domain = d_match.group(1)
        s_match = re.search(r"\bs=([^\s;]+)", dkim_sig_val)
        if s_match:
            dkim_selector = s_match.group(1)
        a_match = re.search(r"\ba=([^\s;]+)", dkim_sig_val)
        if a_match:
            dkim_algo = a_match.group(1)

        if dkim_res in ["fail", "permerror"]:
            anomalies.append(ForensicAnomaly(
                type="DKIM_SIGNATURE_FAILURE",
                severity="HIGH",
                description="DKIM signature failed cryptographic verification, indicating potential message modification."
            ))

        dkim_evidence = DkimEvidence(
            result=dkim_res,
            domain=dkim_domain,
            selector=dkim_selector,
            algorithm=dkim_algo,
            signature_present=has_dkim_sig
        )

        # 3. DMARC Parsing
        dmarc_res = "unknown"
        dmarc_policy = None
        dmarc_domain = None
        dmarc_match = re.search(r"\bdmarc=(pass|fail|none|permerror|temperror)\b", auth_text)
        if dmarc_match:
            dmarc_res = dmarc_match.group(1)
        p_match = re.search(r"\bp=(none|quarantine|reject)\b", auth_text)
        if p_match:
            dmarc_policy = p_match.group(1)
        h_match = re.search(r"header\.from=([^\s;]+)", auth_text)
        if h_match:
            dmarc_domain = h_match.group(1)

        if dmarc_res in ["fail", "permerror"]:
            anomalies.append(ForensicAnomaly(
                type="DMARC_ALIGNMENT_FAILURE",
                severity="HIGH",
                description=f"DMARC policy alignment failed (result: {dmarc_res.upper()}). Possible sender domain impersonation."
            ))

        dmarc_evidence = DmarcEvidence(
            result=dmarc_res,
            policy=dmarc_policy,
            domain=dmarc_domain,
            spf_aligned=spf_res == "pass",
            dkim_aligned=dkim_res == "pass"
        )

        # Overall status
        if spf_res == "pass" and dkim_res == "pass" and dmarc_res == "pass":
            overall = "VERIFIED"
        elif any(r in ["fail", "permerror"] for r in [spf_res, dkim_res, dmarc_res]):
            overall = "FAILED"
        elif any(r == "softfail" for r in [spf_res, dkim_res, dmarc_res]):
            overall = "SUSPICIOUS"
        elif any(r == "pass" for r in [spf_res, dkim_res, dmarc_res]):
            overall = "PARTIALLY_VERIFIED"
        else:
            overall = "UNKNOWN"

        auth = AuthenticationForensics(
            spf=spf_evidence,
            dkim=dkim_evidence,
            dmarc=dmarc_evidence,
            overall_status=overall,
            raw_auth_headers=raw_auth_headers
        )

        return auth, anomalies

    def analyze_mime_and_attachments(self, msg: email.message.EmailMessage) -> Tuple[MimeAnalysis, List[AttachmentForensics], str, str, List[ForensicAnomaly]]:
        """
        Parses MIME structure, extracts plain/html content, and performs attachment forensics.
        """
        anomalies: List[ForensicAnomaly] = []
        attachments: List[AttachmentForensics] = []
        plain_text_body = ""
        html_body = ""
        charsets: List[str] = []
        parts_count = 0

        for part in msg.walk():
            parts_count += 1
            content_type = part.get_content_type()
            charset = part.get_content_charset()
            if charset and charset not in charsets:
                charsets.append(charset)

            disposition = str(part.get_content_disposition() or "")
            filename = part.get_filename()

            if filename:
                # Attachment identified
                # Sanitize filename against directory traversal
                clean_name = filename.replace("/", "").replace("\\", "").replace("..", "").strip()
                payload = part.get_payload(decode=True) or b""
                size_bytes = len(payload)
                sha256 = hashlib.sha256(payload).hexdigest()

                lower_name = clean_name.lower()
                indicators: List[str] = []

                # Extension analysis
                parts = lower_name.split(".")
                ext = f".{parts[-1]}" if len(parts) > 1 else ""

                if len(parts) > 2:
                    second_ext = f".{parts[-2]}"
                    if ext in DANGEROUS_EXTENSIONS or second_ext in [".pdf", ".doc", ".docx", ".xls", ".xlsx"]:
                        indicators.append("DOUBLE_EXTENSION")
                        anomalies.append(ForensicAnomaly(
                            type="SUSPICIOUS_DOUBLE_EXTENSION",
                            severity="CRITICAL",
                            description=f"Attachment '{clean_name}' employs deceptive double extension (.pdf.exe / .doc.js)."
                        ))

                if ext in DANGEROUS_EXTENSIONS:
                    indicators.append("EXECUTABLE_EXTENSION")
                    anomalies.append(ForensicAnomaly(
                        type="EXECUTABLE_ATTACHMENT",
                        severity="CRITICAL",
                        description=f"Attachment '{clean_name}' carries an executable or script extension ({ext})."
                    ))

                if ext in MACRO_EXTENSIONS:
                    indicators.append("MACRO_ENABLED")
                    anomalies.append(ForensicAnomaly(
                        type="MACRO_ENABLED_ATTACHMENT",
                        severity="HIGH",
                        description=f"Attachment '{clean_name}' is a macro-enabled Office document."
                    ))

                attachments.append(AttachmentForensics(
                    filename=clean_name,
                    mime_type=content_type,
                    size_bytes=size_bytes,
                    sha256_hash=sha256,
                    extension=ext,
                    disposition=disposition or "attachment",
                    indicators=indicators
                ))
            else:
                # Body content
                if content_type == "text/plain" and not plain_text_body:
                    try:
                        raw_payload = part.get_payload(decode=True)
                        plain_text_body = raw_payload.decode(charset or "utf-8", errors="replace")
                    except Exception:
                        plain_text_body = str(part.get_payload() or "")
                elif content_type == "text/html" and not html_body:
                    try:
                        raw_payload = part.get_payload(decode=True)
                        html_body = raw_payload.decode(charset or "utf-8", errors="replace")
                    except Exception:
                        html_body = str(part.get_payload() or "")

        preview = plain_text_body[:300] if plain_text_body else (html_body[:300] if html_body else None)
        
        mime = MimeAnalysis(
            content_type=msg.get_content_type(),
            parts_count=parts_count,
            has_plain_text=bool(plain_text_body),
            has_html=bool(html_body),
            plain_text_preview=preview,
            charsets=charsets
        )

        return mime, attachments, plain_text_body, html_body, anomalies

    def analyze(self, raw_input: bytes | str) -> ForensicEvidenceResult:
        """
        Master orchestration method for Feature 3 Email Forensics.
        """
        msg, raw_bytes, evidence_hash = self.parse_raw_message(raw_input)
        headers_map, raw_headers_text = self.extract_headers_map(msg)

        all_anomalies: List[ForensicAnomaly] = []

        # 1. Message-ID inspection
        msg_id = headers_map.get("Message-ID") or headers_map.get("message-id")
        if not msg_id:
            all_anomalies.append(ForensicAnomaly(
                type="MISSING_MESSAGE_ID",
                severity="MEDIUM",
                description="The email lacks a standard RFC 5322 'Message-ID' header."
            ))
        elif not (msg_id.strip().startswith("<") and msg_id.strip().endswith(">")):
            all_anomalies.append(ForensicAnomaly(
                type="MALFORMED_MESSAGE_ID",
                severity="LOW",
                description=f"Message-ID '{msg_id}' does not adhere to standard RFC angle bracket formatting."
            ))

        # 2. Date normalization
        orig_date = headers_map.get("Date") or headers_map.get("date")
        norm_date = None
        if orig_date:
            try:
                dt = parsedate_to_datetime(orig_date)
                norm_date = dt.isoformat()
            except Exception:
                all_anomalies.append(ForensicAnomaly(
                    type="MALFORMED_DATE_HEADER",
                    severity="LOW",
                    description=f"Date header '{orig_date}' could not be normalized to ISO 8601."
                ))

        # 3. Sender Identity
        sender_id, id_anomalies = self.analyze_sender_identity(headers_map)
        all_anomalies.extend(id_anomalies)

        # 4. SMTP Relay Reconstruction
        relay_hops, routing_analysis, relay_anomalies = self.reconstruct_smtp_relay_path(msg)
        all_anomalies.extend(relay_anomalies)

        # 5. Authentication Evidence
        auth, auth_anomalies = self.parse_authentication_evidence(headers_map, raw_headers_text)
        all_anomalies.extend(auth_anomalies)

        # 6. MIME and Attachments
        mime_analysis, attachments, plain_text, html_text, mime_anomalies = self.analyze_mime_and_attachments(msg)
        all_anomalies.extend(mime_anomalies)

        subject = headers_map.get("Subject") or headers_map.get("subject") or ""

        return ForensicEvidenceResult(
            raw_evidence_hash=evidence_hash,
            normalized_date=norm_date,
            original_date=orig_date,
            message_id=msg_id,
            subject=subject,
            headers=headers_map,
            raw_headers_text=raw_headers_text,
            sender_identity=sender_id,
            authentication=auth,
            relay_path=relay_hops,
            routing_analysis=routing_analysis,
            mime_analysis=mime_analysis,
            attachments=attachments,
            anomalies=all_anomalies
        )

    def convert_forensics_to_analysis_input(self, forensics: ForensicEvidenceResult, body_text: str = "") -> EmailAnalysisInput:
        """
        Bridges Feature 3 forensics into Feature 1 & 2 threat evaluation.
        Allows an uploaded raw .eml to flow seamlessly through the complete platform pipeline.
        """
        urls: List[str] = []
        if body_text:
            urls = URL_REGEX.findall(body_text)

        att_metadata = [
            {"filename": a.filename, "mime_type": a.mime_type, "size": a.size_bytes}
            for a in forensics.attachments
        ]

        sender_str = forensics.sender_identity.from_address
        if forensics.sender_identity.display_name:
            sender_str = f"{forensics.sender_identity.display_name} <{forensics.sender_identity.from_address}>"

        return EmailAnalysisInput(
            sender=sender_str,
            recipient=forensics.headers.get("To") or forensics.headers.get("to") or "",
            reply_to=forensics.sender_identity.reply_to_address or "",
            return_path=forensics.sender_identity.return_path_address or "",
            subject=forensics.subject,
            body=body_text or forensics.mime_analysis.plain_text_preview or "",
            urls=urls,
            domains=list(set([forensics.sender_identity.from_domain] + [a.extension for a in forensics.attachments])),
            ips=forensics.routing_analysis.observed_ips,
            attachments=att_metadata,
            spf=forensics.authentication.spf.result,
            dkim=forensics.authentication.dkim.result,
            dmarc=forensics.authentication.dmarc.result
        )


# Global default service instance
default_forensics_service = EmailForensicsService()


def analyze_email_forensics(raw_input: bytes | str) -> ForensicEvidenceResult:
    """Convenience helper for analyzing email forensics."""
    return default_forensics_service.analyze(raw_input)
