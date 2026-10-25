"""Safe, offline URL analysis and indicator extraction."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass
from urllib.parse import parse_qsl, urlsplit, urlunsplit

MAX_URL_LENGTH = 4096
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class URLAnalysisError(ValueError):
    """Raised when an input cannot be analyzed as an HTTP(S) URL."""


@dataclass(frozen=True)
class Signal:
    name: str
    description: str
    evidence: str
    severity: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def analyze_url(value: str) -> dict:
    """Analyze a URL without opening it, resolving DNS, or making network requests."""
    if not isinstance(value, str) or not value.strip():
        raise URLAnalysisError("Enter a URL to analyze.")
    original = value.strip()
    if len(original) > MAX_URL_LENGTH:
        raise URLAnalysisError(f"URL exceeds the {MAX_URL_LENGTH}-character limit.")
    if _CONTROL.search(original):
        raise URLAnalysisError("URL contains unsupported control characters.")

    try:
        parts = urlsplit(original)
        scheme = parts.scheme.lower()
        if scheme not in {"http", "https"}:
            raise URLAnalysisError("Only HTTP and HTTPS URLs are supported.")
        if not parts.netloc or not parts.hostname:
            raise URLAnalysisError("URL must contain a hostname.")
        if parts.username is not None or parts.password is not None:
            has_credentials = True
        else:
            has_credentials = False
        port = parts.port  # Raises ValueError for invalid ports.
    except ValueError as exc:
        if isinstance(exc, URLAnalysisError):
            raise
        raise URLAnalysisError("URL contains an invalid hostname or port.") from exc

    hostname = parts.hostname.rstrip(".").lower()
    if not hostname:
        raise URLAnalysisError("URL must contain a hostname.")

    ip_literal = None
    try:
        ip_literal = str(ipaddress.ip_address(hostname))
    except ValueError:
        # Validate IDNs through IDNA encoding. Do not claim this is a full PSL check.
        try:
            ascii_host = hostname.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise URLAnalysisError("Hostname cannot be normalized with IDNA.") from exc
        if len(ascii_host) > 253 or any(
            not label or len(label) > 63 for label in ascii_host.split(".")
        ):
            raise URLAnalysisError("Hostname labels have invalid lengths.")
        if any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
            for label in ascii_host.split(".")
        ):
            raise URLAnalysisError("Hostname contains invalid characters.")
        hostname = ascii_host

    # For display in netloc, always bracket IP literals in the normalized URL
    display_host = f"[{hostname}]" if ip_literal else hostname
    netloc = display_host
    if port is not None and not (
        (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    ):
        netloc = f"{display_host}:{port}"

    # Normalize path: remove dot segments and resolve double dots
    # Preserve trailing slash if present in original
    trailing_slash = parts.path.endswith("/") if parts.path else False
    if parts.path:
        path_parts = []
        for segment in parts.path.split("/"):
            if segment == "..":
                if path_parts:
                    path_parts.pop()
            elif segment and segment != ".":
                path_parts.append(segment)
        path = "/" + "/".join(path_parts) if path_parts else "/"
        if trailing_slash and not path.endswith("/"):
            path += "/"
    else:
        path = "/"

    normalized = urlunsplit((scheme, netloc, path, parts.query, parts.fragment))
    subdomain_depth = 0 if ip_literal else max(0, len(hostname.split(".")) - 2)
    signals: list[Signal] = []
    if ip_literal:
        signals.append(
            Signal(
                "ip_literal_host",
                "The URL uses an IP address instead of a domain name.",
                hostname,
                "medium",
            )
        )
    if port is not None and not (
        (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    ):
        signals.append(
            Signal("nonstandard_port", "The URL uses a non-default HTTP(S) port.", str(port), "low")
        )
    if has_credentials:
        signals.append(
            Signal(
                "embedded_credentials",
                "The URL authority contains user information.",
                "Username/password component present (value omitted).",
                "high",
            )
        )
    if hostname.startswith("xn--") or ".xn--" in hostname:
        signals.append(
            Signal(
                "punycode_hostname",
                "The hostname contains an IDNA punycode label.",
                hostname,
                "medium",
            )
        )
    if subdomain_depth >= 4:
        signals.append(
            Signal(
                "deep_subdomain",
                "The hostname contains multiple subdomain levels.",
                f"{subdomain_depth} label(s) before the final two labels; "
                "not a public-suffix calculation.",
                "low",
            )
        )
    if re.search(r"%(?:[0-9a-fA-F]{2})", parts.path + parts.query):
        signals.append(
            Signal(
                "percent_encoded_content",
                "The path or query contains percent-encoded bytes.",
                "Percent encoding found; it is common in benign URLs too.",
                "info",
            )
        )

    query_names = sorted({key for key, _ in parse_qsl(parts.query, keep_blank_values=True)})
    return {
        "original_url": original,
        "normalized_url": normalized,
        "scheme": scheme,
        "hostname": hostname,
        "registrable_domain": None,
        "ip_literal": ip_literal,
        "port": port or (80 if scheme == "http" else 443),
        "path": path,
        "query_parameter_names": query_names,
        "signals": [signal.to_dict() for signal in signals],
        "note": (
            "Signals are heuristics, not proof of maliciousness. "
            "The URL was not visited or resolved."
        ),
    }
