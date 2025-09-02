from __future__ import annotations

from typing import Optional, Tuple

from django.conf import settings
from django.core.cache import cache
from django.http import HttpRequest, HttpResponseForbidden
from django.utils import timezone
from django.utils.deprecation import MiddlewareMixin

from .models import RequestLog, BlockedIP

GEO_CACHE_TTL = 60 * 60 * 24  # 24 hours
GEO_CACHE_PREFIX = "geoip:"
SENSITIVE_PATHS = getattr(
    settings,
    "IP_TRACKING_SENSITIVE_PATHS",
    ["/admin", "/login", "/accounts/login"],
)


def _client_ip(request: HttpRequest) -> str:
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        ip = xff.split(",")[0].strip()
        if ip:
            return ip
    return request.META.get("REMOTE_ADDR", "0.0.0.0")


def _geo_from_request(request: HttpRequest) -> Tuple[Optional[str], Optional[str]]:
    """
    Extract (country, city) from request.geolocation populated by
    django-ip-geolocation middleware. Handle different shapes safely.
    """
    geo = getattr(request, "geolocation", None)
    if not geo:
        return None, None

    country_val = None
    if hasattr(geo, "country"):
        c = getattr(geo, "country")
        if isinstance(c, dict):
            country_val = c.get("name") or c.get("code")
        else:
            country_val = str(c)
    elif isinstance(geo, dict):
        c = geo.get("country")
        if isinstance(c, dict):
            country_val = c.get("name") or c.get("code")
        elif c:
            country_val = str(c)

    if hasattr(geo, "city"):
        city_val = getattr(geo, "city")
    elif isinstance(geo, dict):
        city_val = geo.get("city")
    else:
        city_val = None

    return (country_val or None), (city_val or None)


def _geo_lookup(request: HttpRequest, ip: str) -> Tuple[Optional[str], Optional[str]]:
    """
    24h IP-based cache wrapper. Prefer using data already computed by
    django-ip-geolocation (request.geolocation). Never raises.
    """
    cache_key = f"{GEO_CACHE_PREFIX}{ip}"
    cached = cache.get(cache_key)
    if cached:
        return cached.get("country"), cached.get("city")

    country, city = _geo_from_request(request)

    cache.set(cache_key, {"country": country, "city": city}, GEO_CACHE_TTL)
    return country, city


class IPTrackingMiddleware(MiddlewareMixin):
    """
    - Blocks requests whose IP is present in BlockedIP (403).
    - Logs each request with IP, timestamp, path, and geolocation (country/city).
    """

    def process_request(self, request: HttpRequest):
        ip = _client_ip(request)

        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("Forbidden: Your IP has been blocked.")

        country, city = _geo_lookup(request, ip)

        try:
            RequestLog.objects.create(
                ip_address=ip,
                timestamp=timezone.now(),
                path=request.path,
                country=country,
                city=city,
                is_sensitive=any(request.path.startswith(p)
                                 for p in SENSITIVE_PATHS),
            )
        except Exception:
            pass

        return None
