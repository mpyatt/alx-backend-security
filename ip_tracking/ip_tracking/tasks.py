from __future__ import annotations
import datetime as dt

from celery import shared_task
from django.utils import timezone
from django.db.models import Count

from ip_tracking.models import RequestLog, SuspiciousIP


@shared_task(bind=True, ignore_result=True)
def detect_anomalies(self):
    """
    Flags IPs that:
      - exceed 100 requests in the last hour, OR
      - accessed sensitive paths (/admin, /login, etc.)
    """
    now = timezone.now()
    one_hour_ago = now - dt.timedelta(hours=1)
    heavy_ips = (
        RequestLog.objects.filter(timestamp__gte=one_hour_ago)
        .values("ip_address")
        .annotate(n=Count("id"))
        .filter(n__gt=100)
    )

    for row in heavy_ips:
        ip = row["ip_address"]
        reason = f"High volume: {row['n']} requests in the last hour"
        SuspiciousIP.objects.get_or_create(ip_address=ip, reason=reason)

    sensitive_hits = (
        RequestLog.objects.filter(
            timestamp__gte=one_hour_ago, is_sensitive=True)
        .values("ip_address")
        .annotate(n=Count("id"))
        .order_by("-n")
    )
    for row in sensitive_hits:
        ip = row["ip_address"]
        reason = f"Accessed sensitive paths {row['n']} times in the last hour"
        SuspiciousIP.objects.get_or_create(ip_address=ip, reason=reason)
