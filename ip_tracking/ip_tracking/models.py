from __future__ import annotations
from django.db import models


class RequestLog(models.Model):
    ip_address = models.GenericIPAddressField(db_index=True)
    timestamp = models.DateTimeField(db_index=True)
    path = models.CharField(max_length=2048, db_index=True)
    country = models.CharField(max_length=128, null=True, blank=True)
    city = models.CharField(max_length=128, null=True, blank=True)
    is_sensitive = models.BooleanField(default=False, db_index=True)

    class Meta:
        indexes = [
            models.Index(fields=["timestamp", "ip_address"]),
            models.Index(fields=["ip_address", "is_sensitive", "timestamp"]),
        ]
        ordering = ["-timestamp"]

    def __str__(self) -> str:
        return f"{self.ip_address} {self.path} @ {self.timestamp.isoformat()}"


class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)

    def __str__(self) -> str:
        return self.ip_address


class SuspiciousIP(models.Model):
    ip_address = models.GenericIPAddressField(db_index=True)
    reason = models.TextField()
    flagged_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-flagged_at"]

    def __str__(self) -> str:
        return f"{self.ip_address} - {self.reason[:50]}"
