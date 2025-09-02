from __future__ import annotations
from django.core.management.base import BaseCommand, CommandError
from ip_tracking.models import BlockedIP


class Command(BaseCommand):
    help = "Add an IP address to the BlockedIP list."

    def add_arguments(self, parser):
        parser.add_argument("ip", type=str, help="IP address to block")

    def handle(self, *args, **options):
        ip = options["ip"].strip()
        if not ip:
            raise CommandError("Provide a valid IP address")
        obj, created = BlockedIP.objects.get_or_create(ip_address=ip)
        if created:
            self.stdout.write(self.style.SUCCESS(f"Blocked {ip}"))
        else:
            self.stdout.write(self.style.WARNING(f"{ip} is already blocked"))
