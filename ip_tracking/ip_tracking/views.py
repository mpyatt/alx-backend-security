from __future__ import annotations

from django.contrib.auth import authenticate, login
from django.http import HttpRequest, HttpResponse, JsonResponse
from django_ratelimit.decorators import ratelimit

AUTH_LIMIT = "10/m"
ANON_LIMIT = "5/m"

try:
    from ipware import get_client_ip  # django-ipware

    def _key_by_ip(request: HttpRequest) -> str:
        ip, _routable = get_client_ip(request)
        return ip or "0.0.0.0"
except Exception:
    def _key_by_ip(request: HttpRequest) -> str:
        xff = request.META.get("HTTP_X_FORWARDED_FOR")
        if xff:
            return xff.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR", "0.0.0.0")


def _dynamic_rate(request: HttpRequest) -> str:
    return AUTH_LIMIT if getattr(request, "user", None) and request.user.is_authenticated else ANON_LIMIT


@ratelimit(key=_key_by_ip, rate=_dynamic_rate, method=["POST"], block=True)
def login_view(request: HttpRequest) -> HttpResponse:
    if request.method != "POST":
        return JsonResponse({"detail": "Use POST"}, status=405)

    username = request.POST.get("username")
    password = request.POST.get("password")
    user = authenticate(request, username=username, password=password)
    if user is None:
        return JsonResponse({"detail": "Invalid credentials"}, status=401)

    login(request, user)
    return JsonResponse({"detail": "Logged in"})
