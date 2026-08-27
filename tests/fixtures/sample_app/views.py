"""Django/DRF surface for the profiling fixture.

NOT RUN — parsed only. Django expresses authorization three different ways, and
the fixture carries one of each so the extractor is exercised on all three.

Ground truth encoded here:
  ReportView    permission_classes = [IsAuthenticated]  -> enforcement="enforced"
  PublicView    permission_classes = [AllowAny]         -> enforcement="none" (explicit opt-out)
  BillingView   LoginRequiredMixin                      -> enforcement="enforced"
  LegacyView    nothing                                 -> enforcement="none"
"""
from django.contrib.auth.mixins import LoginRequiredMixin
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView


class ReportView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return {"reports": []}


class PublicView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        return {"ok": True}


class BillingView(LoginRequiredMixin, APIView):
    def post(self, request):
        return {"charged": True}


class LegacyView(APIView):
    """No permission_classes and no mixin — DRF falls back to project defaults,
    which is exactly the ambiguity the matrix should surface rather than guess."""

    def get(self, request):
        return {"legacy": True}
