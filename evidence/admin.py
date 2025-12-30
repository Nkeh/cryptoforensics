from django.contrib import admin
from .models import Case, EvidenceFile, KeyPair, WrappedKey, AuditLog

# Register your models here.
admin.site.register(Case)
admin.site.register(EvidenceFile)
admin.site.register(KeyPair)
admin.site.register(WrappedKey)
admin.site.register(AuditLog)