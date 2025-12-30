from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class Case(models.Model):
    case_id = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.case_id

class EvidenceFile(models.Model):
    case = models.ForeignKey(Case, on_delete=models.CASCADE)
    file_name = models.CharField(max_length=255)
    file_id = models.CharField(max_length=100, unique=True)
    original_path = models.CharField(max_length=500, blank=True)
    encrypted_path = models.CharField(max_length=500)
    hash_value = models.CharField(max_length=64)  # SHA-256
    status = models.CharField(max_length=50, default='ingested')

    def __str__(self):
        return f"{self.file_name} ({self.file_id})"

class KeyPair(models.Model):
    case = models.ForeignKey(Case, on_delete=models.CASCADE)
    private_key = models.TextField()  # Encrypted or PEM
    public_key = models.TextField()   # PEM

    def __str__(self):
        return f"KeyPair for {self.case.case_id}"

class WrappedKey(models.Model):
    evidence_file = models.ForeignKey(EvidenceFile, on_delete=models.CASCADE)
    wrapped_key = models.BinaryField()

    def __str__(self):
        return f"Wrapped key for {self.evidence_file.file_id}"

class AuditLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    action = models.CharField(max_length=100)
    timestamp = models.DateTimeField(default=timezone.now)
    details = models.TextField()

    def __str__(self):
        return f"{self.user.username} at {self.timestamp} - {self.action}"
