from django import forms
from .models import Case, EvidenceFile

class CaseForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput, help_text="Password to protect the private key")

    class Meta:
        model = Case
        fields = ['case_id', 'description']

class EvidenceUploadForm(forms.ModelForm):
    file = forms.FileField()

    class Meta:
        model = EvidenceFile
        fields = ['file_name']

class IntegrityCheckForm(forms.Form):
    case_id = forms.CharField(max_length=100)
    file_id = forms.CharField(max_length=100)
    file = forms.FileField()

class DecryptForm(forms.Form):
    case_id = forms.CharField(max_length=100)
    file_id = forms.CharField(max_length=100)
    private_key_pem = forms.CharField(widget=forms.Textarea)

class GetKeyForm(forms.Form):
    password = forms.CharField(widget=forms.PasswordInput)