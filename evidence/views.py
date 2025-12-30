from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse
from django.urls import reverse
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from .models import Case, EvidenceFile, KeyPair, WrappedKey, AuditLog
from .forms import CaseForm, EvidenceUploadForm, IntegrityCheckForm, DecryptForm, GetKeyForm
from .utils import *
import os
import uuid

@login_required
def dashboard(request):
    cases = Case.objects.filter(created_by=request.user)
    return render(request, 'evidence/dashboard.html', {'cases': cases})

@login_required
def create_case(request):
    if request.method == 'POST':
        form = CaseForm(request.POST)
        if form.is_valid():
            password = form.cleaned_data['password']
            case = form.save(commit=False)
            case.created_by = request.user
            case.save()
            # Generate keys
            private_key, public_key = generate_rsa_keypair()
            private_pem = serialize_private_key(private_key)
            public_pem = serialize_public_key(public_key)
            # Encrypt private key
            encrypted_private = encrypt_text(private_pem, password)
            KeyPair.objects.create(
                case=case,
                private_key=encrypted_private.hex(),  # Store as hex
                public_key=public_pem
            )
            AuditLog.objects.create(user=request.user, action='create_case', details=f'Created case {case.case_id}')
            messages.success(request, 'Case created successfully.')
            return redirect('dashboard')
    else:
        form = CaseForm()
    return render(request, 'evidence/create_case.html', {'form': form})

@login_required
def ingest_evidence(request, case_id):
    case = get_object_or_404(Case, case_id=case_id, created_by=request.user)
    if request.method == 'POST':
        form = EvidenceUploadForm(request.POST, request.FILES)
        if form.is_valid():
            file = request.FILES['file']
            file_id = str(uuid.uuid4())
            file_name = form.cleaned_data['file_name']

            # Create directories
            case_dir = os.path.join('evidence_store', case_id)
            encrypted_dir = os.path.join(case_dir, 'encrypted')
            keys_dir = os.path.join(case_dir, 'keys')
            hashes_dir = os.path.join(case_dir, 'hashes')
            os.makedirs(encrypted_dir, exist_ok=True)
            os.makedirs(keys_dir, exist_ok=True)
            os.makedirs(hashes_dir, exist_ok=True)

            # Save original file temporarily
            original_path = os.path.join(case_dir, f'{file_id}_original')
            with open(original_path, 'wb') as f:
                for chunk in file.chunks():
                    f.write(chunk)

            # Compute hash
            hash_value = compute_hash(original_path)

            # Get keypair
            keypair = KeyPair.objects.get(case=case)
            public_key = load_public_key(keypair.public_key)

            # Generate symmetric key
            sym_key = generate_symmetric_key()

            # Encrypt file
            encrypted_path = os.path.join(encrypted_dir, f'{file_id}.enc')
            encrypt_file(original_path, encrypted_path, sym_key)

            # Wrap key
            wrapped_key = wrap_key(sym_key, public_key)

            # Save hash
            hash_path = os.path.join(hashes_dir, f'{file_id}.hash')
            with open(hash_path, 'w') as f:
                f.write(hash_value)

            # Save to DB
            evidence = EvidenceFile.objects.create(
                case=case,
                file_name=file_name,
                file_id=file_id,
                original_path=original_path,
                encrypted_path=encrypted_path,
                hash_value=hash_value
            )
            WrappedKey.objects.create(evidence_file=evidence, wrapped_key=wrapped_key)

            # Remove original
            os.remove(original_path)

            AuditLog.objects.create(user=request.user, action='ingest_evidence', details=f'Ingested {file_name} in {case_id}')
            messages.success(request, 'Evidence ingested successfully.')
            return redirect('case_detail', case_id=case_id)
    else:
        form = EvidenceUploadForm()
    return render(request, 'evidence/ingest.html', {'form': form, 'case': case})

@login_required
def check_integrity(request):
    if request.method == 'POST':
        form = IntegrityCheckForm(request.POST, request.FILES)
        if form.is_valid():
            case_id = form.cleaned_data['case_id']
            file_id = form.cleaned_data['file_id']
            uploaded_file = form.cleaned_data['file']
            case = get_object_or_404(Case, case_id=case_id, created_by=request.user)
            evidence = get_object_or_404(EvidenceFile, case=case, file_id=file_id)
            # Save uploaded file temporarily
            temp_path = f'temp_{file_id}'
            with open(temp_path, 'wb') as f:
                for chunk in uploaded_file.chunks():
                    f.write(chunk)
            uploaded_hash = compute_hash(temp_path)
            os.remove(temp_path)
            if uploaded_hash == evidence.hash_value:
                result = 'Integrity verified: File matches the stored hash.'
            else:
                result = 'Integrity compromised: File does not match the stored hash.'
            AuditLog.objects.create(user=request.user, action='check_integrity', details=f'Checked {file_id} in {case_id}: {result}')
            return render(request, 'evidence/check_result.html', {'result': result, 'evidence': evidence})
    else:
        form = IntegrityCheckForm()
    return render(request, 'evidence/check_integrity.html', {'form': form})

@login_required
def decrypt_evidence(request):
    if request.method == 'POST':
        form = DecryptForm(request.POST)
        if form.is_valid():
            case_id = form.cleaned_data['case_id']
            file_id = form.cleaned_data['file_id']
            private_key_pem = form.cleaned_data['private_key_pem']
            case = get_object_or_404(Case, case_id=case_id, created_by=request.user)
            evidence = get_object_or_404(EvidenceFile, case=case, file_id=file_id)
            wrapped_key_obj = get_object_or_404(WrappedKey, evidence_file=evidence)
            try:
                private_key = load_private_key(private_key_pem)
            except Exception as e:
                result = f'Invalid private key: {e}'
                AuditLog.objects.create(user=request.user, action='decrypt_evidence', details=f'Failed to load private key for {file_id} in {case_id}: {e}')
                return render(request, 'evidence/decrypt_result.html', {'result': result})
            try:
                sym_key = unwrap_key(wrapped_key_obj.wrapped_key, private_key)
            except Exception as e:
                result = f'Failed to unwrap key: {e}'
                AuditLog.objects.create(user=request.user, action='decrypt_evidence', details=f'Failed to unwrap key for {file_id} in {case_id}: {e}')
                return render(request, 'evidence/decrypt_result.html', {'result': result})
            if not os.path.exists(evidence.encrypted_path):
                result = 'Encrypted file not found.'
                AuditLog.objects.create(user=request.user, action='decrypt_evidence', details=f'Encrypted file not found for {file_id} in {case_id}')
                return render(request, 'evidence/decrypt_result.html', {'result': result})
            try:
                decrypted_dir = os.path.join('evidence_store', case_id, 'decrypted')
                os.makedirs(decrypted_dir, exist_ok=True)
                decrypted_path = os.path.join(decrypted_dir, f'{file_id}_decrypted')
                decrypt_file(evidence.encrypted_path, decrypted_path, sym_key)
            except Exception as e:
                result = f'Failed to decrypt file: {e}'
                AuditLog.objects.create(user=request.user, action='decrypt_evidence', details=f'Failed to decrypt file {file_id} in {case_id}: {e}')
                return render(request, 'evidence/decrypt_result.html', {'result': result})
            # Verify hash
            try:
                decrypted_hash = compute_hash(decrypted_path)
            except Exception as e:
                result = f'Failed to compute hash of decrypted file: {e}'
                os.remove(decrypted_path)
                AuditLog.objects.create(user=request.user, action='decrypt_evidence', details=f'Failed to hash decrypted file {file_id} in {case_id}: {e}')
                return render(request, 'evidence/decrypt_result.html', {'result': result})
            if decrypted_hash == evidence.hash_value:
                result = f'Decryption successful. File saved to {decrypted_path}'
            else:
                print(decrypted_hash, evidence.hash_value)
                result = 'Decryption failed: Hash mismatch.'
                os.remove(decrypted_path)
            AuditLog.objects.create(user=request.user, action='decrypt_evidence', details=f'Decrypted {file_id} in {case_id}: {result}')
    else:
        form = DecryptForm()
    return render(request, 'evidence/decrypt_evidence.html', {'form': form})

@login_required
def case_detail(request, case_id):
    case = get_object_or_404(Case, case_id=case_id, created_by=request.user)
    evidences = EvidenceFile.objects.filter(case=case)
    keypair = KeyPair.objects.filter(case=case).first()
    return render(request, 'evidence/case_detail.html', {'case': case, 'evidences': evidences, 'keypair': keypair})

@login_required
def get_key(request, case_id):
    case = get_object_or_404(Case, case_id=case_id, created_by=request.user)
    keypair = get_object_or_404(KeyPair, case=case)
    if request.method == 'POST':
        form = GetKeyForm(request.POST)
        if form.is_valid():
            password = form.cleaned_data['password']
            try:
                encrypted_private = bytes.fromhex(keypair.private_key)
                private_pem = decrypt_text(encrypted_private, password)
                AuditLog.objects.create(user=request.user, action='get_key', details=f'Retrieved private key for case {case_id}')
                return render(request, 'evidence/get_key.html', {'case': case, 'private_key': private_pem, 'form': form})
            except Exception as e:
                messages.error(request, f'Invalid password: {e}')
    else:
        form = GetKeyForm()
    return render(request, 'evidence/get_key.html', {'case': case, 'form': form})

@login_required
def file_detail(request, case_id, file_id):
    case = get_object_or_404(Case, case_id=case_id, created_by=request.user)
    evidence = get_object_or_404(EvidenceFile, case=case, file_id=file_id)
    keypair = KeyPair.objects.filter(case=case).first()
    wrapped_key_obj = get_object_or_404(WrappedKey, evidence_file=evidence)
    check_form = IntegrityCheckForm(initial={'case_id': case_id, 'file_id': file_id})
    decrypt_form = DecryptForm(initial={'case_id': case_id, 'file_id': file_id})
    if request.method == 'POST':
        if 'check' in request.POST:
            check_form = IntegrityCheckForm(request.POST, request.FILES)
            if check_form.is_valid():
                uploaded_file = check_form.cleaned_data['file']
                temp_path = f'temp_{file_id}'
                with open(temp_path, 'wb') as f:
                    for chunk in uploaded_file.chunks():
                        f.write(chunk)
                uploaded_hash = compute_hash(temp_path)
                os.remove(temp_path)
                if uploaded_hash == evidence.hash_value:
                    result = 'Integrity verified: File matches the stored hash.'
                else:
                    result = 'Integrity compromised: File does not match the stored hash.'
                AuditLog.objects.create(user=request.user, action='check_integrity', details=f'Checked {file_id} in {case_id}: {result}')
                return render(request, 'evidence/file_detail.html', {'evidence': evidence, 'case': case, 'keypair': keypair, 'check_form': check_form, 'decrypt_form': decrypt_form, 'check_result': result})
        elif 'decrypt' in request.POST:
            decrypt_form = DecryptForm(request.POST)
            if decrypt_form.is_valid():
                private_key_pem = decrypt_form.cleaned_data['private_key_pem']
                try:
                    private_key = load_private_key(private_key_pem)
                except Exception as e:
                    result = f'Invalid private key: {e}'
                    AuditLog.objects.create(user=request.user, action='decrypt_evidence', details=f'Failed to load private key for {file_id} in {case_id}: {e}')
                    return render(request, 'evidence/file_detail.html', {'evidence': evidence, 'case': case, 'keypair': keypair, 'check_form': check_form, 'decrypt_form': decrypt_form, 'decrypt_result': result})
                try:
                    sym_key = unwrap_key(wrapped_key_obj.wrapped_key, private_key)
                except Exception as e:
                    result = f'Failed to unwrap key: {e}'
                    AuditLog.objects.create(user=request.user, action='decrypt_evidence', details=f'Failed to unwrap key for {file_id} in {case_id}: {e}')
                    return render(request, 'evidence/file_detail.html', {'evidence': evidence, 'case': case, 'keypair': keypair, 'check_form': check_form, 'decrypt_form': decrypt_form, 'decrypt_result': result})
                if not os.path.exists(evidence.encrypted_path):
                    result = 'Encrypted file not found.'
                    AuditLog.objects.create(user=request.user, action='decrypt_evidence', details=f'Encrypted file not found for {file_id} in {case_id}')
                    return render(request, 'evidence/file_detail.html', {'evidence': evidence, 'case': case, 'keypair': keypair, 'check_form': check_form, 'decrypt_form': decrypt_form, 'decrypt_result': result})
                try:
                    decrypted_dir = os.path.join('evidence_store', case_id, 'decrypted')
                    os.makedirs(decrypted_dir, exist_ok=True)
                    decrypted_path = os.path.join(decrypted_dir, f'{file_id}_decrypted')
                    decrypt_file(evidence.encrypted_path, decrypted_path, sym_key)
                except Exception as e:
                    result = f'Failed to decrypt file: {e}'
                    AuditLog.objects.create(user=request.user, action='decrypt_evidence', details=f'Failed to decrypt file {file_id} in {case_id}: {e}')
                    return render(request, 'evidence/file_detail.html', {'evidence': evidence, 'case': case, 'keypair': keypair, 'check_form': check_form, 'decrypt_form': decrypt_form, 'decrypt_result': result})
                # Verify hash
                try:
                    decrypted_hash = compute_hash(decrypted_path)
                except Exception as e:
                    result = f'Failed to compute hash of decrypted file: {e}'
                    if os.path.exists(decrypted_path):
                        os.remove(decrypted_path)
                    AuditLog.objects.create(user=request.user, action='decrypt_evidence', details=f'Failed to hash decrypted file {file_id} in {case_id}: {e}')
                    return render(request, 'evidence/file_detail.html', {'evidence': evidence, 'case': case, 'keypair': keypair, 'check_form': check_form, 'decrypt_form': decrypt_form, 'decrypt_result': result})
                print(f"Decrypted hash: {decrypted_hash}")
                print(f"Stored hash: {evidence.hash_value}")
                print(f"Decrypted file exists: {os.path.exists(decrypted_path)}")
                if os.path.exists(decrypted_path):
                    print(f"Decrypted file size: {os.path.getsize(decrypted_path)}")
                if decrypted_hash == evidence.hash_value:
                    url = reverse('download_decrypted', args=[case_id, file_id])
                    result = f'Decryption successful. File hash: {decrypted_hash}. <a href="{url}">Download file</a>'
                else:
                    result = f'Decryption failed: Hash mismatch. Decrypted: {decrypted_hash}, Stored: {evidence.hash_value}'
                    os.remove(decrypted_path)
                AuditLog.objects.create(user=request.user, action='decrypt_evidence', details=f'Decrypted {file_id} in {case_id}: {result}')
                return render(request, 'evidence/file_detail.html', {'evidence': evidence, 'case': case, 'keypair': keypair, 'check_form': check_form, 'decrypt_form': decrypt_form, 'decrypt_result': result})
    return render(request, 'evidence/file_detail.html', {'evidence': evidence, 'case': case, 'keypair': keypair, 'check_form': check_form, 'decrypt_form': decrypt_form})

@login_required
def download_decrypted(request, case_id, file_id):
    case = get_object_or_404(Case, case_id=case_id, created_by=request.user)
    evidence = get_object_or_404(EvidenceFile, case=case, file_id=file_id)
    decrypted_path = os.path.join('evidence_store', case_id, 'decrypted', f'{file_id}_decrypted')
    if not os.path.exists(decrypted_path):
        return HttpResponse('File not found', status=404)
    with open(decrypted_path, 'rb') as f:
        response = HttpResponse(f.read(), content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="{evidence.file_name}"'
        return response

@login_required
def view_logs(request):
    logs = AuditLog.objects.filter(user=request.user).order_by('-timestamp')
    return render(request, 'evidence/view_logs.html', {'logs': logs})


@login_required
def log_detail(request, log_id):
    log = get_object_or_404(AuditLog, id=log_id, user=request.user)
    return render(request, 'evidence/log_detail.html', {'log': log})
