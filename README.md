# Digital Forensic Cryptography Tool

A Django-based web application for securely handling, storing, and verifying electronic evidence in simulated forensic investigations.

## Features

- **Ingest Evidence**: Upload and encrypt evidence files, generate SHA-256 hashes, and store securely.
- **Integrity Check**: Verify if a file matches its stored hash to detect tampering.
- **Decrypt Evidence**: Authorized decryption with integrity verification.
- **Case Management**: Organize evidence by cases.
- **User Authentication**: Multi-user support with role-based access.
- **Audit Logging**: Record all operations for chain-of-custody.

## Installation

1. Clone the repository.
2. Create a virtual environment: `python -m venv .venv`
3. Activate: `.venv\Scripts\activate` (Windows)
4. Install dependencies: `pip install -r requirements.txt`
5. Run migrations: `python manage.py migrate`
6. Create superuser: `python manage.py createsuperuser`
7. Run server: `python manage.py runserver`

## Usage

- Access the dashboard at `/`
- Create cases, ingest evidence, check integrity, decrypt.

## Security

- Uses Fernet for symmetric encryption.
- RSA for key wrapping.
- SHA-256 for hashing.
- Audit logs for all actions.

## Dependencies

- Django
- cryptography
- celery (for async tasks, optional)