# Digital Forensic Cryptography Tool

A comprehensive Django-based web application designed for secure digital evidence handling in forensic investigations. This tool ensures the integrity, confidentiality, and authenticity of electronic evidence through advanced cryptographic operations, comprehensive audit logging, and strict chain-of-custody principles.

## Features

### 🔐 **Cryptographic Operations**
- **Symmetric Encryption**: AES via Fernet for fast, secure file encryption
- **Asymmetric Encryption**: RSA key pairs for secure key wrapping and distribution
- **Hash Verification**: SHA-256 hashing for tamper detection and integrity checks
- **Password Protection**: AES-encrypted private keys with PBKDF2 key derivation

### 📁 **Case Management**
- **Organized Storage**: Hierarchical directory structure for evidence files
- **Multi-Case Support**: Handle multiple concurrent investigations
- **User Isolation**: Each user manages their own cases and evidence

### 🔍 **Evidence Operations**
- **Ingest Evidence**: Upload and automatically encrypt files with integrity verification
- **Integrity Checking**: Verify file authenticity against stored hashes
- **Authorized Decryption**: Password-protected key retrieval for evidence access
- **Secure Downloads**: Direct file downloads with original filenames

### 📊 **Audit & Compliance**
- **Comprehensive Logging**: All actions logged with timestamps and user context
- **Chain of Custody**: Complete audit trail for forensic admissibility
- **Log Viewer**: Web interface for reviewing all logged activities
- **Detailed Log Inspection**: Drill-down into specific log entries

### 🎨 **User Interface**
- **Dark Professional Theme**: Sleek, forensic-appropriate dark interface
- **Responsive Design**: Clean, mobile-friendly layout
- **Intuitive Navigation**: Button-based navigation with clear workflows

## Architecture

### Security Model
- **Authentication**: Django's built-in user authentication system
- **Authorization**: User-based access control for cases and evidence
- **Encryption at Rest**: All sensitive data encrypted before storage
- **Secure Key Management**: Password-protected private keys with strong derivation

### Data Flow
1. **Case Creation**: Generate RSA key pair, encrypt private key with user password
2. **Evidence Ingestion**: Hash file, encrypt with symmetric key, wrap key with RSA public key
3. **Integrity Verification**: Compare uploaded file hash with stored hash
4. **Evidence Access**: Decrypt private key with password, unwrap symmetric key, decrypt file

### Directory Structure
```
evidence_store/
├── case_001/
│   ├── encrypted/     # Encrypted evidence files
│   ├── keys/         # Key storage (if needed)
│   ├── hashes/       # Hash files for verification
│   └── decrypted/    # Temporary decrypted files
└── case_002/
    └── ...
```

## Installation

### Prerequisites
- Python 3.8+
- pip package manager

### Setup Steps
1. **Clone Repository**
   ```bash
   git clone <repository-url>
   cd cryptoforensics
   ```

2. **Create Virtual Environment**
   ```bash
   python -m venv .venv
   .venv\Scripts\activate  # Windows
   # source .venv/bin/activate  # Linux/Mac
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Database Setup**
   ```bash
   python manage.py migrate
   ```

5. **Create Superuser**
   ```bash
   python manage.py createsuperuser
   ```

6. **Start Server**
   ```bash
   python manage.py runserver
   ```

7. **Access Application**
   - Open browser to `http://127.0.0.1:8000/`
   - Login with superuser credentials

## Usage Guide

### Getting Started
1. **Login** to the application
2. **Create a Case** with a unique ID and description
3. **Set a strong password** for private key protection

### Evidence Workflow

#### 1. Ingest Evidence
- Navigate to case details
- Click "Ingest Evidence"
- Upload file and provide filename
- System automatically:
  - Computes SHA-256 hash
  - Encrypts file with Fernet
  - Wraps encryption key with RSA
  - Stores encrypted file and metadata

#### 2. Check Integrity
- Upload the original file
- System compares hash with stored value
- Results show verification status

#### 3. Access Evidence
- Go to case details
- Click "Get Private Key"
- Enter case password to retrieve key
- Navigate to file details
- Paste key into decryption form
- Download decrypted file

### Log Management
- Access "View Logs" from dashboard
- Browse chronological audit trail
- Click "View Details" for full log information
- All actions are timestamped and user-attributed

## Security Considerations

### Key Protection
- Private keys are encrypted with user-provided passwords
- PBKDF2 with 100,000 iterations for key derivation
- AES encryption for key storage

### Access Control
- User authentication required for all operations
- Case ownership verification
- File access restricted to case owners

### Data Integrity
- SHA-256 hashing for tamper detection
- Hash verification on all decryption operations
- Audit logging for all sensitive operations

### Best Practices
- Use strong, unique passwords for each case
- Regularly backup encrypted evidence store
- Monitor audit logs for unauthorized access attempts
- Keep private keys secure and never share passwords

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard |
| `/create_case/` | POST | Create new case |
| `/case/<id>/` | GET | Case details |
| `/case/<id>/get_key/` | POST | Retrieve private key |
| `/case/<id>/ingest/` | POST | Upload evidence |
| `/file/<case>/<file>/` | GET/POST | File operations |
| `/download/<case>/<file>/` | GET | Download decrypted file |
| `/check_integrity/` | POST | Integrity verification |
| `/logs/` | GET | View audit logs |
| `/logs/<id>/` | GET | Log details |

## Dependencies

- **Django**: Web framework
- **cryptography**: Cryptographic operations
- **Celery**: Async task processing (optional)
- **django-storages**: Cloud storage support (optional)

## Configuration

### Environment Variables
```bash
# For production deployment
SECRET_KEY=your-secret-key-here
DEBUG=False
DATABASE_URL=postgresql://user:pass@host:port/db
```

### Logging Configuration
- Logs stored in `logs/forensic.log`
- Configurable log levels and formats
- Automatic log rotation recommended for production

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes with proper testing
4. Submit pull request with detailed description

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is designed for forensic and security research purposes. Users are responsible for compliance with applicable laws and regulations regarding digital evidence handling and cryptographic operations.