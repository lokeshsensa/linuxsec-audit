# LinuxSecAudit Backend

FastAPI backend and defensive auditing engine for LinuxSecAudit.

## Quickstart

```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run CLI audit
python -m app.cli audit --demo

# Start API server
uvicorn app.main:app --reload --port 8000
```

## Running Tests

```bash
pytest -v
```

## API Docs

With the backend running, open http://127.0.0.1:8000/docs for Swagger UI.
