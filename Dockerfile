# Production image for the platform API (Render runtime: docker).
#
# Why Docker: the native Python runtime cannot install system packages, so
# media scans in production ran without exiftool (image EXIF: GPS, serials)
# and tesseract (OCR of screenshots) — audit P4. This image ships both, plus
# git for repository scans and the libraries WeasyPrint needs for PDFs.
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      git libimage-exiftool-perl tesseract-ocr tesseract-ocr-eng \
      libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md alembic.ini ./
COPY opsec_scanner ./opsec_scanner
COPY opsec_platform ./opsec_platform
RUN pip install '.[platform]'

# Never run the API as root.
RUN useradd --create-home --uid 10001 app
USER app

EXPOSE 10000
# Render sets PORT; 10000 is its default.
CMD ["sh", "-c", "exec uvicorn opsec_platform.app.main:app --host 0.0.0.0 --port ${PORT:-10000}"]
