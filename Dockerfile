FROM python:3.11-slim

# libmagic1 is required by python-magic, which pycti pulls in for file type
# detection. Without it, importing pycti fails at runtime rather than at build.
RUN apt-get update && \
    apt-get install -y --no-install-recommends libmagic1 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependencies first, so a code change does not invalidate the pip layer.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# The whole package. `tools/` and `tests/` are deliberately NOT copied: they are
# development utilities and have no place in a runtime image.
COPY enrichment/ ./enrichment/

RUN useradd --no-create-home --shell /bin/false appuser

# AI_AUDIT_LOG defaults to /state/ai_audit.log in .env.example, and the durable
# audit trail is the whole point of pointing it at a mounted path. Create the
# directory and hand it to appuser here so a NAMED VOLUME inherits the right
# ownership on first mount.
#
# NOTE for BIND mounts: the host directory's ownership wins, so `-v ./state:/state`
# on a host directory owned by root will leave the container unable to write, and
# the symptom is an audit file that never appears. Either chown the host
# directory to the container's appuser uid, or use a named volume.
RUN mkdir -p /state && chown appuser:appuser /state
VOLUME ["/state"]

USER appuser

# Run as a module so the package's relative imports resolve. `-u` keeps stdout
# unbuffered, which matters because container logs are the only thing you have
# before the audit handler is attached.
CMD ["python", "-u", "-m", "enrichment.connector"]
