# FileEngine LDAP Manager — tenant user/role admin API (FastAPI).
# Mirrors the convert_search_ai image conventions.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Install the package (src/ layout via pyproject).
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir .

# Runtime config is injected via environment (compose); never bake secrets in.
EXPOSE 8093
# Bind the API on all interfaces inside the container (reached only via the
# nginx /ldapadmin proxy); monitoring stays loopback-only per config.
CMD ["fileengine-ldap-manager"]
