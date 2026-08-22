FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl unzip nmap jq ca-certificates \
    libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libgdk-pixbuf-2.0-0 \
    libffi-dev shared-mime-info fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ProjectDiscovery recon/detection tools — prebuilt release binaries (same
# tools BB_Assist uses, minus its active-exploit set: no ffuf/dalfox/sqlmap/
# interactsh-client here, per this project's non-destructive scan boundary).
# Self-contained in the image on purpose — this container can't reach the
# user's local BB_Assist install, so everything it needs has to live here.
#
# Must run AFTER `pip install`: the Python `httpx` package (requirements.txt)
# installs its own console-script stub at /usr/local/bin/httpx, which
# silently overwrote this real Go binary when this step ran first — every
# scan's httpx-based tech-detect/HSTS check was then silently falling back
# to the plain-Python manual probe instead of the intended tool, with no
# error anywhere (tool_runner.is_available() only checks the file exists).
RUN set -eux; \
    for repo in projectdiscovery/subfinder projectdiscovery/dnsx projectdiscovery/httpx projectdiscovery/nuclei; do \
      name=$(basename "$repo"); \
      tag=$(curl -sL "https://api.github.com/repos/$repo/releases/latest" | jq -r .tag_name | sed 's/^v//'); \
      url="https://github.com/$repo/releases/download/v${tag}/${name}_${tag}_linux_amd64.zip"; \
      echo "Fetching $name $tag from $url"; \
      curl -sL "$url" -o "/tmp/$name.zip"; \
      unzip -o "/tmp/$name.zip" -d /usr/local/bin "$name"; \
      rm "/tmp/$name.zip"; \
      chmod +x "/usr/local/bin/$name"; \
    done

# Pre-fetch nuclei templates at build time so the first real scan isn't slow.
RUN nuclei -update-templates -silent || true

COPY . .
RUN mkdir -p /app/data

EXPOSE 8000
# --proxy-headers/--forwarded-allow-ips trust X-Forwarded-For from the
# immediate peer (Traefik on the docker network) so request.client.host —
# and CSRF/rate-limit IP detection — sees the real client, not Traefik's IP.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips=*"]
