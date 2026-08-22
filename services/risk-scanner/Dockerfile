FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl unzip nmap jq ca-certificates \
    libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libgdk-pixbuf-2.0-0 \
    libffi-dev shared-mime-info fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

# ProjectDiscovery recon/detection tools — prebuilt release binaries (same
# tools BB_Assist uses, minus its active-exploit set: no ffuf/dalfox/sqlmap/
# interactsh-client here, per this project's non-destructive scan boundary).
# Self-contained in the image on purpose — this container can't reach the
# user's local BB_Assist install, so everything it needs has to live here.
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

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p /app/data

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
