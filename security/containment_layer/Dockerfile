# Driver image for the single-command SQ3 reproduction harness
# (security/containment_layer/reproduce.sh).
#
# This image does NOT run the experiment sandboxes itself. It contains the
# repository plus the docker CLI and talks to the HOST Docker daemon through
# the mounted /var/run/docker.sock, launching the six per-condition sibling
# containers (runc / hardened runc / gVisor) exactly as the official runner
# does on a prepared VPS. Host-level facilities (gVisor runsc runtime,
# AppArmor profile, nftables) must already be installed by prepare_vps.sh.
#
# Build from the repository root:
#   docker build -t vukzero-sq3-harness -f security/containment_layer/Dockerfile .
FROM python:3.12-slim

# nftables/iptables: the runner applies host egress policy from inside the
# driver, which works because reproduce.sh runs it with --network host.
# The static docker CLI talks to the host daemon via the mounted socket.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl nftables iptables \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-27.3.1.tgz \
       | tar -xz --strip-components=1 -C /usr/local/bin docker/docker \
    && docker --version

WORKDIR /repo

COPY requirements.txt /repo/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . /repo

# run_factorial_vps.sh falls back to $PYTHON_BIN when the repo has no .venv.
ENV PYTHON_BIN=python

ENTRYPOINT ["bash", "security/containment_layer/run_factorial_vps.sh"]
