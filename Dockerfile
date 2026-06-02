# wheels - под оффлайн деплой
FROM python:3.12-slim-bookworm

WORKDIR /opt/ars3arch

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iputils-ping \
        iproute2 \
        traceroute \
        curl \
        net-tools \
        gcc \
        python3-dev \
        libffi-dev \
        libssl-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*


COPY wheels /tmp/wheels


COPY requirements.txt .


RUN pip install --no-index --find-links /tmp/wheels -r requirements.txt && \
    rm -rf /tmp/wheels


COPY analyzer ./analyzer
COPY cli ./cli
COPY modules ./modules
COPY runner ./runner
COPY config ./config
COPY tools ./tools


RUN chmod +x cli/cli.py


CMD ["/bin/bash"]
