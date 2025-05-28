FROM python:3.11-slim

RUN apt-get update --option Acquire::Retries=5 || true && \
    apt-get install -y --no-install-recommends \
    tcpdump \
    libpcap-dev \
    ca-certificates \
    wireshark-common \
    tshark \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

#Do dumpcap trong Docker không sử dụng được option -F pcapng nên cần phần bên dưới để chuyển option -F thành -n
RUN if [ -f /usr/bin/dumpcap ]; then \
        mv /usr/bin/dumpcap /usr/bin/dumpcap.real && \
        echo '#!/bin/bash' > /usr/bin/dumpcap && \
        echo 'args=()' >> /usr/bin/dumpcap && \
        echo 'i=0' >> /usr/bin/dumpcap && \
        echo 'while [ $i -lt $# ]; do' >> /usr/bin/dumpcap && \
        echo '    i=$((i+1))' >> /usr/bin/dumpcap && \
        echo '    arg="${!i}"' >> /usr/bin/dumpcap && \
        echo '    if [ "$arg" = "-F" ]; then' >> /usr/bin/dumpcap && \
        echo '        i=$((i+1))' >> /usr/bin/dumpcap && \
        echo '        args+=("-n")' >> /usr/bin/dumpcap && \
        echo '    else' >> /usr/bin/dumpcap && \
        echo '        args+=("$arg")' >> /usr/bin/dumpcap && \
        echo '    fi' >> /usr/bin/dumpcap && \
        echo 'done' >> /usr/bin/dumpcap && \
        echo 'exec /usr/bin/dumpcap.real "${args[@]}"' >> /usr/bin/dumpcap && \
        chmod +x /usr/bin/dumpcap; \
    fi

WORKDIR /app

RUN pip install --no-cache-dir \
    flask>=2.0.1 \
    markdown>=3.4.1 \
    markupsafe>=2.0.1 \
    scapy>=2.5.0 \
    autogen-agentchat>=0.2.0 \
    autogen-core>=0.2.0 \
    autogen-ext>=0.2.0 \
    python-dotenv>=1.0.0 \
    asyncio>=3.4.3 \
    openai>=1.0.0 \
    tiktoken>=0.5.0

COPY . .

RUN mkdir -p content log config

ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=run_me.py
ENV FLASK_ENV=production

RUN mkdir -p config && echo "capture_interface=\"wlp3s0\"\ncapture_duration=10\nmaximum_packets_capture=200\noutput_capture_file=\"content/captured_network.pcapng\"\nminimum_network_limit=\"1024\"\nmaximum_network_limit=\"8192\"" > config/system_config.txt

ENTRYPOINT ["python"]
CMD ["run_me.py"] 