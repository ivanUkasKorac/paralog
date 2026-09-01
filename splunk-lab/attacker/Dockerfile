FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# Osnovni paketi
RUN apt update && apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    git-lfs \
    curl \
    build-essential \
    libssl-dev \
    libffi-dev \
    unzip \
    && apt clean

# Instalacija git lfs-a i poetry-a
RUN git lfs install --skip-smudge

RUN curl -sSL https://install.python-poetry.org/ | python3 -

ENV PATH="/root/.local/bin:$PATH"

WORKDIR /opt

# Preuzimanje attack_data i security content repozitorija
RUN git clone https://github.com/splunk/attack_data.git
RUN git clone https://github.com/splunk/security_content.git

# Preuzimanje paralog generatora i skripte za slanje zapisa
RUN git clone --filter=blob:none --no-checkout https://github.com/ivanUkasKorac/paralog.git paralog && \
    cd thesis-repo && \
    git sparse-checkout init --cone && \
    git sparse-checkout set data && \
    git checkout

# Instalacija python ovisnosti za attack_data/bin/replay.py
RUN python3 -m pip install --break-system-packages -r /opt/attack_data/bin/requirements.txt

WORKDIR /opt/attack_data/total_replay
RUN poetry self add poetry-plugin-shell || true

RUN poetry lock
RUN poetry install

# Dodaj putanje repozitorija u config.yml
RUN sed -i 's|security_content_detection_path:.*|security_content_detection_path: /opt/security_content/detections|' /opt/attack_data/total_replay/configuration/config.yml && \
    sed -i 's|attack_data_dir_path:.*|attack_data_dir_path: /opt/attack_data|' /opt/attack_data/total_replay/configuration/config.yml

WORKDIR /root
CMD ["/bin/bash"]