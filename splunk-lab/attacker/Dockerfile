FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# Osnovni paketi
RUN apt update && apt install -y \
    python3 \
    python3-pip \
    git \
    git-lfs \
    curl \
    unzip \
    && apt clean

# Instalacija git lfs-a
RUN git lfs install --skip-smudge

ENV PATH="/root/.local/bin:$PATH"

WORKDIR /opt

# Preuzimanje attack_data i security content repozitorija
RUN git clone https://github.com/splunk/attack_data.git

# Preuzimanje paralog generatora i skripte za slanje zapisa
RUN git clone --filter=blob:none --no-checkout https://github.com/ivanUkasKorac/paralog.git paralog && \
    cd paralog && \
    git sparse-checkout init --cone && \
    git sparse-checkout set data && \
    git checkout

# Instalacija python ovisnosti za attack_data/bin/replay.py
RUN python3 -m pip install --break-system-packages -r /opt/attack_data/bin/requirements.txt

WORKDIR /root
CMD ["/bin/bash"]