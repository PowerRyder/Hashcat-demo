# GPU-enabled hashcat container for the Fernet-passphrase brute-force demo.
#
# Base image: NVIDIA's official CUDA *runtime* on Ubuntu 22.04 — ships
# libnvrtc, which hashcat's CUDA backend uses to JIT-compile kernels.
# The host's libcuda gets mounted in by NVIDIA Container Toolkit when
# `compute` capability is granted (the only one Docker Desktop on WSL2
# allows, which is why we're not using OpenCL here).
#
# We download hashcat from hashcat.net rather than installing the
# Ubuntu apt package. Why: the Debian/Ubuntu hashcat build is OpenCL-
# only (no CUDA backend), AND it depends on `pocl-opencl-icd` which
# auto-binds hashcat to a broken CPU-OpenCL implementation before the
# GPU is even checked. Upstream hashcat has the CUDA backend built in
# and doesn't depend on POCL.
#
# Build:  docker compose build       (from this folder)
# Run:    docker compose run --rm crack
FROM nvidia/cuda:12.4.1-runtime-ubuntu22.04

# Docker Desktop on Windows allows only `compute,utility`. Setting it
# explicitly avoids any "unsupported capabilities" error if the image
# layer above ever tries to widen the default.
ENV NVIDIA_VISIBLE_DEVICES=all
ENV NVIDIA_DRIVER_CAPABILITIES=compute,utility

# Pull hashcat 6.2.6 from upstream. The .7z is ~50 MB on disk, ~250 MB
# unpacked (kernel source files for every supported hash mode). The
# build tools (wget, p7zip) get purged after extraction to keep the
# final image lean.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        wget \
        p7zip-full \
        python3 \
    && wget -q https://hashcat.net/files/hashcat-6.2.6.7z -O /tmp/hashcat.7z \
    && 7z x -o/opt /tmp/hashcat.7z \
    && mv /opt/hashcat-6.2.6 /opt/hashcat \
    && ln -s /opt/hashcat/hashcat.bin /opt/hashcat/hashcat \
    && rm /tmp/hashcat.7z \
    && mkdir -p /opt/hashcat/wordlists \
    && wget -q -O /opt/hashcat/wordlists/rockyou.txt \
        https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt \
    && apt-get purge -y --auto-remove wget p7zip-full \
    && rm -rf /var/lib/apt/lists/*

# Put hashcat on PATH so `shutil.which('hashcat')` finds it. The
# binary discovers its own data files via /proc/self/exe, so calling
# it via the symlink works the same as calling it directly.
ENV PATH="/opt/hashcat:${PATH}"

# Create unversioned symlinks for the CUDA libraries hashcat needs.
# nvidia/cuda:*-runtime ships only versioned sonames (e.g.
# libnvrtc.so.12), but hashcat's CUDA backend does
# `dlopen("libnvrtc.so")` without a version. Without these symlinks,
# libcuda loads but NVRTC fails, the CUDA backend bails out, and
# hashcat reports "No OpenCL, HIP or CUDA compatible platform found".
RUN ln -sf /usr/local/cuda-12.4/targets/x86_64-linux/lib/libnvrtc.so.12 \
           /usr/local/cuda-12.4/targets/x86_64-linux/lib/libnvrtc.so \
    && ln -sf /usr/local/cuda-12.4/targets/x86_64-linux/lib/libnvrtc-builtins.so.12.4 \
              /usr/local/cuda-12.4/targets/x86_64-linux/lib/libnvrtc-builtins.so

# On Docker Desktop / WSL2 the Windows-side NVIDIA driver libraries
# (libcuda.so.1, libnvidia-ml.so.1, etc.) get mounted into the WSL2
# VM at `/usr/lib/wsl/lib/` and the container inherits the same mount
# path. `nvidia-smi` works without any extra config because it knows
# to look there. A generic dlopen("libcuda.so.1"), like hashcat's CUDA
# backend uses, does NOT — that path isn't on the default linker
# search list. Without this, hashcat reports "No CUDA compatible
# platform found" even though `nvidia-smi` inside the same container
# prints the GPU table correctly.
ENV LD_LIBRARY_PATH="/usr/lib/wsl/lib:/usr/lib/x86_64-linux-gnu:/usr/local/cuda/lib64:${LD_LIBRARY_PATH}"

WORKDIR /demo
COPY crack_fernet_passphrase.py .

# Default to launching the wrapper script. Compose passes -it so getpass
# works. Any extra args after `docker compose run --rm crack` are
# forwarded straight to the script (e.g. `--skip-wordlist`).
ENTRYPOINT ["python3", "/demo/crack_fernet_passphrase.py"]
