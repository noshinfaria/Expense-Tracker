# # Use Python 3.8 as the base image
# FROM python:3.8-slim

# # Install build dependencies and curl
# RUN apt-get update && apt-get install -y \
#     build-essential \
#     python3-dev \
#     curl \
#     && apt-get clean \
#     && rm -rf /var/lib/apt/lists/*

# # Install Rust using rustup
# RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain stable -y

# # Set the environment variable for the Rust installation
# ENV PATH="/root/.cargo/bin:${PATH}"

# # Verify Rust version
# RUN rustc --version

# ENTRYPOINT [ "pdm", "run"]

# # Install PDM
# RUN pip install pdm

# # Set working directory inside the container
# WORKDIR /app

# # Copy PDM files (ensure `pdm.lock` and `pyproject.toml` are included)
# COPY pyproject.toml pdm.lock ./

# # Install dependencies using PDM
# RUN pdm sync -v

# # Copy the rest of the project files
# COPY . .

# Use Python 3.8 as the base image
FROM python:3.8-slim

# Install build dependencies and curl
RUN apt-get update && apt-get install -y \
    build-essential \
    python3-dev \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Rust using rustup
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain stable -y

# Set the environment variable for the Rust installation
ENV PATH="/root/.cargo/bin:${PATH}"

# Verify Rust version
RUN rustc --version

# Install PDM
RUN pip install pdm

# Set working directory inside the container
WORKDIR /app

# Copy PDM files (ensure `pyproject.toml` and `pdm.lock` are included)
COPY pyproject.toml pdm.lock ./

# Install dependencies using PDM
RUN pdm install --prod

# Copy the rest of the project files
COPY . .

# Set the entrypoint for the application
ENTRYPOINT ["pdm", "run"]

# Command to run the Flask app
CMD ["python", "run.py"]
