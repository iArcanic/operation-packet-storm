# Use the official latest Rust image as the base
FROM rust:latest

# Set the working directory inside the container
WORKDIR /usr/src/app

# Install libpcap-dev package
RUN apt-get update && apt-get install -y libpcap-dev

# Copy Cargo.toml first
COPY Cargo.toml ./

# Copy the rest of the source code into the container
COPY src ./src

# Rebuild the Rust application with the source code changes
RUN cargo build --release

# Set the command to run the Rust application
CMD ["./target/release/app"]

