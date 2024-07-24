# Use the official latest Rust image as the base
FROM rust:latest

# Set the working directory inside the container
WORKDIR /usr/src/app

# Copy the Cargo.toml file first
COPY src/Cargo.toml ./

# Create a dummy src/main.rs to build dependencies and cache them
RUN mkdir src && echo "fn main() { println!(\"Hello, world!\"); }" > src/main.rs && cargo build --release

# Remove the dummy src/main.rs
RUN rm -rf src

# Copy the rest of the source code into the container
COPY src ./src

# Rebuild the Rust application with the source code changes
RUN cargo build --release

# Set the command to run the Rust application
CMD ["./target/release/app"]

