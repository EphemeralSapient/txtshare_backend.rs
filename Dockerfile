# FROM rust:alpine
FROM rust:slim-bookworm

# Create app directory
WORKDIR /app

# Install app dependencies
COPY proto proto/
COPY src src/
COPY .env .env
COPY build.rs build.rs
COPY example.env example.env
COPY Cargo.toml Cargo.toml
COPY Cargo.lock Cargo.lock

# Proto buffer dependencies
# RUN apk update && apk add protobuf-dev openssl-dev pkgconfig

# In debian
RUN apt-get update && apt-get install -y protobuf-compiler libprotobuf-dev libssl-dev pkg-config


# Compile the binary
RUN cargo build --bin server --release

# Ports
# Application's port
EXPOSE 4321
# Postgres external port
EXPOSE 5432


CMD [ "./target/release/server" ]