FROM rust:alpine

# Create app directory
WORKDIR /app

# Install app dependencies
COPY * ./
COPY .* ./

# Proto buffer dependencies
RUN apk update && apk add protobuf-dev

# Compile the binary
RUN cargo build --bin server --release

EXPOSE 4321

CMD [ "./target/release/server" ]