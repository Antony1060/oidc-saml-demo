FROM debian:bookworm

WORKDIR /app

RUN apt-get update && apt-get install openssl -y

COPY ./target/release/oidc-saml-demo oidc-saml-demo

CMD ["bash", "-c", "/app/oidc-saml-demo"]