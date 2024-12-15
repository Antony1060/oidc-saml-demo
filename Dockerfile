FROM debian:bookworm

WORKDIR /app

RUN apt-get update && apt-get install openssl ca-certificates -y

COPY ./target/release/oidc-saml-demo oidc-saml-demo

CMD ["/app/oidc-saml-demo"]
