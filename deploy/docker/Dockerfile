FROM golang:1.27.1-alpine3.24 AS build
WORKDIR /src
COPY go.mod ./
COPY src ./src
RUN CGO_ENABLED=0 go build -trimpath -o /out/kms ./src/cmd/kms && \
    CGO_ENABLED=0 go build -trimpath -o /out/test-pki ./src/cmd/test-pki && \
    mkdir /pki && chown 65532:65532 /pki

FROM scratch AS kms
WORKDIR /app
COPY --from=build /out/kms /bin/kms
COPY --from=build /out/test-pki /bin/test-pki
COPY --from=build --chown=65532:65532 /pki /pki
COPY deploy/config/local.json /app/deploy/config/local.json
USER 65532:65532
ENTRYPOINT ["/bin/kms"]

FROM python:3.14.7-alpine3.24 AS sae
WORKDIR /app
COPY emulator/sae/demo.py /app/demo.py
USER 65532:65532
ENTRYPOINT ["python3", "/app/demo.py"]
