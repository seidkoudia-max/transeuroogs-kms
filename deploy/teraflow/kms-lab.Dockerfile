FROM busybox:1.37
COPY kms /bin/kms
COPY start-kms.sh /bin/start-kms
USER 65532:65532
ENTRYPOINT ["/bin/sh", "/bin/start-kms"]
