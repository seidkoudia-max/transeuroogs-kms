ARG BASE
FROM ${BASE}
COPY teraflow/ /var/teraflow/device/service/drivers/transeuroogs/
COPY services/ /opt/transeuroogs-services/
