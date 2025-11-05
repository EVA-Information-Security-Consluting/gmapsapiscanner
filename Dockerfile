FROM python:3-alpine AS eva_gmaps_scanner
RUN mkdir -p /opt/html
WORKDIR /opt/html
COPY eva_gmaps_scanner.py /opt/eva_gmaps_scanner.py
RUN pip install requests
ENTRYPOINT ["/usr/local/bin/python", "/opt/eva_gmaps_scanner.py", "--api-key"]
