# The openschc reference peer (MIT, https://github.com/openschc/openschc)
# at a fixed commit, with the driver in peer.py.
FROM python:3.12.10-slim
RUN pip install --no-cache-dir scapy==2.5.0 cbor2==5.6.5
ADD https://github.com/openschc/openschc/archive/58293f71daac24036dd28aa7b1a2a241536c6aea.tar.gz /tmp/openschc.tar.gz
RUN mkdir /opt/openschc && tar -xzf /tmp/openschc.tar.gz -C /opt/openschc --strip-components=1 && rm /tmp/openschc.tar.gz
COPY peer.py /opt/peer.py
ENV PYTHONPATH=/opt/openschc/src
WORKDIR /opt/openschc/src
CMD ["python", "-u", "/opt/peer.py"]
