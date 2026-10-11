# The schc-over-sigfox reference peer (MIT,
# https://github.com/schc-over-sigfox/schc-over-sigfox) at a fixed commit,
# with the driver in peer.py.
FROM python:3.12.10-slim
RUN pip install --no-cache-dir requests==2.28.2
ADD https://github.com/schc-over-sigfox/schc-over-sigfox/archive/1ec0b723199f0b85a25aff04aaccd9d50cccf0ee.tar.gz /tmp/sos.tar.gz
RUN mkdir /opt/sos && tar -xzf /tmp/sos.tar.gz -C /opt/sos --strip-components=1 && rm /tmp/sos.tar.gz
COPY peer.py /opt/peer.py
ENV PYTHONPATH=/opt/sos
WORKDIR /opt/sos
CMD ["python", "-u", "/opt/peer.py"]
