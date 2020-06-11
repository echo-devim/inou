FROM ubuntu:18.04
# USER root

RUN apt update && apt -y install python3
COPY inou.py /bin
ENTRYPOINT ["python3", "/bin/inou.py"]
