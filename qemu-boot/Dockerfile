FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
	qemu-system-arm \
  qemu-system-aarch64 \
	ca-certificates \
	iproute2 \
	tcpdump \
	make \
  build-essential \
  gcc-aarch64-linux-gnu \
	vim \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /work
