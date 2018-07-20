ARG COREOS_VERSION=1745.7.0
ARG PF_RING_VERSION=7.2.0-stable

FROM bugroger/coreos-developer:${COREOS_VERSION} as BUILD
LABEL maintainer "ntop.org"

ARG COREOS_VERSION
ARG PF_RING_VERSION

RUN emerge-gitclone
RUN . /usr/share/coreos/release && \
    git -C /var/lib/portage/coreos-overlay checkout build-${COREOS_RELEASE_VERSION%%.*}
RUN emerge -gKv coreos-sources > /dev/null
RUN cp /usr/lib64/modules/$(ls /usr/lib64/modules)/build/.config /usr/src/linux/
RUN make -C /usr/src/linux modules_prepare

WORKDIR /tmp
RUN git clone https://github.com/ntop/PF_RING.git && \
    cd PF_RING/kernel && make && cd ../.. &&\
    cd PF_RING/drivers/intel && make && cd ../../..
RUN mkdir -p /opt/pf_ring/${PF_RING_VERSION}/${COREOS_VERSION}/lib64/modules/$(ls /usr/lib64/modules)/kernel/net/pf_ring
RUN find /tmp/PF_RING -name "*.ko" -exec cp {} /opt/pf_ring/${PF_RING_VERSION}/${COREOS_VERSION}/lib64/modules/$(ls /usr/lib64/modules)/kernel/net/pf_ring \; 

# Create a clean transport image containing only the driver

FROM alpine 
LABEL maintainer "ntop.org"

ARG COREOS_VERSION
ARG PF_RING_VERSION

ENV COREOS_VERSION $COREOS_VERSION
ENV PF_RING_VERSION $PF_RING_VERSION

COPY --from=BUILD /opt/pf_ring /opt/pf_ring

COPY run.sh /
COPY install.sh /

ENTRYPOINT ["/run.sh"]
