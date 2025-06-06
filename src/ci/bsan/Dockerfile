FROM ubuntu:latest AS base
ARG URL
ARG TARGET
ARG VERSION
ENV DEBIAN_FRONTEND=noninteractive
RUN apt update \
    && apt upgrade -y \
    && apt install curl xz-utils -y
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > rustup.sh\
    && chmod +x rustup.sh \
    && ./rustup.sh -y --default-toolchain none \
    && rm rustup.sh
ENV PATH="/root/.cargo/bin:${PATH}"

FROM base AS download
COPY install.sh .
RUN ./install.sh /root/.rustup/toolchains/bsan ${VERSION} dev ${TARGET} ${URL}

FROM base AS final 
COPY --from=download /root/.rustup/toolchains/bsan /root/.rustup/toolchains/bsan
RUN rustup default bsan && rustc -vV
