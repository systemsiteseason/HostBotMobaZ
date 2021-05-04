FROM buildpack-deps:bullseye AS base

RUN apt-get update && \
    apt-get install --no-install-recommends -y \
        cmake \
    && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /build

COPY . .

RUN cd StormLib && \
    mkdir build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_DYNAMIC_MODULE=1 .. && \
    make -j$(nproc) && make install && \
    cd ../.. && rm -rf StormLib

RUN cd bncsutil/src/bncsutil && \
    make -j$(nproc) && make install && \
    cd ../../.. && rm -rf bncsutil

RUN make -j$(nproc) && make install

WORKDIR /aura

COPY ip-to-country.csv ip-to-country.csv

CMD ["aura++", "-f"]