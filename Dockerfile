FROM alpine:3.24

RUN apk add --no-cache \
        build-base \
        meson \
        ninja \
        pkgconfig \
        openssl-dev

WORKDIR /src
COPY . .

RUN meson setup build -Dopenssl=enabled -Dexamples=enabled \
    && meson compile -C build