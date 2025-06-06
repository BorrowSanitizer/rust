#!/bin/bash
if [ "$#" -ne 4 ]; then
    echo "usage: install.sh [dest_dir] [target] [URL]"
    exit 1
fi

DEST_DIR="$1"
TARGET="$2"
URL="$3"

download_unpack_install() {
    PREFIX=$1
    TAR_FILE="$PREFIX-$TARGET.tar.xz"
    echo "Downloading $TAR_FILE from $URL/$TAR_FILE"
    TMP_DIR=".tmp.$PREFIX"
    curl -Lf --retry 3 -o "$TAR_FILE" "$URL/$TAR_FILE"
    tar -xf "$TAR_FILE" -C "$TMP_DIR" --strip-components=1
    rm "$TAR_FILE"
    "$TMP_DIR"/install.sh --verbose --prefix="" --destdir="$DEST_DIR"
    rm -rf 
}
download_unpack_install "rust"
download_unpack_install "rustc-dev"
download_unpack_install "rust-dev"
download_unpack_install "rust-src"
rustup toolchain link bsan "$DEST_DIR"