#!/bin/bash
if [ "$#" -ne 5 ]; then
    echo "usage: install.sh [dest_dir] [version] [channel] [target] [URL]"
    exit 1
fi

DEST_DIR="$1"
VERSION="$2"
CHANNEL="$3"
TARGET="$4"
URL="$5"

download_unpack_install() {
    PREFIX=$1
    if [ "$2" = true ] ; then
        TAR_FILE="$PREFIX-$VERSION-$CHANNEL-$TARGET.tar.xz"
    else
        TAR_FILE="$PREFIX-$VERSION-$CHANNEL.tar.xz"
    fi

    echo "Downloading $TAR_FILE from $URL/$TAR_FILE"
    TMP_DIR=".tmp.$PREFIX"
    curl -Lf --retry 3 -o "$TAR_FILE" "$URL/$TAR_FILE"
    mkdir $TMP_DIR
    tar -xf "$TAR_FILE" -C "$TMP_DIR" --strip-components=1
    rm "$TAR_FILE"
    "$TMP_DIR"/install.sh --verbose --prefix="" --destdir="$DEST_DIR"
    rm -rf $TMP_DIR
}

download_unpack_install "rust" true
download_unpack_install "rustc-dev" true
download_unpack_install "rust-dev" true
download_unpack_install "rust-src" false