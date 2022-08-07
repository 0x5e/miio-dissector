#!/bin/sh

DIR="$HOME/.config/wireshark/plugins" \
  && mkdir -p $DIR \
  && curl -sSL  https://raw.githubusercontent.com/0x5e/miio-dissector/main/miio.lua > $DIR/miio.lua \
  && echo "Installation complete."
