#!/bin/sh
# Nautilus script: "Scripts > 67zip - Extract here"
for f in "$@"; do 67zip --extract-here "$f"; done
