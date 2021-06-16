#!/bin/sh

go test -c ./... -o goxdpfw.test

sudo ./goxdpfw.test "$@"

rm goxdpfw.test