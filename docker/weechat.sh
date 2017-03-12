#!/bin/bash

docker build . -t signal-weechat

# docker run -v "$(pwd)"/.weechat:/home/guest/.weechat -it signal-weechat:latest

docker run -v "$(pwd)"/.weechat:/home/guest/.weechat -v "$(dirname $(pwd))":/signal-weechat -it signal-weechat:latest

