FROM ubuntu:16.04
MAINTAINER Steve McQuaid, djstevemcquaid+docker@gmail.com

# Versioning/Docker image cache reset
ENV LAST_UPDATE=2016-09-03
ENV VERSION=0.0.1

RUN apt-get update && \
    apt-get upgrade -y

# Set the Timezone
RUN echo "US/Pacific-New" | tee /etc/timezone && \
    ln -fs /usr/share/zoneinfo/US/Pacific-New /etc/localtime && \
    dpkg-reconfigure -f noninteractive tzdata

# Set the locale for UTF-8 support
RUN echo en_US.UTF-8 UTF-8 >> /etc/locale.gen && \
    locale-gen && \
    update-locale LC_ALL=en_US.UTF-8 LANG=en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

# Install weechat, OTR, bitlbee
RUN apt-get -y install \
    python-potr \
    weechat \
    weechat-scripts \
    bitlbee 

# Install LE root cert
RUN apt-get -y install wget tar curl
RUN wget http://curl.haxx.se/download/curl-7.53.1.tar.gz
RUN mkdir /curl-7.53.1
RUN tar xzvf curl-7.53.1.tar.gz -C /
RUN curl-7.53.1/lib/mk-ca-bundle.pl

# Install Java
RUN apt-get -y install default-jre

# Install signal-cli
ENV VERSION="0.5.5"
RUN wget https://github.com/AsamK/signal-cli/releases/download/v"${VERSION}"/signal-cli-"${VERSION}".tar.gz
RUN tar xf signal-cli-"${VERSION}".tar.gz -C /opt
RUN ln -sf /opt/signal-cli-"${VERSION}"/bin/signal-cli /usr/local/bin/

# Add weechat-signal deps
RUN apt-get -y install \ 
    python-qrcode \
    python-pip \
    python-gtk2 \
    python-dbus
RUN pip install --upgrade pip
RUN pip install qrcode

# Install weechat-signal
RUN apt-get -y install git
RUN git clone https://github.com/thefinn93/signal-weechat.git
# RUN chmod o+r /signal-weechat/*
# RUN cp signal-weechat/signal.py /home/guest/.weechat/python/autoload/signal.py
# Either link to an existing device: /signal link or register a new account: /signal register +12024561414

# RUN echo "export TZ=US/Pacific" >> /etc/bash.bashrc
RUN echo "cp /signal-weechat/signal.py /home/guest/.weechat/python/autoload/signal.py" >> /etc/bash.bashrc
RUN echo "weechat" >> /etc/bash.bashrc

# Remove this for testing
RUN adduser --disabled-login --gecos '' guest
USER guest
WORKDIR /home/guest

RUN \
    # enable otr \
    \
    echo /python load /usr/share/weechat/python/otr.py >> config.txt && \
    echo /set weechat.bar.status.items "\"[time],[buffer_last_number],[buffer_plugin],[otr],buffer_number+:+buffer_name+(buffer_modes)+{buffer_nicklist_count}+buffer_zoom+buffer_filter,[lag],[hotlist],completion,scroll\"" >> config.txt && \
    \
    # Connect with SSL  \
    \
    echo /server add freenode chat.freenode.net >> config.txt && \
    echo /set irc.server.freenode.addresses \"chat.freenode.net/7000\" >> config.txt && \
    echo /set irc.server.freenode.ssl on >> config.txt && \
    echo /set weechat.network.gnutls_ca_file "/curl-7.53.1/lib/ca-bundle.crt" >> config.txt && \
    echo 

# Use config.txt only if no weechat configuration exists.
# If there is already a configuration in /home/guest/.weechat, ignore config.txt

ENTRYPOINT ["/bin/bash"]
