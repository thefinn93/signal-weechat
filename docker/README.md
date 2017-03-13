# How to Get Started

1) create .weechat folder (empty) in the same directory as this file.

2) When you first run this:
`docker build . -t signal-weechat`

3) Then run:
`docker run -v "$(pwd)"/.weechat:/home/guest/.weechat -v "$(dirname $(pwd))":/signal-weechat -it signal-weechat:latest`

4) Follow prompts on screen

5) Then every time after that, simply run: `./weechat.sh` to load up weechat

# How to load accounts
When you are inside of weechat its very easy to load new accounts.

Here is an example of the commands you need to run:

/server add SERVERLABEL SERVERURL -autoconnect
/secure set SERVERLABEL_PASSWORD 12345678
/set irc.server.SERVERLABEL.command "/msg &bitlbee identify ${sec.data.SERVERLABEL_PASSWORD}"
/set irc.server.SERVERLABEL.nicks USERNAME
/set irc.server.SERVERLABEL.realname USERNAME
/set irc.server.SERVERLABEL.username USERNAME
/set irc.server.SERVERLABEL.sasl_username USERNAME
/set irc.server.SERVERLABEL.password ${sec.data.SERVERLABEL_PASSWORD}
/set irc.server.SERVERLABEL.sasl_password ${sec.data.SERVERLABEL_PASSWORD}
/set irc.server.SERVERLABEL.autoconnect on
/set irc.server.SERVERLABEL.ssl on
/connect SERVERLABEL

6) Enable otr
Run: `/script` If you would like to view all available scripts
Run: `/script install otr.py` to actually get otr setup
