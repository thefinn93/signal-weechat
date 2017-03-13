# How to Get Started

1) Run `./weechat.sh` to build and run.

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
