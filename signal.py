# -*- coding: utf-8 -*-
try:
    import weechat
except ImportError:
    print("Are you sure you're doing this right?")
import logging
import sys
import dbus


SCRIPT_NAME = 'signal'
SCRIPT_AUTHOR = 'Finn Herzfeld <finn@finn.io>'
SCRIPT_VERSION = '0.1'
SCRIPT_LICENSE = 'GPL3'
SCRIPT_DESC = 'Send and receive messages via Signal with weechat'

SCRIPT_COMMAND = 'signal'
SCRIPT_BUFFER = 'signal'

default_options = {
    'bus': "session",
    'debug': '',
    'sentry_dsn': ''
}

options = {}

bus = dbus.SessionBus()
signal = None


def init_config():
    global default_options, options, bus, signal
    for option, default_value in default_options.items():
        if not weechat.config_is_set_plugin(option):
            weechat.config_set_plugin(option, default_value)
        options[option] = weechat.config_get_plugin(option)
    if options.get('debug', '') != '':
        logging.basicConfig(filename=options.get('debug'), level=logging.DEBUG)
    if options.get('bus', 'session') == "system":
        bus = dbus.SystemBus()
    signal = bus.get_object('org.asamk.Signal', '/org/asamk/Signal')
    logging.debug("Initialized configuration")


def config_changed(data, option, value):
    try:
        init_config()
    except Exception:
        logging.exception("Failed to reload config")
    return weechat.WEECHAT_RC_OK


def send(data, buffer, args):
    number, message = args.split(" ", 1)
    signal.sendMessage(message, dbus.Array(signature="s"), number)
    return weechat.WEECHAT_RC_OK


def main():
    logging.debug("Preparing to register")
    try:
        if weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE, SCRIPT_DESC, 'shutdown', ''):
            init_config()
            weechat.hook_config('plugins.var.python.%s.*' % SCRIPT_NAME, 'config_changed', '')
            signal_help = [
                "number: the full number (including country code) to send to",
                "message: the text of the message to send"
            ]
            logging.debug("Registering command...")
            weechat.hook_command("signal", "Send a message to someone on signal", "[number] [message]",
                                 "\n".join(signal_help), "%(message)", "send", "")
    except Exception:
        logging.exception("Failed to initialize plugin.")

if __name__ == "__main__":
    if "weechat" in sys.modules:
        main()
    else:
        import pdb
        pdb.set_trace()
