# -*- coding: utf-8 -*-
try:
    import weechat
except ImportError:
    from dbus.mainloop.glib import DBusGMainLoop
    from gi.repository import GLib
    DBusGMainLoop(set_as_default=True)
    loop = GLib.MainLoop()
import logging
import sys
import dbus
import json
import socket
import base64
import os


SCRIPT_NAME = 'signal'
SCRIPT_AUTHOR = 'Finn Herzfeld <finn@finn.io>'
SCRIPT_VERSION = '0.1'
SCRIPT_LICENSE = 'GPL3'
SCRIPT_DESC = 'Send and receive messages via Signal with weechat'

SCRIPT_COMMAND = 'signal'
SCRIPT_BUFFER = 'signal'

logging.basicConfig(filename='signal-weechat.log', level=logging.DEBUG)

default_options = {
    'bus': "session",
    'debug': '',
    'sentry_dsn': ''
}

options = {}
buffers = {}
sock = None


bus = dbus.SessionBus()
signal = bus.get_object('org.asamk.Signal', '/org/asamk/Signal')


def init_config():
    global default_options, options, bus, signal
    for option, default_value in default_options.items():
        if not weechat.config_is_set_plugin(option):
            weechat.config_set_plugin(option, default_value)
        options[option] = weechat.config_get_plugin(option)
    if options.get('debug', '') != '':
        logging.basicConfig(filename=options.get('debug'), level=logging.DEBUG)
    logging.debug("Initialized configuration")


def show_msg(number, group, message, incoming):
    buf = get_buffer(group if len(group) > 0 else number, len(group) > 0)
    weechat.prnt(buf, "%s\t%s" % (number if incoming else "Me", message))


def config_changed(data, option, value):
    try:
        init_config()
    except Exception:
        logging.exception("Failed to reload config")
    return weechat.WEECHAT_RC_OK


def send(data, buffer, args):
    if len(args) == 0:
        weechat.prnt("", "Not enough arguments! Try /help signal")
    elif " " not in args:
        get_buffer(args, False)
    else:
        number, message = args.split(" ", 1)
        signal.sendMessage(message, dbus.Array(signature="s"), number)
        show_msg(number, "", message, False)
    return weechat.WEECHAT_RC_OK


def get_buffer(name, group):
    if name not in buffers:
        cb = "buffer_input_group" if group else "buffer_input"
        buffers[name] = weechat.buffer_new(name, cb, name, "", "")
        weechat.buffer_set(buffers[name], "title", name)
    return buffers[name]


def buffer_input(number, buffer, message):
    signal.sendMessage(message, dbus.Array(signature="s"), number)
    show_msg(number, "", message, False)
    return weechat.WEECHAT_RC_OK


def buffer_input_group(group, buffer, message):
    groupId = [dbus.Byte(x) for x in base64.b64decode(group)]
    signal.sendGroupMessage(message, dbus.Array(signature="s"), groupId)
    show_msg("", group, message, False)
    return weechat.WEECHAT_RC_OK


def receive(data, fd):
    if not sock:
        return weechat.WEECHAT_RC_OK
    conn, addr = sock.accept()
    logging.debug("Receiving data!")
    data = json.loads(conn.recv(4069))
    logging.debug("got %s", data)
    if "meta" not in data:
        show_msg(data.get("sender"), data.get("groupId"), data.get("message"), True)
    else:
        weechat.prnt("", "Signal Daemon message: %s" % data.get("meta"))
    return weechat.WEECHAT_RC_OK


def dbus_to_sock(timestamp, sender, groupId, message, attachments):
    groupId = base64.b64encode("".join([chr(x) for x in groupId]))
    send_to_sock({
        "timestamp": timestamp,
        "sender": sender,
        "groupId": groupId,
        "message": message,
        "attachments": attachments
    })


def send_to_sock(msg):
    msg = json.dumps(msg)
    sock_path = sys.argv[1]
    logging.debug("Pushing %s to the %s", msg, sock_path)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    logging.debug("Connecting to socket...")
    sock.connect(sock_path)
    logging.debug("Sending message...")
    sock.sendall(msg)
    logging.debug("Closing socket")
    sock.close()
    logging.debug("Done")


def wait_for_message():
    logging.debug("Daemon running!")
    interface = dbus.Interface(signal, dbus_interface='org.asamk.Signal')
    interface.connect_to_signal("MessageReceived", dbus_to_sock)
    logging.debug("preparing to run dbus...")
    send_to_sock({"meta": "initialized"})
    loop.run()


def main():
    global sock
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

            sock_path = '%s/signal.sock' % weechat.info_get("weechat_dir", "")
            try:
                os.unlink(sock_path)
            except OSError:
                if os.path.exists(sock_path):
                    raise
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.bind(sock_path)
            sock.listen(5)

            logging.debug("Initializing subprocess...")
            # subprocess.Popen(['python', __file__, sock_path], stdout=subprocess.PIPE)
            fdhook = weechat.hook_fd(sock.fileno(), 1, 1, 0, 'receive', '')
            weechat.prnt("", "Listening on %s" % sock_path)
            logging.debug("Hooked fd: %s", fdhook)
    except Exception:
        logging.exception("Failed to initialize plugin.")

if __name__ == "__main__":
    if "weechat" in sys.modules:
        main()
    else:
        wait_for_message()
