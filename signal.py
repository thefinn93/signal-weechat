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
import time
from signal import SIGTERM
import atexit


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


def getSignal():
    bus = dbus.SessionBus()
    return bus.get_object('org.asamk.Signal', '/org/asamk/Signal')


def send(data, buffer, args):
    if len(args) == 0:
        weechat.prnt("", "Not enough arguments! Try /help signal")
    elif " " not in args:
        get_buffer(args, False)
    else:
        number, message = args.split(" ", 1)
        getSignal().sendMessage(message, dbus.Array(signature="s"), number)
        show_msg(number, "", message, False)
    return weechat.WEECHAT_RC_OK


def get_buffer(name, group):
    if name not in buffers:
        cb = "buffer_input_group" if group else "buffer_input"
        buffers[name] = weechat.buffer_new(name, cb, name, "", "")
        weechat.buffer_set(buffers[name], "title", name)
    return buffers[name]


def buffer_input(number, buffer, message):
    getSignal().sendMessage(message, dbus.Array(signature="s"), number)
    show_msg(number, "", message, False)
    return weechat.WEECHAT_RC_OK


def buffer_input_group(group, buffer, message):
    groupId = [dbus.Byte(x) for x in base64.b64decode(group)]
    getSignal().sendGroupMessage(message, dbus.Array(signature="s"), groupId)
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


def daemon_cb(*args):
    weechat.prnt("", "Daemon launched!")
    logging.info("Daemon successfully launched: %s", args)
    return weechat.WEECHAT_RC_OK


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
            pid_path = '%s/signal.pid' % weechat.info_get("weechat_dir", "")
            try:
                os.unlink(sock_path)
            except OSError:
                if os.path.exists(sock_path):
                    raise
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.bind(sock_path)
            sock.listen(5)

            weechat.hook_fd(sock.fileno(), 1, 1, 0, 'receive', '')
            weechat.prnt("", "Listening on %s" % sock_path)

            logging.debug("Preparing to launch daemon...")
            daemon_command = ["python", __file__, sock_path, pid_path]
            weechat.hook_process(" ".join(daemon_command), 10, "daemon_cb", "")
    except Exception:
        logging.exception("Failed to initialize plugin.")


# (almost) everything after this is for the daemon

class Daemon:
        def __init__(self, sock_path, pidfile):
                self.pidfile = pidfile
                self.sock_path = sock_path

        def daemonize(self):
                """
                do the UNIX double-fork magic, see Stevens' "Advanced
                Programming in the UNIX Environment" for details (ISBN 0201563177)
                http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC16
                """
                try:
                        pid = os.fork()
                        if pid > 0:
                                # exit first parent
                                sys.exit(0)
                except OSError, e:
                        sys.stderr.write("fork #1 failed: %d (%s)\n" % (e.errno, e.strerror))
                        sys.exit(1)

                # decouple from parent environment
                os.chdir("/")
                os.setsid()
                os.umask(0)

                # do second fork
                try:
                        pid = os.fork()
                        if pid > 0:
                                # exit from second parent
                                sys.exit(0)
                except OSError, e:
                        sys.stderr.write("fork #2 failed: %d (%s)\n" % (e.errno, e.strerror))
                        sys.exit(1)

                # write pidfile
                atexit.register(self.delpid)
                pid = str(os.getpid())
                logging.info("Daemon running as PID %s", pid)
                file(self.pidfile, 'w+').write("%s\n" % pid)

        def delpid(self):
                os.remove(self.pidfile)

        def start(self):
                """
                Start the daemon
                """
                # Check for a pidfile to see if the daemon already runs
                try:
                        pf = file(self.pidfile, 'r')
                        pid = int(pf.read().strip())
                        pf.close()
                except IOError:
                        pid = None

                if pid:
                        message = "pidfile %s already exist. Daemon already running?\n"
                        sys.stderr.write(message % self.pidfile)
                        sys.exit(1)

                # Start the daemon
                self.daemonize()
                self.run()

        def stop(self):
                """
                Stop the daemon
                """
                # Get the pid from the pidfile
                try:
                        pf = file(self.pidfile, 'r')
                        pid = int(pf.read().strip())
                        pf.close()
                except IOError:
                        pid = None

                if not pid:
                        message = "pidfile %s does not exist. Daemon not running?\n"
                        sys.stderr.write(message % self.pidfile)
                        return  # not an error in a restart

                # Try killing the daemon process
                try:
                        while 1:
                                os.kill(pid, SIGTERM)
                                time.sleep(0.1)
                except OSError, err:
                        err = str(err)
                        if err.find("No such process") > 0:
                                if os.path.exists(self.pidfile):
                                        os.remove(self.pidfile)
                        else:
                                print str(err)
                                sys.exit(1)

        def restart(self):
                """
                Restart the daemon
                """
                self.stop()
                self.start()

        def run(self):
                """
                You should override this method when you subclass Daemon. It will be called after the process has been
                daemonized by start() or restart().
                """
                try:
                    logging.debug("Daemon running!")
                    signal = None
                    while signal is None:
                        try:
                            signal = getSignal()
                        except dbus.DBusException:
                            logging.debug("Waiting for signal-cli to come up...")
                            time.sleep(1)
                    interface = dbus.Interface(signal, dbus_interface='org.asamk.Signal')
                    interface.connect_to_signal("MessageReceived", self.dbus_to_sock)
                    self.send_to_sock({"meta": "Connected to signal-cli"})
                    loop.run()
                except:
                    logging.exception("The daemon hath died a horrible death :(")

        def dbus_to_sock(self, timestamp, sender, groupId, message, attachments):
            groupId = base64.b64encode("".join([chr(x) for x in groupId]))
            self.send_to_sock({
                "timestamp": timestamp,
                "sender": sender,
                "groupId": groupId,
                "message": message,
                "attachments": attachments
            })

        def send_to_sock(self, msg):
            msg = json.dumps(msg)
            sock_path = sys.argv[1]
            logging.debug("Pushing %s to the %s", msg, sock_path)
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            logging.debug("Connecting to socket...")
            sock.connect(self.sock_path)
            logging.debug("Sending message...")
            sock.sendall(msg)
            logging.debug("Closing socket")
            sock.close()
            logging.debug("Done")


if __name__ == "__main__":
    if "weechat" in sys.modules:
        main()
    else:
        daemon = Daemon(*sys.argv[1:])
        daemon.start()
