# -*- coding: utf-8 -*-
try:
    import weechat
    logger_name = "weechat_script"
except ImportError:
    from dbus.mainloop.glib import DBusGMainLoop
    from gi.repository import GLib
    DBusGMainLoop(set_as_default=True)
    loop = GLib.MainLoop()
    logger_name = "daemon"
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
import subprocess


SCRIPT_NAME = 'signal'
SCRIPT_AUTHOR = 'Finn Herzfeld <finn@finn.io>'
SCRIPT_VERSION = '0.1'
SCRIPT_LICENSE = 'GPL3'
SCRIPT_DESC = 'Send and receive messages via Signal with weechat'

SCRIPT_COMMAND = 'signal'
SCRIPT_BUFFER = 'signal'

logging.basicConfig(filename='signal-weechat.log', level=logging.DEBUG)

logger = logging.getLogger(logger_name)

default_options = {
    'bus': "session",
    'debug': '',
    'sentry_dsn': '',
    'number': ''
}

options = {}
buffers = {}
sock = None
daemon_path = __file__


def init_config():
    global default_options, options, bus, signal
    for option, default_value in default_options.items():
        if not weechat.config_is_set_plugin(option):
            weechat.config_set_plugin(option, default_value)
        options[option] = weechat.config_get_plugin(option)
    if options.get('debug', '') != '':
        logging.basicConfig(filename=options.get('debug'), level=logging.DEBUG)
    if len(options.get('number', '')) == 0:
        weechat.prnt("", "Set your number with /set plugins.var.python.signal.number +12024561414")
    else:
        logger.debug("Number is '%s'", options.get('number'))
        launch_daemon()
    logger.debug("Initialized configuration")


def show_msg(number, group, message, incoming):
    buf = get_buffer(group if len(group) > 0 else number, len(group) > 0)
    weechat.prnt(buf, "%s\t%s" % (number if incoming else "Me", message))


def config_changed(data, option, value):
    try:
        init_config()
    except Exception:
        logger.exception("Failed to reload config")
    return weechat.WEECHAT_RC_OK


def getSignal():
    bus = dbus.SessionBus()
    return bus.get_object('org.asamk.Signal', '/org/asamk/Signal')


def send(data, buffer, args):
    if len(args) == 0:
        weechat.prnt("", "Not enough arguments! Try /help smg")
    elif " " not in args:
        get_buffer(args, False)
    else:
        number, message = args.split(" ", 1)
        getSignal().sendMessage(message, dbus.Array(signature="s"), number)
        show_msg(number, "", message, False)
    return weechat.WEECHAT_RC_OK


def signal_cmd_cb(data, buffer, args):
    if len(args) == 0:
        weechat.prnt("", "not enough arguments! try /help signal")
        return weechat.WEECHAT_RC_OK
    args = args.split(" ")
    command = args[0]
    if command == "register":
        do_register(args)
    elif command == "verify":
        do_verify(args)
    else:
        weechat.prnt("", "Unrecognized command! try /help signal")
    return weechat.WEECHAT_RC_OK


def do_register(args):
    if len(args) != 2:
        weechat.prnt("", "Incorrect usage. Try /help signal")
        return None
    number = args[1]
    weechat.hook_process('signal-cli -u %s register' % number, 300, "register_cb", number)


def register_cb(number, command, code, out, err):
    logger.debug("Registration for %s (%s) exited with code %s, out %s err %s", number, command, code, out, err)
    weechat.prnt("", "A verification code has been texted to %s. Run /signal verify %s [code] when you receive it" %
                 (number, number))
    return weechat.WEECHAT_RC_OK


def do_verify(args):
    if len(args) != 3:
        weechat.prnt("", "Incorrect arguments. Try /help signal")
        return None
    number = args[1]
    code = args[2]
    weechat.hook_process('signal-cli -u %s verify %s' % (number, code), 300, "verify_cb", number)
    return weechat.WEECHAT_RC_OK


def verify_cb(number, command, code, out, err):
    logger.debug("Registration for %s (%s) exited with code %s, out %s err %s", number, command, code, out, err)
    weechat.prnt("", "Verification probably succeeded. Trying to start listening for messages...")
    weechat.config_set_plugin("number", number)
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
    logger.debug("Receiving data!")
    data = json.loads(conn.recv(4069))
    logger.debug("got %s", data)
    msg = data.get("msg")
    if data.get("type") == "message":
        show_msg(msg.get("sender"), msg.get("groupId"), msg.get("message"), True)
    elif data.get("type") == "meta":
        weechat.prnt("", msg)
    return weechat.WEECHAT_RC_OK


def daemon_cb(*args):
    weechat.prnt("", "Daemon launched!")
    logger.info("Daemon successfully launched: %s", args)
    return weechat.WEECHAT_RC_OK


def launch_daemon():
    global sock
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

    logger.debug("Preparing to launch daemon...")
    daemon_command = [sys.executable, daemon_path, sock_path, pid_path, options.get('number')]
    weechat.hook_process(" ".join(daemon_command), 10, "daemon_cb", "")


def main():
    logger.debug("Preparing to register")
    try:
        if weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE, SCRIPT_DESC, 'shutdown', ''):
            init_config()
            weechat.hook_config('plugins.var.python.%s.*' % SCRIPT_NAME, 'config_changed', '')
            signal_help = [
                "number: the full number (including country code) to send to",
                "message: the text of the message to send"
            ]
            logger.debug("Registering command...")
            weechat.hook_command("smsg", "Send a message to someone on signal", "[number] [message]",
                                 "\n".join(signal_help), "%(message)", "send", "")
            weechat.hook_command("signal", "Interact with Signal", "[action]",
                                 "help coming soon...", "%(message)", "signal_cmd_cb", "")
    except Exception:
        logger.exception("Failed to initialize plugin.")


# (almost) everything after this is for the daemon

class Daemon:
        signalsubprocess = None

        def __init__(self, sock_path, pidfile, number):
                self.pidfile = pidfile
                self.sock_path = sock_path
                self.number = number

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
                logger.info("Daemon running as PID %s", pid)
                file(self.pidfile, 'w+').write("%s\n" % pid)

        def delpid(self):
                if self.signalsubprocess is not None:
                    self.signalsubprocess.kill()
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
                    logger.debug("Daemon running!")
                    self.signalsubprocess = subprocess.Popen(['signal-cli', '-u', self.number, 'daemon'])
                    signal = None
                    while signal is None and self.signalsubprocess.poll() is None:
                        try:
                            signal = getSignal()
                        except dbus.DBusException:
                            logger.debug("Waiting for signal-cli to come up...")
                            time.sleep(1)
                    if self.signalsubprocess.poll() is None:
                        interface = dbus.Interface(signal, dbus_interface='org.asamk.Signal')
                        interface.connect_to_signal("MessageReceived", self.dbus_to_sock)
                        self.send_to_sock("Connected to signal-cli", "meta")
                        loop.run()
                    else:
                        logging.debug("signal-cli exited with code %s, assuming unregistered",
                                      self.signalsubprocess.poll())
                        message = "We don't have a registration for {number}! Please either register it or link " \
                                  "an existing device:\n\n" \
                                  "  Register with: /signal register {number}\n" \
                                  "             or\n" \
                                  "  Link an existing device with /signal link".format(number=self.number)

                        self.send_to_sock(message, "meta")
                except:
                    logger.exception("The daemon hath died a horrible death :(")

        def dbus_to_sock(self, timestamp, sender, groupId, message, attachments):
            groupId = base64.b64encode("".join([chr(x) for x in groupId]))
            self.send_to_sock({
                "timestamp": timestamp,
                "sender": sender,
                "groupId": groupId,
                "message": message,
                "attachments": attachments
            }, "message")

        def send_to_sock(self, msg, type):
            msg = json.dumps({"msg": msg, "type": type})
            sock_path = sys.argv[1]
            logger.debug("Pushing %s to the %s", msg, sock_path)
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            logger.debug("Connecting to socket...")
            sock.connect(self.sock_path)
            logger.debug("Sending message...")
            sock.sendall(msg)
            logger.debug("Closing socket")
            sock.close()
            logger.debug("Done")


if __name__ == "__main__":
    logger.debug("__file__ = %s", __file__)
    if "weechat" in sys.modules:
        main()
    else:
        daemon = Daemon(*sys.argv[1:])
        daemon.start()
