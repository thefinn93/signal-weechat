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
try:
    import qrcode
except ImportError:
    qrcode = False


SCRIPT_NAME = 'signal'
SCRIPT_AUTHOR = 'Finn Herzfeld <finn@finn.io>'
SCRIPT_VERSION = '0.1'
SCRIPT_LICENSE = 'GPL3'
SCRIPT_DESC = 'Send and receive messages via Signal with weechat'

SCRIPT_COMMAND = 'signal'
SCRIPT_BUFFER = 'signal'

useragent = "%s v%s by %s" % (SCRIPT_NAME, SCRIPT_VERSION, SCRIPT_AUTHOR)


logger = logging.getLogger(logger_name)

default_options = {
    'bus': "session",
    'debug': '',
    'sentry_dsn': '',
    'number': '',
    'signal_cli_update_url': 'https://api.github.com/repos/thefinn93/signal-cli/releases/latest',
    'signal_cli_command': 'signal-cli',
    'autoupgrade': 'off'
}

options = {}
buffers = {}
sock = None
daemon_path = __file__
signalpid = None
downloads_in_progresss = []


def prnt(text):
    logger.info(text)
    weechat.prnt("", "signal-cli\t%s" % text)


def init_config():
    global default_options, options, bus, signal
    for option, default_value in default_options.items():
        if not weechat.config_is_set_plugin(option):
            weechat.config_set_plugin(option, default_value)
        options[option] = weechat.config_get_plugin(option)
    if options.get('number', '') == '':
        check_update("welcome")
    return weechat.WEECHAT_RC_OK


def show_msg(number, group, message, incoming):
    buf = get_buffer(group if len(group) > 0 else number, len(group) > 0)
    name = "Me"
    if incoming:
        name = getSignal().getContactName(number)
        if len(name) == 0:
            name = number
    weechat.prnt(buf, "%s\t%s" % (name, message))


def config_changed(data, option, value):
    global options
    logger.debug('Config option %s changed to %s', option, value)
    option = option.split("plugins.var.python.signal.")[-1]
    options[option] = value
    if option == 'debug' and value != '':
        logging.basicConfig(filename=options.get('debug'), level=logging.DEBUG)
    if option == 'number':
        if len(value) == 0:
            prnt("Set your number with /set plugins.var.python.signal.number +12024561414")
        else:
            logger.debug("Number is '%s'", value)
    if option in ['number', 'signal_cli_command']:
        launch_daemon()
    return weechat.WEECHAT_RC_OK


def getSignal():
    bus = dbus.SessionBus()
    return bus.get_object('org.asamk.Signal', '/org/asamk/Signal')


def send(data, buffer, args):
    if len(args) == 0:
        prnt("Not enough arguments! Try /help smsg")
    elif " " not in args:
        get_buffer(args, False)
    else:
        number, message = args.split(" ", 1)
        getSignal().sendMessage(message, dbus.Array(signature="s"), number)
        show_msg(number, "", message, False)
    return weechat.WEECHAT_RC_OK


def kill_daemon(*args):
    pid_path = '%s/signal.pid' % weechat.info_get("weechat_dir", "")
    try:
        pf = file(pid_path, 'r')
        pid = int(pf.read().strip())
        pf.close()
    except IOError:
        logger.debug("IOError while reading %s, proly not gonna kill the daemon", pid_path)
        return weechat.WEECHAT_RC_OK

    try:
        os.kill(pid, SIGTERM)
    except OSError:
        pass
    if signalpid is not None:
        logger.debug("Killing signal-cli process (PID %s)", signalpid)
        try:
            os.kill(signalpid, SIGTERM)
        except:
            logger.exception("Failed to kill signal-cli process %s", signalpid)
    else:
        logger.debug("No known signal-cli process to kill :/")
    return weechat.WEECHAT_RC_OK


def signal_cmd_cb(data, buffer, args):
    if len(args) == 0:
        prnt("not enough arguments! try /help signal")
        return weechat.WEECHAT_RC_OK
    args = args.split(" ")
    command = args[0]
    if command == "register":
        do_register(args)
    elif command == "verify":
        do_verify(args)
    elif command == "contact":
        contact_subcommand(args[1:])
    elif command in ["update", "upgrade"]:
        check_update("install")
    elif command == "install":
        check_update("installIfMissing")
    elif command == "link":
        do_link()
    else:
        prnt("Unrecognized command! try /help signal")
    return weechat.WEECHAT_RC_OK


def contact_subcommand(args):
    logger.debug("Running contact subcommand with args %s", args)
    if len(args) == 0:
        prnt("not enough arguments! try /help signal")
        return None
    command = args[0]
    if command in ["update", "add"]:
        if len(args) > 2:
            number = args[1]
            name = " ".join(args[2:])
            getSignal().setContactName(number, name)
            prnt("Contact %s (%s) created/updated" % (number, name))
        else:
            prnt("not enough arguments! try /help signal")
    else:
        prnt("not enough arguments! try /help signal")


def do_register(args):
    if len(args) != 2:
        prnt("Incorrect usage. Try /help signal")
        return None
    number = args[1]
    weechat.hook_process('%s -u %s register' % (options['signal_cli_command'], number), 3000, "register_cb", number)


def register_cb(number, command, code, out, err):
    logger.debug("Registration for %s (%s) exited with code %s, out %s err %s", number, command, code, out, err)
    prnt("A verification code has been texted to %s. Run /signal verify %s [code] when you receive it" %
         (number, number))
    return weechat.WEECHAT_RC_OK


def do_verify(args):
    if len(args) != 3:
        prnt("Incorrect arguments. Try /help signal")
        return None
    number = args[1]
    code = args[2]
    weechat.hook_process('%s -u %s verify %s' % (options['signal_cli_command'], number, code), 3000, "verify_cb",
                         number)
    return weechat.WEECHAT_RC_OK


def verify_cb(number, command, code, out, err):
    logger.debug("Registration for %s (%s) exited with code %s, out %s err %s", number, command, code, out, err)
    prnt("Verification probably succeeded. Trying to start listening for messages...")
    weechat.config_set_plugin("number", number)
    return weechat.WEECHAT_RC_OK


def do_link():
    kill_daemon()
    init_socket()
    pid_path = '%s/signal.pid' % weechat.info_get("weechat_dir", "")
    sock_path = '%s/signal.sock' % weechat.info_get("weechat_dir", "")

    daemon_command = ['python', daemon_path, sock_path, pid_path, 'link', options.get('signal_cli_command')]
    if options.get('debug', '') != '':
        daemon_command.append(options.get('debug', ''))
    logger.debug("Preparing to launch daemon with comand %s" % " ".join(daemon_command))
    weechat.hook_process(" ".join(daemon_command), 1000, "daemon_cb", "")
    prnt("Preparing to link to a device...")
    return weechat.WEECHAT_RC_OK


def get_buffer(identifier, isGroup):
    if identifier not in buffers:
        cb = "buffer_input_group" if isGroup else "buffer_input"
        name = identifier
        logger.debug("Creating buffer for identifier %s (%s)", identifier, "group" if isGroup else "contact")
        nicklist = []
        signal = getSignal()
        try:
            if isGroup:
                group = [dbus.Byte(x) for x in base64.b64decode(identifier)]
                name = signal.getGroupName(group)
                for number in signal.getGroupMembers(group):
                    contact_name = signal.getContactName(number)
                    if len(contact_name) == 0:
                        contact_name = number
                    nicklist.append(contact_name)
            else:
                name = signal.getContactName(identifier)
                if len(name) == 0:
                    name = identifier
            logger.debug("%s %s is known as %s", "group" if isGroup else "contact", identifier, name)
        except dbus.exceptions.DBusException:
            pass
        buffers[identifier] = weechat.buffer_new(name, cb, identifier, "", "")
        weechat.buffer_set(buffers[identifier], "title", name)
        if len(nicklist) > 0:
            weechat.buffer_set(buffers[identifier], "nicklist", "1")
            weechat.buffer_set(buffers[identifier], "nicklist_display_groups", "0")
            for nick in nicklist:
                logger.debug("Adding %s to group %s", nick, identifier)
                weechat.nicklist_add_nick(buffers[identifier], "", nick, "", "", "", 1)
    return buffers[identifier]


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
    global signalpid
    if not sock:
        return weechat.WEECHAT_RC_OK
    conn, addr = sock.accept()
    logger.debug("Receiving data!")
    data = json.loads(conn.recv(4069))
    logger.debug("got %s", data)
    msg = data.get("msg")
    if data.get("type") == "message":
        show_msg(msg.get("sender"), msg.get("groupId"), msg.get("message"), True)
    elif data.get("type") == "signal-pid":
        signalpid = msg
        prnt("signal daemon running!")
    elif data.get("type") == "link-uri":
        prnt("Link your device by visiting %s" % msg)
        if qrcode:
            show_link_qr(msg)
        else:
            prnt("If you'd prefer to scan a barcode, run pip install qrcode and restart this script.")
    elif data.get("type") == "set-number":
        weechat.config_set_plugin("number", msg)
        prnt("Successfully linked to %s" % msg)
    elif data.get("type") == "meta":
        prnt(msg)
    return weechat.WEECHAT_RC_OK


def show_link_qr(uri):
    logger.debug("encoding as QR code: %s", uri)
    prnt("Open Signal on your phone and navigate to Settings > Linked devices. Tap the button to add a new device, "
         "then scan the code above.")
    code = qrcode.QRCode()
    code.add_data(uri)
    matrix = code.get_matrix()
    lastline = len(matrix)-1
    for y in range(0, len(matrix), 2):
        line = ""
        for x in range(0, len(matrix[y])):
            if matrix[y][x]:
                # This line is black
                if lastline > y and matrix[y+1][x]:
                    # The next line is also black
                    line += "█"
                else:
                    # The next line is white or non existant
                    line += "▀"
            else:
                # This line is white
                if lastline > y and matrix[y+1][x]:
                    # The next line is black
                    line += "▄"
                else:
                    # The next line is also white or non-existant
                    line += " "
        prnt("%s%s" % (weechat.color("black,white"), line))


def daemon_cb(*args):
    logger.info("Daemon successfully launched: %s", args)
    return weechat.WEECHAT_RC_OK


def init_socket():
    global sock
    kill_daemon()
    if sock is None:
        sock_path = '%s/signal.sock' % weechat.info_get("weechat_dir", "")
        try:
            os.unlink(sock_path)
        except OSError:
            if os.path.exists(sock_path):
                raise
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(sock_path)
        sock.listen(5)

        weechat.hook_fd(sock.fileno(), 1, 1, 0, 'receive', '')


def launch_daemon(*_):
    if len(options.get('number', '')) > 0:
        init_socket()
        pid_path = '%s/signal.pid' % weechat.info_get("weechat_dir", "")
        sock_path = '%s/signal.sock' % weechat.info_get("weechat_dir", "")
        daemon_command = ['python', daemon_path, sock_path, pid_path, options.get('number'),
                          options.get('signal_cli_command')]
        if options.get('debug', '') != '':
            daemon_command.append(options.get('debug', ''))
        logger.debug("Preparing to launch daemon with comand %s" % " ".join(daemon_command))
        weechat.hook_process(" ".join(daemon_command), 1000, "daemon_cb", "")
    return weechat.WEECHAT_RC_OK


# Signal-cli Update BS
def check_update(action, *_):
    weechat.hook_process('%s -v' % options['signal_cli_command'], 10000, 'current_version_cb', action)
    return weechat.WEECHAT_RC_OK


def current_version_cb(action, command, rc, out, err):
    logger.debug("%s exited with %s", command, rc)
    version = out.split(" ")[-1].strip()
    if action == "install":
        prnt("Current version of signal-cli is %s" % version)
        weechat.hook_process_hashtable('url:%s' % options.get('signal_cli_update_url'), {"useragent": useragent},
                                       10000, 'update_url_cb', version)
    if action == "installIfMissing":
        if version == "":
            prnt("signal-cli not found, downloading...")
            current_version_cb("install", command, rc, out, err)
        else:
            prnt("signal-cli is already installed. Run %s/signal upgrade%s to get the latest version" %
                 (weechat.color("bold"), weechat.color("reset")))
    elif action == "welcome":
        prnt("")
        prnt("")
        if version != "":
            prnt("Welcome to Signal Weechat! You're running signal-cli %s." % version)
            prnt("To begin, you must register or link to an existing device:")
            prnt("To register a new number: %s/signal register +12024561414" % weechat.color("bold"))
            prnt("To link to an existing device: %s/signal link" % weechat.color("bold"))
        else:
            prnt("You don't have signal-cli! Run %s/signal install%s first to get it!" %
                 (weechat.color("bold"), weechat.color("reset")))
        prnt("")
        prnt("")
    return weechat.WEECHAT_RC_OK


def update_url_cb(current, _, rc, out, err):
    global downloads_in_progresss
    release = json.loads(out)
    latest = release['name'].split(" ")[-1]
    if latest != current:
        prnt("Latest release is %s, but we're running %s!" % (latest, current))
        for asset in release['assets']:
            url = asset['browser_download_url']
            filename = "/tmp/%s" % asset['name']
            downloads_in_progresss.append(asset['name'])
            prnt("Downloading %s" % url)
            weechat.hook_process_hashtable('url:%s' % url,
                                           {"useragent": useragent, "file_out": filename},
                                           60000, 'update_download_cb',
                                           json.dumps({"filename": asset['name'], "version": latest}))
    return weechat.WEECHAT_RC_OK


def update_download_cb(info, url, rc, out, err):
    global downloads_in_progresss
    info = json.loads(info)
    downloads_in_progresss.remove(info.get('filename'))
    if len(downloads_in_progresss) > 0:
        prnt("%s finished, still waiting on %s" % (info.get('filename'), ", ".join(downloads_in_progresss)))
    else:
        weechat.hook_process("mkdir %s/signal-cli" % weechat.info_get("weechat_dir", ""), 1000, 'extract_new_version',
                             info.get('version'))
    return weechat.WEECHAT_RC_OK


def extract_new_version(new_version, url, rc, out, err):
    logger.debug("Update download finished! Signed binaries are for suckers so we're just gonna extract it!")
    tarball = "/tmp/signal-cli-%s.tar.gz" % new_version
    weechat.hook_process('tar xzf %s -C %s/signal-cli' % (tarball, weechat.info_get("weechat_dir", "")), 60000,
                         'update_extract_cb', new_version)
    return weechat.WEECHAT_RC_OK


def update_extract_cb(new_version, command, rc, out, err):
    new_bin = "%s/signal-cli/signal-cli-%s/bin/signal-cli" % (weechat.info_get("weechat_dir", ""), new_version)
    prnt("Downloaded and extracted signal-cli %s!" % new_bin)
    weechat.config_set_plugin("signal_cli_command", new_bin)
    logger.debug("Options are %s", options)
    if options.get("number", "") == "":
        check_update("welcome")
    return weechat.WEECHAT_RC_OK


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
            for signal in ['quit', 'signal_sighup', 'signal_sigquit', 'signal_sigterm', 'upgrade']:
                weechat.hook_signal(signal, 'kill_daemon', '')
            weechat.hook_signal('upgrade_ended', 'launch_daemon', '')
            if options.get('autoupgrade') == 'on':
                weechat.hook_timer(3*24*60*60*1000, 0, 0, 'check_update', '', 'install')
    except Exception:
        logger.exception("Failed to initialize plugin.")


# (almost) everything after this is for the daemon

class Daemon:
        signalsubprocess = None

        def __init__(self, sock_path, pidfile, number, signalcli, filename=None):
                self.pidfile = pidfile
                self.sock_path = sock_path
                self.number = number
                self.signalcli = signalcli
                if filename is not None:
                    logging.basicConfig(filename=filename, level=logging.DEBUG)

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
            logger.debug("Shutting down daemon")
            if self.signalsubprocess is not None:
                logger.debug("Killing signal-cli subprocess...")
                self.signalsubprocess.kill()
            logger.debug("Removing pid file %s", self.pidfile)
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
                try:
                    os.kill(pid, SIGTERM)
                except OSError:
                    pass
                os.unlink(self.pidfile)

            self.daemonize()
            if self.number == "link":
                self.link()
            else:
                self.run()

        def run(self):
                try:
                    logger.debug("Daemon running as %s", os.getpid())
                    self.signalsubprocess = subprocess.Popen([self.signalcli, '-u', self.number, 'daemon'])
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
                        self.send_to_sock(self.signalsubprocess.pid, "signal-pid")
                        loop.run()
                    else:
                        logger.debug("signal-cli exited with code %s, assuming unregistered",
                                     self.signalsubprocess.poll())
                        message = "We don't have a registration for {number}! Please either register it or link " \
                                  "an existing device:\n\n" \
                                  "  Register with: /signal register {number}\n" \
                                  "             or\n" \
                                  "  Link an existing device with /signal link".format(number=self.number)

                        self.send_to_sock(message, "meta")
                except:
                    logger.exception("The daemon hath died a horrible death :(")

        def link(self):
            try:
                subp = subprocess.Popen([self.signalcli, 'link', '-n', 'weechat on %s' % socket.getfqdn()],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                uri = subp.stdout.readline()
                self.send_to_sock(uri, "link-uri")
                out, err = subp.communicate()
                if len(err) > 0:
                    self.send_to_sock(err, "meta")
                if len(out) > 0:
                    number = out.split(" ")[-1].strip()
                    self.send_to_sock(number, "set-number")
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
