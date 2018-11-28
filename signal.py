#!/usr/bin/env python
import weechat
import logging
import socket
import json
import os
import random


SCRIPT_NAME = 'signal'
SCRIPT_AUTHOR = 'Finn Herzfeld <finn@finn.io>'
SCRIPT_VERSION = '0.1'
SCRIPT_LICENSE = 'GPL3'
SCRIPT_DESC = 'Send and receive messages via Signal with weechat'

SCRIPT_COMMAND = 'signal'
SCRIPT_BUFFER = 'signal'

useragent = "%s v%s by %s" % (SCRIPT_NAME, SCRIPT_VERSION, SCRIPT_AUTHOR)

def get_logfile():
    weechat_dir = weechat.info_get("weechat_dir", "") or ".weechat"
    return os.path.join(weechat_dir, "logs", "signal.log")

logging.basicConfig(filename=get_logfile())
logger = logging.getLogger("weechat_script")

default_options = {
    "socket": "/var/run/signald/signald.sock",
    "loglevel": "WARN",
    "sentry_dsn": "",
    "number": ""
}

options = {}
buffers = {}

callbacks = {}

signald_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)


def prnt(text):
    logger.info(text)
    weechat.prnt("", "signal\t%s" % text)


def show_msg(number, group, message, incoming):
    identifier = number if group is None else group
    buf = get_buffer(identifier, group is not None)
    name = "Me"
    if incoming:
        name = number
#        name = getSignal().getContactName(number)
#        if len(name) == 0:
#            name = number
    weechat.prnt(buf, "%s\t%s" % (name, message))


def init_config():
    global default_options, options
    for option, default_value in default_options.items():
        if not weechat.config_is_set_plugin(option):
            weechat.config_set_plugin(option, default_value)
        options[option] = weechat.config_get_plugin(option)
    return weechat.WEECHAT_RC_OK


def welcome(version):
    prnt("")
    prnt("")
    if version != "":
        prnt("Welcome to Signal Weechat! You're running {name} version {version} ({commit}).".format(**version))
        if len(options['number']) > 0:
            subscribe(options['number'])
        else:
            prnt("To begin, you must register or link to an existing device:")
            prnt("To register a new number: {}/signal register +12024561414".format(weechat.color("bold")))
            prnt("To link to an existing device: {}/signal link".format(weechat.color("bold")))
    else:
        prnt("You don't have signald running! See https://gitlab.com/thefinn93/signald")
    prnt("")
    prnt("")


def handle_version(payload):
    if "id" not in payload:
        welcome(payload)
    else:
        prnt("Connected to {name} version {version} ({commit})".format(**payload))


def receive(data, fd):
    global signald_socket
    while not data.endswith("\n"):
        data += signald_socket.recv(1)
    logger.debug("Got message from signald: %s", data)
    payload = json.loads(data)
    signald_callbacks = {
        "version": handle_version,
        "message": message_cb
    }

    if "id" in payload and payload["id"] in callbacks:
        callback = callbacks[payload["id"]]
        callback["func"](payload, *callback["args"], **callback["kwargs"])
    elif payload.get('type') in signald_callbacks:
        signald_callbacks[payload.get('type')](payload.get('data'))
    else:
        prnt("Got unhandled {} message from signald, see debug log for more info".format(payload.get('type')))
        logger.warn("Got unhandled message of type %s from signald", payload.get('type'))
    return weechat.WEECHAT_RC_OK


def send(msgtype, cb=None, cb_args=[], cb_kwargs={}, **kwargs):
    global signald_socket
    request_id = "weechat-signal-{}".format(random.randint(0, 1000))
    payload = kwargs
    payload['type'] = msgtype
    payload["id"] = request_id
    if cb is not None:
        callbacks[request_id] = {"func": cb, "args": cb_args, "kwargs": cb_kwargs}
    msg = json.dumps(payload)
    logger.debug("Sending to signald: %s", msg)
    signald_socket.sendall(msg + "\n")


def subscribe(number):
    send("subscribe", username=number, cb=subscribe_cb, cb_kwargs={"number": number})


def subscribe_cb(payload, number):
    prnt("Successfully subscribed to {}".format(number))


def message_cb(payload):
    if payload.get('dataMessage') is None:  # Sometimes "dataMessage" is set to null
        return

    if payload['dataMessage'].get('message') is None:
        return

    message = payload['dataMessage']['message']
    groupInfo = payload['dataMessage'].get('groupInfo')
    group = groupInfo.get('groupId') if groupInfo is not None else None
    show_msg(payload['source'], group, message, True)


def get_buffer(identifier, isGroup):
    if identifier not in buffers:
        cb = "buffer_input_group" if isGroup else "buffer_input"
        name = identifier
        logger.debug("Creating buffer for identifier %s (%s)", identifier, "group" if isGroup else "contact")
        nicklist = []
        name = identifier  # TODO: get contact or group name
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
    send("send", username=options["number"], recipientNumber=number, messageBody=message)
    show_msg(number, None, message, False)
    return weechat.WEECHAT_RC_OK


def buffer_input_group(groupId, buffer, message):
    send("send", username=options["number"], recipientGroupId=groupId, messageBody=message)
    show_msg(None, groupId, message, False)
    return weechat.WEECHAT_RC_OK


def init_socket():
    global signald_socket
    signald_socket.connect(options["socket"])
    weechat.hook_fd(signald_socket.fileno(), 1, 0, 0, 'receive', '')


def set_log_level():
    level = logging.getLevelName(options['loglevel'].upper())
    logging.basicConfig(level=level, filename=get_logfile())
    logger.info("Log level set to %s", logging.getLevelName(level))


def config_changed(data, option, value):
    global options
    logger.debug('Config option %s changed to %s', option, value)
    option = option.split("plugins.var.python.signal.")[-1]
    options[option] = value
    if option == 'loglevel':
        set_log_level()
    if option == 'number':
        if len(value) == 0:
            prnt("Set your number with /set plugins.var.python.signal.number +12024561414")
        else:
            logger.debug("Number is '%s'", value)
            subscribe(value)
    return weechat.WEECHAT_RC_OK


def shutdown():
    global signald_socket
    logger.info("Shutdown called, closing signald socket")
    signald_socket.close()
    return weechat.WEECHAT_RC_OK


def signal_cmd_cb(data, buffer, args):
    prnt("not yet implemented")
    return weechat.WEECHAT_RC_OK


def smsg_cmd_cb(data, buffer, args):
    if len(args) == 0:
        prnt("Not enough arguments! Try /help smg")
    elif " " not in args:
        get_buffer(args, False)
    else:
        number, message = args.split(" ", 1)
        #getSignal().sendMessage(message, dbus.Array(signature="s"), number)
        show_msg(number, None, message, False)
    return weechat.WEECHAT_RC_OK



if __name__ == "__main__":
    logger.debug("Preparing to register")
    try:
        if weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE, SCRIPT_DESC, 'shutdown', ''):
            weechat.hook_config('plugins.var.python.%s.*' % SCRIPT_NAME, 'config_changed', '')
            init_config()
            set_log_level()
            signal_help = [
                "number: the full e164 number (including country code) to send to",
                "message: the text of the message to send"
            ]
            logger.debug("Registering command...")
            weechat.hook_command("smsg", "Send a message to someone on signal", "[number] [message]",
                                 "\n".join(signal_help), "%(message)", "smsg_cmd_cb", "")
            weechat.hook_command("signal", "Interact with Signal", "[action]",
                                 "help coming soon...", "%(message)", "signal_cmd_cb", "")
            init_socket()
    except Exception:
        logger.exception("Failed to initialize plugin.")
