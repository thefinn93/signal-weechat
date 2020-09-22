#!/usr/bin/env python3
import weechat
import logging
import socket
import json
import os
import random

"""
For completion to work, you need to set option
weechat.completion.default_template to include signal_contact_or_group, e.g.

%{nicks}|%(irc_channels)|%(signal_contact_or_group)
"""

try:
    import emoji
except ImportError:
    emoji = None

SCRIPT_NAME = 'signal'
SCRIPT_AUTHOR = 'Finn Herzfeld <finn@finn.io>'
SCRIPT_VERSION = '0.1'
SCRIPT_LICENSE = 'GPL3'
SCRIPT_DESC = 'Send and receive messages via Signal with weechat'

SCRIPT_COMMAND = 'signal'
SCRIPT_BUFFER = 'signal'

useragent = "%s v%s by %s" % (SCRIPT_NAME, SCRIPT_VERSION, SCRIPT_AUTHOR)


def get_logfile():
    weechat_dir = weechat.info_get("weechat_dir", "") or "~/.weechat"
    return os.path.join(os.path.expanduser(weechat_dir), "logs", "signal.log")


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
contacts = {}
groups = {}

signald_hook = None
signald_socket = None


def prnt(text):
    logger.info(text)
    weechat.prnt("", "signal\t%s" % text)


def show_msg(number, group, message, incoming):
    identifier = number if group is None else group
    buf = get_buffer(identifier, group is not None)
    name = "Me"
    if incoming:
        name = contact_name(number)
    weechat.prnt(buf, "%s\t%s" % (name, message))
    if incoming:
        if group is None:
            # 1:1 messages are private messages
            hotness = weechat.WEECHAT_HOTLIST_PRIVATE
        else:
            # group messages are treated as 'messages'
            hotness = weechat.WEECHAT_HOTLIST_MESSAGE
        weechat.buffer_set(buf, "hotlist", hotness)


def contact_name(number):
    if number == options["number"]:
        return 'Me'
    if number in contacts:
        return contacts[number].get('name', number)
    else:
        return number

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
            prnt("To begin, you must register or link to an existing device in signald.")
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
    try:
        # awesome. since data is a string, but .recv() gives us bytes (that we
        # don't necessarily want to decode, since they may be broken in the
        # middle of a unicode character or something), we have to shoehorn
        # bytes directly to a string. we use latin1 per:
        # https://stackoverflow.com/a/42795285
        # so we can roundtrip every byte
        while not data.endswith("\n"):
            raw = signald_socket.recv(1).decode('latin1')
            if len(raw) == 0:
                logger.info('signald socket disconnected, attempting to reconnect')
                signald_socket.close()
                close_socket()
                init_socket()
                return weechat.WEECHAT_RC_OK
            data += raw
    except socket.error:
        logger.exception("Failed to read from signald.")
        close_socket()
        init_socket()
        return weechat.WEECHAT_RC_OK
    logger.debug("Got message from signald: %s", data)
    payload = json.loads(data.encode('latin1'))
    signald_callbacks = {
        "version": handle_version,
        "message": message_cb,
        "contact_list": contact_list_cb,
        "group_list": group_list_cb,
        "send_results": noop_cb,
        "sync_requested": noop_cb,
    }

    try:
        if "id" in payload and payload["id"] in callbacks:
            callback = callbacks[payload["id"]]
            callback["func"](payload, *callback["args"], **callback["kwargs"])
        elif payload.get('type') in signald_callbacks:
            signald_callbacks[payload.get('type')](payload.get('data'))
        else:
            prnt("Got unhandled {} message from signald, see debug log for more info".format(payload.get('type')))
            logger.warning("Got unhandled message of type %s from signald", payload.get('type'))
    except:
        logger.exception("exception while handling payload %s", json.dumps(payload, indent="    "))
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
    try:
        signald_socket.sendall((msg + "\n").encode('utf-8'))
    except (BrokenPipeError, OSError):
        close_socket()
        init_socket()


def subscribe(number):
    send("sync_contacts", username=number)
    send("list_contacts", username=number)
    send("list_groups", username=number)
    send("subscribe", username=number, cb=subscribe_cb, cb_kwargs={"number": number})


def subscribe_cb(payload, number):
    prnt("Successfully subscribed to {}".format(number))


def render_message(message):
    sticker = message.get('sticker')
    if sticker is not None:
        return "<sent sticker>"
    reaction = message.get('reaction')
    if reaction is not None:
        name = contact_name(reaction['targetAuthor']['number'])
        em = reaction["emoji"]
        if emoji is not None:
            em = emoji.demojize(em)
        return "<reacted with {} to a message from {}>".format(em, name)
    attachment_msg = ""
    attachments = message.get('attachments')
    if attachments is not None:
        types = [attach['contentType'] for attach in attachments]
        attachment_msg = "<sent {}> ".format(', '.join(types))
    body = message.get('body', "")
    if emoji is not None:
        body = emoji.demojize(body)
    return attachment_msg + body


def message_cb(payload):
    if payload.get('dataMessage') is not None:
        message = render_message(payload['dataMessage'])
        groupInfo = payload['dataMessage'].get('group')
        group = groupInfo.get('groupId') if groupInfo is not None else None
        show_msg(payload['source']['number'], group, message, True)
    elif payload.get('syncMessage') is not None:
        # some syncMessages are to synchronize read receipts; we ignore these
        if payload['syncMessage'].get('readMessages') is not None:
            return

        # if contactsComplete is present, the contact sync from initial plugin
        # load (or someone else triggering a contacts sync on signald) is
        # complete, and we should update our contacts list.
        if payload['syncMessage'].get('contactsComplete', False):
            send("list_contacts", username=options['number'])
            return

        message = render_message(payload['syncMessage']['sent']['message'])
        groupInfo = payload['syncMessage']['sent']['message'].get('group')
        group = groupInfo.get('groupId') if groupInfo is not None else None
        dest = payload['syncMessage']['sent']['destination']['number'] if groupInfo is None else None
        show_msg(dest, group, message, False)


def noop_cb(payload):
    pass


def contact_list_cb(payload):
    global contacts

    for contact in payload:
        contacts[contact['address']['number']] = contact
        logger.debug("Checking for buffers with contact %s", contact)
        if contact['address']['number'] in buffers:
            b = buffers[contact['address']['number']]
            name = contact.get('name', contact['address']['number'])
            set_buffer_name(b, name)


def set_buffer_name(b, name):
    logger.info("Setting buffer name to %s", name)
    weechat.buffer_set(b, "title", name)
    weechat.buffer_set(b, "name", name)
    weechat.buffer_set(b, "shortname", name)


def group_list_cb(payload):
    global groups
    for group in payload['groups']:
        groups[group['groupId']] = group


def setup_group_buffer(groupId):
    global groups
    group = groups[groupId]
    buffer = get_buffer(groupId, True)
    set_buffer_name(buffer, group['name'])
    weechat.buffer_set(buffer, "nicklist", "1")
    weechat.buffer_set(buffer, "nicklist_display_groups", "0")
    for member in group['members']:
        member_name = contact_name(member['number'])
        entry = weechat.nicklist_search_nick(buffer, "", member_name)
        if len(entry) == 0:
            logger.debug("Adding %s to group %s", member_name, groupId)
            weechat.nicklist_add_nick(buffer, "", member_name, "", "", "", 1)


def buffer_close_cb(identifier, buffer):
    del buffers[identifier]
    return weechat.WEECHAT_RC_OK


def get_buffer(identifier, isGroup):
    if identifier not in buffers:
        cb = "buffer_input_group" if isGroup else "buffer_input"
        logger.debug("Creating buffer for identifier %s (%s)", identifier, "group" if isGroup else "contact")
        buffers[identifier] = weechat.buffer_new(identifier, cb, identifier, "buffer_close_cb", identifier)
        if not isGroup and identifier in contacts:
            name = contacts[identifier].get('name', identifier)
            set_buffer_name(buffers[identifier], name)
        if isGroup:
            setup_group_buffer(identifier)
        weechat.hook_signal_send("logger_backlog", weechat.WEECHAT_HOOK_SIGNAL_POINTER, buffers[identifier])
    return buffers[identifier]


def encode_message(message):
    if emoji is not None:
        message = emoji.emojize(message, use_aliases=True)
    return message


def buffer_input(number, buffer, message):
    encoded = encode_message(message)
    send("send", username=options["number"], recipientAddress={"number": number}, messageBody=encoded)
    show_msg(number, None, message, False)
    return weechat.WEECHAT_RC_OK


def buffer_input_group(groupId, buffer, message):
    encoded = encode_message(message)
    send("send", username=options["number"], recipientGroupId=groupId, messageBody=encoded)
    show_msg(None, groupId, message, False)
    return weechat.WEECHAT_RC_OK


def close_socket():
    global signald_socket
    global signald_hook

    if signald_socket is not None:
        signald_socket.close()
    if signald_hook is not None:
        weechat.unhook(signald_hook)


def init_socket():
    global signald_socket
    global signald_hook
    signald_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        signald_socket.connect(options["socket"])
        # weechat really wants the last argument to be a string, but we really
        # want it to be bytes. so we end up having to do a bunch of gnarly
        # decoding and stuff in receive(). c'est la vie.
        signald_hook = weechat.hook_fd(signald_socket.fileno(), 1, 0, 0, 'receive', '')
    except Exception:
        logger.exception("Failed to connect to signald socket")


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
    logger.info("Shutdown called, closing signald socket")
    close_socket()
    return weechat.WEECHAT_RC_OK


def smsg_cmd_cb(data, buffer, args):
    identifier = None
    if len(args) == 0:
        prnt("Usage: /smsg [number | group]")
    else:
        for number in contacts:
            if number == args or contacts[number].get('name', number).lower() == args.lower():
                identifier = number
                group = None
        if not identifier:
            for group in groups:
                if groups[group]['name'] == args:
                    identifier = group
        if identifier:
            buf = get_buffer(identifier, group is not None)

    return weechat.WEECHAT_RC_OK


def signal_cmd_cb(data, buffer, args):
    if args == 'list groups':
        prnt('List of all available Signal groups:')
        for group in groups:
            prnt(groups[group]['name'])
        prnt('')
    elif args == 'list contacts':
        prnt('List of all available contacts:')
        for number in contacts:
            if contact_name(number) != options['number']:
                prnt('{name}, {number}\n'.format(name=contact_name(number), number=number))
        prnt('')
    else: pass

    return weechat.WEECHAT_RC_OK

def completion_cb(data, completion_item, buffer, completion):
    if weechat.info_get('version', '') <= '2.8':
        for number in contacts:
            weechat.hook_completion_list_add(completion, number, 0, weechat.WEECHAT_LIST_POS_SORT)
            weechat.hook_completion_list_add(completion, contact_name(number).lower(), 0, weechat.WEECHAT_LIST_POS_SORT)
            weechat.hook_completion_list_add(completion, contact_name(number), 0, weechat.WEECHAT_LIST_POS_SORT)
        for group in groups:
            weechat.hook_completion_list_add(completion, groups[group]['name'].lower(), 0, weechat.WEECHAT_LIST_POS_SORT)
            weechat.hook_completion_list_add(completion, groups[group]['name'], 0, weechat.WEECHAT_LIST_POS_SORT)
    else:
        for number in contacts:
            weechat.completion_list_add(completion, number, 0, weechat.WEECHAT_LIST_POS_SORT)
            weechat.completion_list_add(completion, contact_name(number).lower(), 0, weechat.WEECHAT_LIST_POS_SORT)
            weechat.completion_list_add(completion, contact_name(number), 0, weechat.WEECHAT_LIST_POS_SORT)
        for group in groups:
            weechat.completion_list_add(completion, groups[group]['name'].lower(), 0, weechat.WEECHAT_LIST_POS_SORT)
            weechat.completion_list_add(completion, groups[group]['name'], 0, weechat.WEECHAT_LIST_POS_SORT)

    return weechat.WEECHAT_RC_OK

if __name__ == "__main__":
    logger.debug("Preparing to register")
    try:
        if weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE, SCRIPT_DESC, 'shutdown', ''):
            weechat.hook_config('plugins.var.python.%s.*' % SCRIPT_NAME, 'config_changed', '')
            init_config()
            set_log_level()
            smsg_help = [
                "number: the full e164 number (including country code) for the contact",
            ]
            signal_help = [
                "contacts: list all contact names and numbers",
                "groups: list all group names",
            ]
            logger.debug("Registering command...")
            weechat.hook_completion('signal_contact_or_group','Script to complete numbers','completion_cb', '')
            weechat.hook_command("smsg", "Open a buffer to message someone (or some group) on signal", "[<number or group name>]",
                                 "\n".join(smsg_help), "%(number)", "smsg_cmd_cb", "")
            weechat.hook_command("signal", "List contacts or group names", "list [contacts | groups]",
                                 "\n".join(signal_help), "%(list)", "signal_cmd_cb", "")
            init_socket()
    except Exception:
        logger.exception("Failed to initialize plugin.")
