#!/usr/bin/env python3
import weechat
import logging
import socket
import json
import os
import random
import textwrap

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

def get_groupinfo(dictionary):
    groupInfo = None
    if 'group' in dictionary.keys():
        groupInfo = dictionary['group']
    elif 'groupV2' in dictionary.keys():
        groupInfo = dictionary['groupV2']
    return groupInfo


def get_groupid(groupinfo):
    if groupinfo is None:
        return None
    if 'groupId' in groupinfo:
        return groupinfo['groupId']
    elif 'id' in groupinfo:
        return groupinfo['id']


def get_groupname(groupinfo):
    if 'title' in groupinfo:
        return groupinfo['title']
    if 'name' in groupinfo:
        return groupinfo['name']


def get_logfile():
    weechat_dir = weechat.info_get("weechat_data_dir", "") or weechat.info_get("weechat_dir", "") or "~/.weechat"
    return os.path.join(os.path.expanduser(weechat_dir), "logs", "signal.log")

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


def show_msg(uuid, group, message, incoming, tags=[]):
    identifier = uuid if group is None else group
    buf = get_buffer(identifier, group is not None)
    name = "Me"
    if incoming:
        name = contact_name(uuid)
        if group is None:
            # 1:1 messages are private messages
            hotness = weechat.WEECHAT_HOTLIST_PRIVATE
            tags.append("notify_private")
        else:
            # group messages are treated as 'messages'
            hotness = weechat.WEECHAT_HOTLIST_MESSAGE
        weechat.buffer_set(buf, "hotlist", hotness)
    weechat.prnt_date_tags(buf, 0, ",".join(tags),  "%s\t%s" % (name, message))


def contact_name(uuid):
    if uuid == options["number"]:
        return 'Me'
    if uuid in contacts:
        name = contacts[uuid]\
                .get('name', uuid)\
                .strip()
        name = ''.join(x for x in name if x.isprintable())
        return name
    else:
        return uuid

def init_config():
    global default_options, options, logger
    logging.basicConfig(filename=get_logfile())
    logger = logging.getLogger("weechat_script")
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
        "IncomingMessage": message_cb,
        "list_contacts": contact_list_cb,
        "list_groups": group_list_cb,
        "send_results": noop_cb,
        "sync_requested": noop_cb,
        "listen_started": noop_cb,
        "listen_stopped": noop_cb,
        "account_refreshed": noop_cb,
        "ListenerState": noop_cb,
        "send": noop_cb,
        "request_sync": noop_cb,
        "ExceptionWrapper": noop_cb,
        "WebSocketConnectionState": noop_cb,
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
    payload["version"] = "v1"
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
    send("request_sync", account=number)
    send("list_contacts", account=number)
    send("list_groups", account=number)
    send("subscribe", account=number, cb=subscribe_cb, cb_kwargs={"number": number})


def subscribe_cb(payload, number):
    prnt("Successfully subscribed to {}".format(number))


def render_message(message):
    sticker = message.get('sticker')
    if sticker is not None:
        return "<sent sticker>"
    reaction = message.get('reaction')
    if reaction is not None:
        name = contact_name(reaction['targetAuthor']['uuid'])
        em = reaction["emoji"]
        if emoji is not None:
            em = emoji.demojize(em)
        return "<reacted with {} to a message from {}>".format(em, name)
    attachment_msg = ""
    attachments = message.get('attachments')
    if attachments is not None:
        types = [attach['contentType'] for attach in attachments]
        filenames = [attach['storedFilename'] for attach in attachments]
        attachment_msg = "<sent {}>: \n{}\n\n".format(
                ', '.join(types),
                '\n'.join(filenames))

    quote = message.get('quote')
    quote_msg = ""
    if quote is not None:
        quote_msg = quote['text']
        if quote_msg != "":
            wrapper = textwrap.TextWrapper(
                width=64,
                initial_indent="{}> ".format(weechat.color("lightgreen")),
                subsequent_indent="{}> ".format(weechat.color("lightgreen"))
            )
            quote_msg = wrapper.fill(weechat.string_remove_color(quote_msg, "")) + "\n"

    body = message.get('body', "")
    mentions = message.get('mentions', [])
    for mention in mentions[::-1]:
        mentioned = contact_name(mention["uuid"])
        body = "{first_part}{start_highlight}{name}{stop_highlight}{second_part}".format(
                first_part=body[:mention["start"]],
                start_highlight=weechat.color("lightgreen"),
                name=mentioned,
                stop_highlight=weechat.color("chat"),
                second_part=body[mention["start"] + mention["length"]:])

    if emoji is not None:
        body = emoji.demojize(body)

    message_string = attachment_msg + quote_msg + body
    if message_string.strip() == "":
        return None
    else:
        return message_string


def message_cb(payload):
    if payload.get('data_message') is not None:
        message = render_message(payload['data_message'])
        if message is not None:
            groupInfo = get_groupinfo(payload['data_message'])
            group = get_groupid(groupInfo)
            show_msg(payload['source']['uuid'], group, message, True)
    elif payload.get('syncMessage') is not None:
        # some syncMessages are to synchronize read receipts; we ignore these
        if payload['syncMessage'].get('readMessages') is not None:
            return

        # if contactsComplete is present, the contact sync from initial plugin
        # load (or someone else triggering a contacts sync on signald) is
        # complete, and we should update our contacts list.
        if payload['syncMessage'].get('contactsComplete', False):
            send("list_contacts", account=options['number'])
            return

        # we don't know how to render anything besides sync messags with actual
        # 'sent' info.
        if 'sent' not in payload['syncMessage']:
            return

        message = render_message(payload['syncMessage']['sent']['message'])
        groupInfo = get_groupinfo(payload['syncMessage']['sent']['message'])
        group = get_groupid(groupInfo)
        dest = payload['syncMessage']['sent']['destination']['uuid'] if groupInfo is None else None
        show_msg(dest, group, message, False)


def noop_cb(payload):
    pass


def contact_list_cb(payload):
    global contacts

    for contact in payload['profiles']:
        uuid = contact['address']['uuid']
        contacts[uuid] = contact
        logger.debug("Checking for buffers with contact %s", contact)
        if uuid in buffers:
            b = buffers[uuid]
            name = contact_name(uuid)
            set_buffer_name(b, name)


def set_buffer_name(b, name):
    logger.info("Setting buffer name to %s", name)
    weechat.buffer_set(b, "title", name)
    weechat.buffer_set(b, "name", name)
    weechat.buffer_set(b, "shortname", name)


def group_list_cb(payload):
    global groups
    for group in payload.get('groups', []):
        groups[get_groupid(group)] = group
    for group in payload.get('groupsv2', []):
        groups[get_groupid(group)] = group



def setup_group_buffer(groupId):
    global groups
    group = groups[groupId]
    buffer = get_buffer(groupId, True)
    set_buffer_name(buffer, get_groupname(group))
    weechat.buffer_set(buffer, "nicklist", "1")
    weechat.buffer_set(buffer, "nicklist_display_groups", "0")
    for member in group['members']:
        uuid = member['uuid']
        member_name = contact_name(uuid)
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
            name = contact_name(identifier)
            weechat.buffer_set(buffers[identifier], "localvar_set_type", "private")
            set_buffer_name(buffers[identifier], name)
        if isGroup:
            setup_group_buffer(identifier)
        weechat.hook_signal_send("logger_backlog", weechat.WEECHAT_HOOK_SIGNAL_POINTER, buffers[identifier])
    return buffers[identifier]


def encode_message(message):
    if emoji is not None:
        message = emoji.emojize(message, use_aliases=True)
    return message


def buffer_input(uuid, buffer, message):
    encoded = encode_message(message)
    send("send", username=options["number"], recipientAddress={"uuid": uuid}, messageBody=encoded)
    show_msg(uuid, None, message, False)
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
    logger.setLevel(level)
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
        for uuid in contacts:
            if uuid == args or contact_name(uuid).lower() == args.lower():
                print("found your number")
                identifier = uuid
                group = None
        if not identifier:
            for group in groups:
                if get_groupname(groups[group]) == args:
                    identifier = group
        if identifier:
            buf = get_buffer(identifier, group is not None)

    return weechat.WEECHAT_RC_OK


def signal_cmd_cb(data, buffer, args):
    if args == 'list groups':
        prnt('List of all available Signal groups:')
        for group in groups:
            prnt(get_groupname(groups[group]))
        prnt('')
    elif args == 'list contacts':
        prnt('List of all available contacts:')
        for uuid in contacts:
            if contact_name(uuid) != options['number']:
                prnt('{name}, {uuid}\n'.format(name=contact_name(uuid), uuid=uuid))
        prnt('')
    elif args.startswith('attach'):
        attach_cmd_cb(data, buffer, args.lstrip("attach"))
    else: pass

    return weechat.WEECHAT_RC_OK


def attach_cmd_cb(data, buffer, args):
    # check if files exist
    files = [f.strip() for f in args.split(",")]
    for f in files:
        if not os.path.exists(f):
            prnt('could not send attachment: file "{}" could not be found'.format(f))
            return weechat.WEECHAT_RC_ERROR

    # check if buffer is a valid signal buffer and can be found in contacts
    uuid = [n for n in buffers if buffers[n] == buffer]
    if len(uuid) != 1:
        prnt('could not send attachment: buffer {} is no signal'.format(buffer))
        return weechat.WEECHAT_RC_ERROR
    else:
        uuid = uuid[0]

    # determine if it's a group or contact,
    # send files and show confirmation message
    if uuid in groups:
        send("send", username=options["number"], recipientGroupId=uuid, attachments=files)
    else:
        send("send", username=options["number"], recipientAddress={"uuid": uuid}, attachments=files)

    msg = "sent file(s):\n{}".format(files)
    show_msg(uuid, None, msg, False)
    return weechat.WEECHAT_RC_OK


def completion_cb(data, completion_item, buffer, completion):
    for uuid in contacts:
        weechat.completion_list_add(completion, contact_name(uuid).lower(), 0, weechat.WEECHAT_LIST_POS_SORT)
        weechat.completion_list_add(completion, contact_name(uuid), 0, weechat.WEECHAT_LIST_POS_SORT)
    for group in groups:
        weechat.completion_list_add(completion, get_groupname(groups[group]).lower(), 0, weechat.WEECHAT_LIST_POS_SORT)
        weechat.completion_list_add(completion, get_groupname(groups[group]), 0, weechat.WEECHAT_LIST_POS_SORT)

    return weechat.WEECHAT_RC_OK

if __name__ == "__main__":
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
                "attach: one or multiple comma-separated filenames to send as attachment to the conversation of the active buffer",
            ]
            logger.debug("Registering command...")
            weechat.hook_completion('signal_contact_or_group','Script to complete numbers','completion_cb', '')
            weechat.hook_command("smsg", "Open a buffer to message someone (or some group) on signal", "[<number or group name>]",
                                 "\n".join(smsg_help), "%(number)", "smsg_cmd_cb", "")
            weechat.hook_command("signal", "List contacts or group names, or send attachments", "list [contacts | groups | attach]",
                                 "\n".join(signal_help), "%(list)", "signal_cmd_cb", "")
            init_socket()
    except Exception:
        logger.exception("Failed to initialize plugin.")
