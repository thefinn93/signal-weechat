# Signal Weechat

Use Signal (via [signal-cli](https://github.com/AsamK/signal-cli)) in weechat.

## Requirements

* [signal-cli](https://github.com/AsamK/signal-cli)
* Weechat
* python-dbus


## Installing

1. Setup signal-cli:
```bash
signal-cli -u +12024561414 register
signal-cli -u +12024561414 verify 999999
```
3. Install this script: `cp signal.py ~/.weechat/python/signal.py`
4. Load it in weechat: `/python load signal.py`
5. Run signal-cli in daemon mode: `signal-cli -u +12024561414 daemon`
6. Run signal.py daemon: `python ~/.weechat/signal/signal.py ~/.weechat/signal.sock`.


## Use

`/signal +12025551212 hi! I'm texting you from weechat!`


## Limitations

There are numerous issues in the GitHub issues for this project, but the following limitations are imposed
by signal-cli's dbus interface. Some of them have open issues on signal-cli:

* No contact or group names yet. ([#55](https://github.com/AsamK/signal-cli/issues/55))
* Can't register or link other devices.
* Can only register one number.
* No read receipts

## Support

good luck. No but seriously, feel free to file an issue, just no promises of support.


## Contributing

Pull requests welcome.
