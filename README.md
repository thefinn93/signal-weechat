# Signal Weechat

Use Signal (via [signal-cli](https://github.com/AsamK/signal-cli)) in weechat.

## Dependencies

Required:

* Weechat
* python-dbus (`pip install dbus-python`/`apt install python-dbus`)
* java - to run signal-cli

Optional:
* [signal-cli](https://github.com/AsamK/signal-cli) - If you don't have it, run `/signal upgrade` to download and install the latest version
* [qrcode](https://pypi.python.org/pypi/qrcode) python library (`pip install qrcode`/`apt install python-qrcode`) - required to render QR codes when linking to new devices


## Installing

1. Install this script: `cp signal.py ~/.weechat/python/signal.py`
2. Load it in weechat: `/python load signal.py`
3. Either link to an existing device: `/signal link` or register a new account: `/signal register +12024561414`


## Use

`/smsg +12025551212 hi! I'm texting you from weechat!`


## Limitations

There are numerous issues in the GitHub issues for this project, but the following limitations are imposed
by signal-cli's dbus interface. Some of them have open issues on signal-cli:

* Can only register one number.
* No read receipts

## Support

good luck. No but seriously, feel free to file an issue, just no promises of support.


## Contributing

Pull requests welcome.
