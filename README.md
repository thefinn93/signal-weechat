# Signal Weechat

Use Signal (via [signald](https://gitlab.com/thefinn93/signald)) in weechat.

## Dependencies

Required:

* Weechat
* signald

Optional:
* [qrcode](https://pypi.python.org/pypi/qrcode) python library (`pip install qrcode`/`apt install python-qrcode`) - required to render QR codes when linking to new devices


## Installing

1. Install this script: `cp signal.py ~/.weechat/python/signal.py`
2. Load it in weechat: `/python load signal.py`
3. Either link to an existing device: `/signal link` or register a new account: `/signal register +12024561414`


## Use

`/smsg +12025551212 hi! I'm texting you from weechat!`
`/signal list contacts`
`/signal list groups`


## Limitations

Some current limitations:

* Can only register one number.
* No read receipts

## TODO

* Handle syncMessage read receipts

## Support

Feel free to file an issue

## Contributing

Pull requests welcome.
