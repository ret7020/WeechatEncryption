import weechat
import logging
import base64

from twofish import Twofish

def tfencrypt(data: str, password: str) -> bytes:
    bs = 16 #block size 128 bits
    plaintext = data

    if len(plaintext) % bs: #add padding 
	    padded_plaintext = str(plaintext + '%' * (bs - len(plaintext) % bs)).encode('utf-8')
    else:
	    padded_plaintext=plaintext.encode('utf-8')

    T = Twofish(str.encode(password))
    ciphertext = b''
    for x in range(int(len(padded_plaintext) / bs)):
	    ciphertext += T.encrypt(padded_plaintext[x * bs: ( x+ 1) * bs])

    return ciphertext

def tfdecrypt(data_bin: bytes, password: str) -> bytes:
    bs = 16 # block size 128 bits
    ciphertext = data_bin
    T = Twofish(str.encode(password))
    plaintext = b''

    for x in range(int(len(ciphertext) / bs)):
        plaintext += T.decrypt(ciphertext[x * bs: (x + 1) * bs])

    return str.encode(plaintext.decode('utf-8').strip('%'))



logging.basicConfig(filename='encr.log', encoding='utf-8', level=logging.DEBUG)

weechat.register("test_python", "FlashCode", "1.0",
                 "MIT", "Script for encryption", "", "")
weechat.prnt("", "Hello, from python script!")
# buffer = weechat.info_get("irc_buffer", "libera,#weechat")


# Config
KEYS = {
    "oftc": {
        "#test_dev_plg": "TEST KEY"
    }
}


def debug(msg):
    if str(weechat.config_get_plugin("debug")) != "0":
        weechat.prnt("", "[weechatenc] DEBUG: %s" % msg)


def get_key_for_channel(server, channel):

    # /set plugins.var.python.encryption.passphrase.oftc.#test_dev_plg = 123

    # config_location = "passphrase.%s.%s" % (server, channel)
    # config_prefix = "plugins.var.python.encryption"
    # channel_key = weechat.config_get_plugin(config_location)
    # logging.debug(config_location)

    # if len(channel_key) < 1 or channel_key is None:
    #     debug("Recieved an encrypted message, but passphrase is"
    #                      " not set for channel %s on network %s"
    #                      % (channel, server))
    #     debug("Use '/set %s.%s SOME_KEY' to enable encryption."
    #                      % (config_prefix, config_location))
    #     return None

    # return channel_key
    if server in KEYS:
        if channel in KEYS[server]:
            return KEYS[server][channel]

    return None


def weechat_decrypt(data, msgtype, servername, args):
    # Decrypt message here
    
    hostmask, chanmsg = args.split("PRIVMSG ", 1)
    channelname, message = args.split(" :", 1)
    channelname = channelname.split(" ")[-1]
    logging.debug(channelname)
    if message[:5] != "!ENC ":
        return args
    
    key = get_key_for_channel(servername, channelname)
    
    message = message[5:]
    decrypted = tfdecrypt(base64.b64decode(message), key)
    cmd = hostmask + "PRIVMSG " + channelname + " :" + decrypted.decode("utf-8")
    logging.debug(cmd)
    return cmd


def weechat_encrypt(data, msgtype, servername, args):
    # Encrypt message here
    pre, message = args.split(":", 1)

    hostmask, chanmsg = args.split("PRIVMSG ", 1)
    channelname, message = chanmsg.split(" :", 1)

    channel_key = get_key_for_channel(servername, channelname)
    logging.debug(f"Using key: {channel_key}")
    # logging.debug(f"Key: {channel_key}")

    # If this channel work in plain-text format
    if channel_key is None:
        return args

    # encrypt message
    encrypted = tfencrypt(message, channel_key)
    encrypted = base64.b64encode(encrypted).decode("utf-8")
    logging.debug(encrypted)

    returning = pre + ":" + "!ENC " + encrypted
    return returning


weechat.hook_modifier("irc_in2_privmsg", "weechat_decrypt", "")
weechat.hook_modifier("irc_out_privmsg",
                      "weechat_encrypt", "")
