from DME import DM
import requests
import base64
import click
import json
import binascii

keys = json.load(open('DME_keys.json'))
# print(keys)
DME = DM()
pk = DME.deserialize_public_key(base64.urlsafe_b64decode(keys["public_key"]))
# del keys["public_key"]
sk = DME.deserialize_secret_key(base64.urlsafe_b64decode(keys["secret_key"]))

# api = "http://bjopwtc2f3umlark.onion"
api = "http://localhost:5000"


def get_session():
    session = requests.session()
    if ".onion" in api:
        session.proxies = {'http': 'socks5h://127.0.0.1:9050',
                           'https': 'socks5h://127.0.0.1:9050'}

    return session


def crc(data):
    return binascii.crc_hqx(data, 0).to_bytes(2, 'big')


@click.group()
@click.option('--url', '-u', help="URL of the bulletin board")
@click.option('--localhost', '-l', is_flag=True, help="Look for the bulletin board in http://localhost:5000")
def cli(url, localhost):
    global api
    if localhost:
        api = "http://localhost:5000"
    if url:
        api = url
        print(f"Using url {api}")


@click.command(help="Generate a normal ciphertext for the encrypted message and post it to the bulletin board")
@click.option('--receiver', prompt="Receiver's policy string", help="Receiver's policy string")
@click.option('--sender', prompt="Sender's encryption key", help="Sender's encryption key")
@click.option('--message', prompt="Message to send", help="Message to send")
# Honesty post message to bulletin board
def post(receiver, sender, message):
    eks = DME.deserialize_eks(keys[sender]["ek"])
    # str type message
    # message = input_message.encode()
    # padded_message = crc(message) + message

    padded_message = str(DME.bytes_to_int(crc(str(int(message)).encode()))) + str(int(message))
    # int type message
    ciphertext = DME.encrypt_int_msg(pk, eks, receiver, int(padded_message))
    # ciphertext = DME.encrypt(pk, eks, receiver, padded_message)

    ctxt = DME.serialize_ciphertext(ciphertext)
    b64_ctxt = base64.urlsafe_b64encode(ctxt)
    click.echo(b"Ciphertext: " + b64_ctxt)
    res = get_session().put(f'{api}/messages', data={'message': b64_ctxt}).json()
    click.echo(f"Index of the message: {res}")


@click.command(help="Generate a normal ciphertext for the encrypted message and post it to the bulletin board")
@click.option('--receiver', prompt="Receiver's policy string", help="Receiver's policy string")
@click.option('--fake_receiver', prompt="Fake receiver's policy string", help="Fake receiver's policy string")
@click.option('--sender', prompt="Sender's encryption key", help="Sender's encryption key")
@click.option('--message', prompt="Message to send", help="Message to send")
@click.option('--fake_message', prompt="Fake message to send", help="Fake message to send")
def de_post(receiver, fake_receiver, sender, message, fake_message):
    # Dishonesty post message to bulletin board
    eks = DME.deserialize_eks(keys[sender]["ek"])
    # str type message
    # message = input_message.encode()
    # padded_message = crc(message) + message

    padded_message = str(DME.bytes_to_int(crc(str(int(message)).encode()))) + str(int(message))
    padded_fake_message = str(DME.bytes_to_int(crc(str(int(fake_message)).encode()))) + str(int(fake_message))
    # int type message
    ciphertext = DME.denc(pk, eks, receiver, fake_receiver, int(padded_message), int(padded_fake_message))
    # ciphertext = DME.encrypt(pk, eks, receiver, padded_message)

    ctxt = DME.serialize_ciphertext(ciphertext)
    b64_ctxt = base64.urlsafe_b64encode(ctxt)
    click.echo(b"Ciphertext: " + b64_ctxt)
    res = get_session().put(f'{api}/messages', data={'message': b64_ctxt}).json()
    click.echo(f"Index of the message: {res}")


@click.command(help="Take a gander at the bulletin board, without decrypting")
def peek():
    res = get_session().get(f'{api}/messages').json()
    for i, message in enumerate(res):
        click.echo(f"({i}): {message}")


def decrypt_ciphertext(dk, b64_ctxt, sender, receiver):
    ctxt = base64.urlsafe_b64decode(b64_ctxt)
    ciphertext = DME.deserialize_ciphertext(ctxt)
    padded_message = str(DME.decrypt(dk, receiver, sender, ciphertext))
    # padded_message[:-num], num is the length of int message
    pad, message = padded_message[:-10], padded_message[-10:]
    return message if str(DME.bytes_to_int(crc(str(int(message)).encode()))) == pad else None
    # return padded_message


@click.command(help="Read encrypted messages from the bulletin board")
@click.option('--receiver', prompt="Receiver's policy string", help="Receiver's policy string")
@click.option('--sender', prompt="Sender's attribute string", help="Sender's attribute string")
def read(receiver, sender):
    dk = DME.deserialize_tuple(base64.urlsafe_b64decode(keys[receiver]["dk"]))
    ciphertexts = get_session().get(f'{api}/messages').json()
    for i, b64_ctxt in enumerate(ciphertexts):
        message = decrypt_ciphertext(dk, b64_ctxt, sender, receiver)
        if message:
            click.echo(f"{i}: {message}")


def decrypt_fake_ciphertext(dkr_, fkr, b64_ctxt, sender, fake_receiver):
    ctxt = base64.urlsafe_b64decode(b64_ctxt)
    ciphertext = DME.deserialize_ciphertext(ctxt)
    dk_r_ = DME.rfake('dave', dkr_, fkr, ciphertext)
    padded_message = str(DME.decrypt(dk_r_, fake_receiver, sender, ciphertext))
    pad, message = padded_message[:-10], padded_message[-10:]
    return message if str(DME.bytes_to_int(crc(str(int(message)).encode()))) == pad else None
    # return padded_message


@click.command(help="Read fake messages from the bulletin board by using fake decryption key")
@click.option('--fake_receiver', prompt="Fake receiver's policy string", help="Fake receiver's policy string")
@click.option('--sender', prompt="Sender's attribute string", help="Sender's attribute string")
def de_read(fake_receiver, sender):
    dkr_, fkr = DME.deserialize_drgen(base64.urlsafe_b64decode(keys[fake_receiver]["fake dk"]))
    ciphertexts = get_session().get(f'{api}/messages').json()
    for i, b64_ctxt in enumerate(ciphertexts):
        message = decrypt_fake_ciphertext(dkr_, fkr, b64_ctxt, sender, fake_receiver)
        if message:
            click.echo(f"{i}: {message}")


@click.command(help="Generate a fake encryption key eks and fake random coins for the sender")
@click.option('--sender', prompt="Sender's attribute string", help="Sender's attribute string")
@click.option('--fake_receiver', prompt="Fake receiver's policy string", help="Fake receiver's policy string")
@click.option('--u', prompt="random", help="random")
def sfake(sender, fake_receiver, u):
    eks = DME.deserialize_eks(keys[sender]["ek"])
    r = int(u)
    eks_, r_ = DME.sfake(pk, eks, fake_receiver, r)
    click.echo(f"fake eks is: {eks_}")
    click.echo(f"fake random is: {r_}")


@click.command(help="Generate a fake decryption key dkr for the fake receiver")
@click.option('--fake_receiver', prompt="Fake receiver's policy string", help="Fake receiver's policy string")
@click.option('--b64_ctxt', prompt="Ciphertext from bulletin board", help="Ciphertext from bulletin board")
def rfake(fake_receiver, b64_ctxt):
    (dkr_, fkr) = DME.drgen(sk, fake_receiver)
    ctxt = base64.urlsafe_b64decode(b64_ctxt)
    ciphertext = DME.deserialize_ciphertext(ctxt)
    fake_dkr = DME.rfake(fake_receiver, dkr_, fkr, ciphertext)
    click.echo(f"fake dkr is: {fake_dkr}")


cli.add_command(post)
cli.add_command(de_post)
cli.add_command(peek)
cli.add_command(read)
cli.add_command(de_read)
cli.add_command(rfake)
cli.add_command(sfake)

if __name__ == '__main__':
    cli()
