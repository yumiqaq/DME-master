Deniable Anonymous Messaging System via Deniable Matchmaking Encryption 

This repository holds a prototype implementation of the authenticated and deniable anonymous messaging system powered by a Deniable Matchmaking Encryption (DME) scheme. It comprises two parts: a web server and a command line client. Concretely, the web server implemented as a service of the anonymous bulletin board is utilized to store data and provides a simple PRST API that allows the clients to upload and download data anonymously. The role of the clients is to serve users to post and read messages. Additionally, in order to cheat the coercer, users can also use the clients to generate a fake random input, possibly some parameters required in the encryption or the key. Particularly, in the implementation of the prototype development, we adopt the anonymous bulletin board over the Tor network (http://bjopwtc2f3umlark.onion/) created by Ateniese et al. in "Match Me if You Can: Matchmaking Encryption and Its Applications." Users can enjoy authenticated and deniable anonymous communication by utilizing the client application to play with the running service in the anonymous bulletin board.

A user who wants to post a message to the anonymous bulletin board can use the client to encrypt it (using his/her DME encryption key and an identity string policy for the intended receiver, possibly also requiring to provide a fake message and an identity string policy of the fake receiver), and upload the ciphertext on the anonymous bulletin board. These ciphertexts are available to anyone. 

A receiver can now use the client to download all the ciphertexts and try to decrypt each one, using the receiver's decryption key and the sender's identity policy. The client will report to the user the outcome of the decryption phase, showing all the successfully decrypted messages.

In the face of coercion, the sender can use the client to obtain a fake input, including a fake encryption key and fake random coins, to cheat the coercer if the generation of his/her ciphertext uses a fake message and an identity string policy of the fake receiver. The fake receiver can also get a fake decryption key from the client, using his/her DME decryption key, the sender's identity string policy and the ciphertext.

You can use the client application to play with the running service in http://bjopwtc2f3umlark.onion/ . Note that the anonymous bulletin board may not be connected. If so, you can run the local bulletin board http://localhost:5000. The local bulletin board service is the same as the anonymous one except it cannot protect users' identity since it does not call the Tor network. That is, you can only enjoy authenticated and deniable communication by utilizing the client application to play with the running service in the local bulletin board. Here, we stress that running a local bulletin board service is also sufficient to test the desired functionalities of authentication and deniability, where these functionalities are provided by the proposed new cryptographic primitive called deniable matchmaking encryption. 

## Client application

### Dependencies

The client application is built with Python 3.7 and depends on [Charm Crypto](https://jhuisi.github.io/charm/index.html) and the `click` and `requests` libraries. It also requires Tor.

For installing Charm Crypto, follow [these instructions](https://jhuisi.github.io/charm/install_source.html).

For `click` and `requests`, you can install them using `pip`:

    pip install click
    pip install requests

### Usage

    $ python3 client.py --help
    Usage: client.py [OPTIONS] COMMAND [ARGS]...

    Options:
      -u, --url TEXT   URL of the bulletin board
      -l, --localhost  Look for the bulletin board in http://localhost:5000
      --help           Show this message and exit.

    Commands:
      hon-post   Honestly posts an encrypted message to the bulletin board
      post       Dishonestly posts an encrypted message to the bulletin board
      peek       Takes a gander at the bulletin board, without decrypting
      read       Honestly reads encrypted messages from the bulletin board
      fake-read  Dishonestly reads encrypted messages from the bulletin board
      rfake      Generates fake dkr by fake receiver
      sfake      Generates fake eks and random by sender

## Server

### Dependencies

The server depends on the `flask` and `flask_restful` libraries.

For `flask` and `flask_restful`, you can install them using `pip`:

    pip install flask
    pip install flask_restful

### Usage

    $ python3 api.py
