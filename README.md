# Crypt example python

This repository contains a script written in Python that describes the algorithm for the Metahash address generation using cryptography module, fetching balance and history for wallet, creating and sending transaction as well as getting information about performing transaction by hash. To find out more about all actions in the Metahash network please follow these links: [Getting started with Metahash network](https://developers.metahash.org/hc/en-us/articles/360002712193-Getting-started-with-Metahash-network), [Creating transactions](https://developers.metahash.org/hc/en-us/articles/360003271694-Creating-transactions) and [Operations with MetaHash address](https://developers.metahash.org/hc/en-us/articles/360008382213-Operations-with-MetaHash-address).

## Dependencies

- Install Python 3.
- Install pip (if it is not installed along with Python).
- Install the following modules using pip:

```shell
pip install cryptography
pip install dnspython
pip install requests
```

## Usage

Common usage is

```shell
usage: python crypt_example_bin.py [functions]

Crypt example python

optional arguments:
  -h, --help        show this help message and exit

List of functions:
  
    generate        generate MH address to mh_address.txt
    fetch-balance   get balance for MH address
    fetch-history   get history for MH address
    get-tx          get transaction information by hash
    create-tx       create transaction using input params
    send-tx         create and send transaction
```
For more information, see [Usage](https://github.com/metahashorg/crypt_example_py/wiki/Usage).

## Creating transaction

See [Creating transaction](https://github.com/metahashorg/crypt_example_py/wiki/Creating-transaction)

## Examples

See [Examples](https://github.com/metahashorg/crypt_example_py/wiki/Examples)
