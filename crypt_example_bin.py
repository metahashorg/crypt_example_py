#!/usr/bin/python3
# coding: utf-8

import sys
if sys.version_info < (3,5):
    print('You use Python version lower than 3.5. For this script work use Python version 3.5 and more.')
    exit(1)

import hashlib
import random
import json
import binascii
import argparse

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat
    from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
except ImportError:
    print('Something went wrong, check your cryptography module installation (pip install cryptography)')
    exit(1)
try:
    import dns.resolver
except ImportError:
    print('Something went wrong, check your dnspython module installation (pip install dnspython)')
    exit(1)
try:
    import requests
except ImportError:
    print('Something went wrong, check your requests module installation (pip install requests)')
    exit(1)


PROXY = 'proxy.net-%s.metahashnetwork.com'
PROXY_PORT = 9999
TORRENT = 'tor.net-%s.metahashnetwork.com'
TORRENT_PORT = 5795
COUNT_RETRY = 5


def create_parser():
    parser = argparse.ArgumentParser(description='Crypt example python',
                                     prog='python crypt_example.py')
    subparsers = parser.add_subparsers(title='List of functions',
                                       metavar='', dest='subparser_name')

    subparsers.add_parser('generate',
                          help='generate MH address to mh_address.txt')

    balance_parser = subparsers.add_parser('fetch-balance',
                                           description='Get balance for MH address',
                                           prog='python crypt_example.py fetch-balance',
                                           help='get balance for MH address')
    balance_parser.add_argument('--net', action='store', type=str, nargs=1,
                                help='name of network (test, dev, main, etc.)', required=True)
    balance_parser.add_argument('--address', action='store', type=str,
                                help='MH address', nargs=1, required=True)

    history_parser = subparsers.add_parser('fetch-history',
                                           description='Get history for MH address',
                                           prog='python crypt_example.py fetch-history',
                                           help='get history for MH address')
    history_parser.add_argument('--net', action='store', type=str, nargs=1,
                                help='name of network (test, dev, main, etc.)', required=True)
    history_parser.add_argument('--address', action='store', type=str,
                                help='MH address', nargs=1, required=True)

    get_tx_parser = subparsers.add_parser('get-tx',
                                          description='Get transaction information by hash',
                                          prog='python crypt_example.py get-tx',
                                          help='get transaction information by hash')
    get_tx_parser.add_argument('--net', action='store', type=str, nargs=1,
                               help='name of network (test, dev, main, etc.)', required=True)
    get_tx_parser.add_argument('--hash', action='store', type=str, nargs=1,
                               help='transaction hash', required=True)

    create_tx_parser = subparsers.add_parser('create-tx',
                                             description='Create transaction from input params',
                                             prog='python crypt_example.py create-tx',
                                             help='create transaction using input params')
    create_tx_parser.add_argument('--net', action='store', type=str, nargs=1,
                                     help='name of network (test, dev, main, etc.)', required=True)
    create_tx_parser.add_argument('--to', action='store', type=str, nargs=1,
                                     help='to MH wallet address', required=True)
    create_tx_parser.add_argument('--value', action='store', type=str, nargs=1,
                                     help='value to send', required=True)
    create_tx_parser.add_argument('--nonce', action='store', type=str, nargs=1,
                                     help='number of outgoing transactions + 1')
    create_tx_parser.add_argument('--privkey', action='store', type=str, nargs=1,
                                     help='path to private key file', required=True)
    create_tx_parser.add_argument('--data', action='store', type=str, nargs=1,
                                     help='data to send')

    sending_tx_parser = subparsers.add_parser('send-tx',
                                              description='Create transaction and sending',
                                              prog='python crypt_example.py send-tx',
                                              help='create and send transaction')
    sending_tx_parser.add_argument('--net', action='store', type=str, nargs=1,
                                   help='name of network (test, dev, main, etc.)', required=True)
    sending_tx_parser.add_argument('--to', action='store', type=str, nargs=1,
                                   help='to MH wallet address', required=True)
    sending_tx_parser.add_argument('--value', action='store', type=str, nargs=1,
                                   help='value to send', required=True)
    sending_tx_parser.add_argument('--privkey', action='store', type=str, nargs=1,
                                     help='path to private key file', required=True)
    sending_tx_parser.add_argument('--data', action='store', type=str, nargs=1,
                                     help='data to send')

    return parser


def get_ip_from_dns(url, net, except_ip=''):
    url = url % net

    try:
        items = dns.resolver.Resolver().query(url).rrset.items
        return items[0].address
    except dns.exception.Timeout as e:
        print("Timeout operation timed out after %r seconds - your computer is"
              " offline." % e.kwargs['timeout'])
        exit(1)


def proxy_request_post(data, net, except_ip='', current_try=0):
    addr = PROXY
    port = PROXY_PORT

    ip = get_ip_from_dns(addr, net)

    req_url = "http://%s:%d" % (ip, port)
    headers = {'Content-Type': 'application/json', 'Accept': 'text/plain'}

    try:
        return requests.post(req_url, data=json.dumps(data),
                            headers=headers, timeout=(3.0, 3.0))
    except requests.exceptions.ConnectionError:
        if current_try < COUNT_RETRY:
            return proxy_request_post(data, net, except_ip=ip, 
                            current_try=current_try+1)
        else:
            print(f"Something went wrong. Failed to establish a new connection: "
                    f"[Errno 111] Connection refused. {ip}:{port}")
            exit(1)


def torrent_request_post(func, data, net, except_ip='', current_try=0):
    addr = TORRENT
    port = TORRENT_PORT

    ip = get_ip_from_dns(addr, net, except_ip=except_ip)
    req_url = "http://%s:%d/%s" % (ip, port, func)

    try:
        return requests.post(req_url, json=data, timeout=(3.0, 3.0))
    except requests.exceptions.ConnectionError:
        if current_try < COUNT_RETRY:
            return torrent_request_post(func, data, net, except_ip=ip, 
                            current_try=current_try+1)
        else:
            print(f'Something went wrong. Failed to establish a new connection: '
                    f'[Errno 111] Connection refused. {ip}:{port}/{func}')
            exit(1)


def response_to_json(response):
    try:
        res_json = json.loads(response.text)
    except json.decoder.JSONDecodeError:
        print("Something went wrong. Not valid json received from server")
        exit(1)
    return json.dumps(res_json, indent=4, separators=(',', ': '))


def get_addr_from_pubkey(pub_key, with_logging=True):
    if with_logging: print("Step 2. Perform SHA-256 hash on the public key.")
    resulrt_sha256 = hash_code(pub_key, 'sha256')
    if with_logging: print("Done")

    if with_logging: print("Step 3. Perform RIPEMD-160 hash on the result of previous step.")
    resulrt_rmd160 = '00' + hash_code(resulrt_sha256.encode('utf-8'), 'rmd160')
    if with_logging: print("Done")

    if with_logging: print("Step 4. SHA-256 hash is calculated on the result of previous step.")
    resulrt_sha256rmd = hash_code(resulrt_rmd160.encode('utf-8'), 'sha256')
    if with_logging: print("Done")

    if with_logging: print("Step 5. Another SHA-256 hash performed on value from Step 4. "
          "Save first 4 bytes.")
    resulrt_sha256rmd_again = hash_code(resulrt_sha256rmd.encode('utf-8'),
                                        'sha256')
    first4_resulrt_sha256rmd_again = resulrt_sha256rmd_again[:8]
    if with_logging: print("Done")

    if with_logging: print("Step 6. These 4 bytes from last step added to RIPEMD-160 hash with "
          "prefix 0x. ")
    address = '0x' + resulrt_rmd160 + first4_resulrt_sha256rmd_again
    return address


def save_to_file(text, file_name):
    with open(file_name, 'w') as f:
        f.write(text)


def hex_point_coordinate(coordinate_value):
    value_hex = hex(coordinate_value)
    value_hex = value_hex[2:]
    value_len = 64 - len(value_hex)
    return value_hex if value_len <= 0 else '0' * value_len + value_hex


def get_code(pub_key):
    x_hex = hex_point_coordinate(pub_key.public_numbers().x)
    y_hex = hex_point_coordinate(pub_key.public_numbers().y)
    return '04' + str(x_hex) + str(y_hex)


def hash_code(code, algth):
    h = hashlib.new(algth)
    h.update(binascii.a2b_hex(code))
    return h.hexdigest()


def generate_metahash_address():
    print("Start generate MetaHash address...")
    print("Step 1. Generate private and public keys. Take part of the public "
          "key that equals to 65 bytes.")

    private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
    private_key_pem = private_key.private_bytes(encoding=Encoding.PEM,
                                format=PrivateFormat.TraditionalOpenSSL,
                                encryption_algorithm=NoEncryption())

    pub_key = private_key.public_key()
    pub_key_pem = pub_key.public_bytes(encoding=Encoding.PEM,
                                   format=PublicFormat.SubjectPublicKeyInfo)

    code = get_code(pub_key)
    address = get_addr_from_pubkey(code)

    save_to_file(private_key_pem.decode("utf-8"), "%s_private.pem" % address)
    save_to_file(pub_key_pem.decode("utf-8"), "%s_public.pub" % address)
    save_to_file(address, "%s.txt" % address)

    print("Your Metahash address is %s" % address)


def fetch_balance(address, net):
    response = torrent_request_post('fetch-balance',
                {"id": 1, "params": {"address": address}}, net)

    return response_to_json(response)


def fetch_history(address, net):
    response = torrent_request_post('fetch-history',
                    {"id": 1, "params": {"address": address}}, net)

    return response_to_json(response)


def get_tx(hash, net):
    response = torrent_request_post('get-tx',
                    {"id": 1, "params": {"hash": hash}}, net)

    return response_to_json(response)


def little_ending(bytes):
    res_str = ''

    while len(bytes):
        res_str += bytes[-2:]
        bytes = bytes[:-2]

    return res_str


def int_to_hex(value):
    low_border = 250
    read_int16 = 'fa'
    read_int32 = 'fb'
    read_int64 = 'fc'
    read_int128 = 'fd'
    read_int256 = 'fe'
    read_int512 = 'ff'

    bit = value.bit_length()

    if value < low_border:
        return '%02x' % value
    elif value >= low_border and bit <= 16:
        return read_int16 + little_ending('%.4x' % value)
    elif bit > 16 and bit <= 32:
        return read_int32 + little_ending('%.8x' % value)
    elif bit > 32 and bit <= 64:
        return read_int64 + little_ending('%.16x' % value)
    elif bit > 64 and bit <= 128:
        return read_int128 + little_ending('%.32x' % value)
    elif bit > 128 and bit <= 256:
        return read_int256 + little_ending('%.64x' % value)
    elif bit > 256 and bit <=512:
        return read_int512 + little_ending('%.128x' % value)


def get_signed_line(to_addr, value, nonce, fee, data):
    result_str = ''

    value = int(value)
    nonce = int(nonce)
    fee = int(fee)
    len_data = int(len(data) / 2)

    if to_addr.startswith('0x'):
        result_str += to_addr[2:]
    else:
        result_str += to_addr
    result_str += int_to_hex(value)
    result_str += int_to_hex(fee)
    result_str += int_to_hex(nonce)
    result_str += int_to_hex(len_data)
    result_str += data

    return binascii.unhexlify(result_str)


def str_to_hex(str_data):
    byte_data = str.encode(str_data)
    hex_data = binascii.hexlify(byte_data)
    return hex_data.decode()


def create_tx(to_addr, value, privkey, nonce=None, fee=0, data='', net=None):
    priv_key = load_pem_private_key(privkey, password=None,
                               backend=default_backend())
    pub_key = priv_key.public_key()
    hex_data = str_to_hex(data)
    fee = len(data)

    if nonce is None:
        mh_address = get_addr_from_pubkey(get_code(pub_key), with_logging=False)
        req_json = json.loads(fetch_balance(mh_address, net))
        nonce = req_json['result']['count_spent'] + 1
        nonce = str(nonce)

    message = get_signed_line(to_addr, value, nonce, fee, hex_data)

    signature = priv_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )

    pub_key_der = pub_key.public_bytes(encoding=Encoding.DER,
                                   format=PublicFormat.SubjectPublicKeyInfo)

    req_data = {"jsonrpc": "2.0", "method": "mhc_send", "params":
               {"to": to_addr, "value": value, "fee": str(fee),
               "nonce": nonce, "data": hex_data, "pubkey": binascii.b2a_hex(pub_key_der).decode(),
               "sign": binascii.b2a_hex(signature).decode()}}

    # offline mode
    if net is None:
        return json.dumps(req_data, indent=4, separators=(',', ': '))
    else: # online mode
        print(json.dumps(req_data, indent=4, separators=(',', ': ')))
        res = proxy_request_post(req_data, net)

        return response_to_json(res)


if __name__ == '__main__':
    arg_parser = create_parser()
    option = arg_parser.parse_args(sys.argv[1:])

    if option.subparser_name == 'generate':
        generate_metahash_address()
    elif option.subparser_name == 'fetch-balance':
        print(fetch_balance(option.address[0], option.net[0]))
    elif option.subparser_name == 'fetch-history':
        print(fetch_history(option.address[0], option.net[0]))
    elif option.subparser_name == 'get-tx':
        print(get_tx(option.hash[0], option.net[0]))
    elif option.subparser_name == 'create-tx':
        with open(option.privkey[0], 'rb') as f:
            pr = f.read()
        data = option.data[0] if not option.data is None else ''
        print(create_tx(option.to[0], option.value[0], pr,
                           nonce=option.nonce[0], data=data))
    elif option.subparser_name == 'send-tx':
        with open(option.privkey[0], 'rb') as f:
            pr = f.read()
        data = option.data[0] if not option.data is None else ''
        print(create_tx(option.to[0], option.value[0], pr,
                           net=option.net[0], data=data))
    else:
        arg_parser.print_help()
