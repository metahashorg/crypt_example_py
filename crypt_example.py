#!/usr/bin/python3
# coding: utf-8

import sys
import hashlib
import binascii
import argparse
try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat
except ImportError:
    print("Something went wrong, check your cryptography module installation")
    exit(1)

try:
    import dns.resolver
except ImportError:
    print("Something went wrong, check your dnspython module installation")
    exit(1)

try:
    import requests
except ImportError:
    print("Something went wrong, check your requests module installation")
    exit(1)

try:
    import json
except ImportError:
    print("Something went wrong, check your json module installation")
    exit(1)

PROXY = 'proxy.net-%s.metahash.org'
PROXY_PORT = 9999
TORRENT = 'tor.net-%s.metahash.org'
TORRENT_PORT = 5795
SUBPARSERS = {}


def check_args(current_args, args_for_check, parser_name):
    if 'net' in args_for_check and current_args.net is None:
        print("Something went wrong, requires an argument 'net'")
        SUBPARSERS[parser_name].print_help()
        return False
    elif 'address' in args_for_check and current_args.address is None:
        print("Something went wrong, requires an argument 'address'")
        SUBPARSERS[parser_name].print_help()
        return False
    return True


def get_ip_from_dns(url, net):
    url = url % net

    try:
        return dns.resolver.Resolver().query(url).rrset.items[0].address
    except dns.exception.Timeout as e:
        print("Timeout operation timed out after %r seconds - your computer is"
              " offline." % e.kwargs['timeout'])
        exit(1)


def request_post(ip, port, func, data):
    req_url = "http://%s:%d/%s" % (ip, port, func)

    try:
        return requests.post(req_url, json=data)
    except requests.exceptions.ConnectionError:
        print("Something went wrong. Failed to establish a new connection: "
              "[Errno 111] Connection refused.")
        exit(1)


def response_to_json(response):
    res_json = json.loads(response.text)
    return json.dumps(res_json, indent=4, separators=(',', ': '))


def fetch_balance(address, net):
    addr = get_ip_from_dns(TORRENT, net)

    response = request_post(addr, TORRENT_PORT, 'fetch-balance',
                            {"id": 1, "params": {"address": address}})

    return response_to_json(response)


def fetch_history(address, net):
    addr = get_ip_from_dns(TORRENT, net)

    response = request_post(addr, TORRENT_PORT, 'fetch-history',
                            {"id": 1, "params": {"address": address}})

    return response_to_json(response)
def create_parser():
    parser = argparse.ArgumentParser(description='Crypt example python',
                                     prog='crypt_example.py',
                                     usage='python %(prog)s [functions]')
    subparsers = parser.add_subparsers(title='List of functions',
                                       metavar='', dest='subparser_name')

    subparsers.add_parser('generate',
                          help='generate MH address to mh_address.txt')

    balance_parser = subparsers.add_parser('fetch-balance',
                                           description='Get balance for MH address',
                                           prog='crypt_example.py fetch-balance [args]',
                                           usage='python %(prog)s',
                                           help='get balance for MH address')
    balance_parser.add_argument('--net', action='store', type=str, nargs=1,
                                help='name of network (test, dev, main, etc.)')
    balance_parser.add_argument('--address', action='store', type=str,
                                help='MH address', nargs=1)
    SUBPARSERS['balance_parser'] = balance_parser

    history_parser = subparsers.add_parser('fetch-history',
                                           description='Get history for MH address',
                                           prog='crypt_example.py fetch-history [args]',
                                           usage='python %(prog)s',
                                           help="get history for MH address")
    history_parser.add_argument('--net', action='store', type=str, nargs=1,
                                help='name of network (test, dev, main, etc.)')
    history_parser.add_argument('--address', action='store', type=str,
                                help='MH address', nargs=1)
    SUBPARSERS['history_parser'] = history_parser
    return parser


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
    print("Step 1. Generate rpivate and public keys. Take part of the public "
          "key that equals to 65 bytes.")

    private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
    private_key_pem = private_key.private_bytes(encoding=Encoding.PEM,
                                format=PrivateFormat.TraditionalOpenSSL,
                                encryption_algorithm=NoEncryption())
    save_to_file(private_key_pem.decode("utf-8"), "mh_private.pem")

    pub_key = private_key.public_key()
    pub_key_der = pub_key.public_bytes(encoding=Encoding.DER,
                                       format=PublicFormat.SubjectPublicKeyInfo)
    pub_key_pem = binascii.b2a_hex(pub_key_der)
    save_to_file(pub_key_pem.decode("utf-8"), "mh_public.pub")

    code = get_code(pub_key)
    print("Done")

    print("Step 2. Perform SHA-256 hash on the public key.")
    resulrt_sha256 = hash_code(code, 'sha256')
    print("Done")

    print("Step 3. Perform RIPEMD-160 hash on the result of previous step.")
    resulrt_rmd160 = '00' + hash_code(resulrt_sha256.encode('utf-8'), 'rmd160')
    print("Done")

    print("Step 4. SHA-256 hash is calculated on the result of previous step.")
    resulrt_sha256rmd = hash_code(resulrt_rmd160.encode('utf-8'), 'sha256')
    print("Done")

    print("Step 5. Another SHA-256 hash performed on value from Step 4 and "
          "save first 4 bytes.")
    resulrt_sha256rmd_again = hash_code(resulrt_sha256rmd.encode('utf-8'),
                                        'sha256')
    first4_resulrt_sha256rmd_again = resulrt_sha256rmd_again[:8]
    print("Done")

    print("Step 6. These 4 bytes from last step added to RIPEMD-160 hash with "
          "prefix 0x. ")
    address = '0x' + resulrt_rmd160 + first4_resulrt_sha256rmd_again
    save_to_file(address, "mh_address.txt")

    print("Your Metahash address is %s" % address)


if __name__ == '__main__':
    arg_parser = create_parser()
    option = arg_parser.parse_args(sys.argv[1:])

    if option.subparser_name == 'generate':
        print("Start generate MetaHash address...")
        generate_metahash_address()
    elif option.subparser_name == 'fetch-balance' and \
            check_args(option, ['net', 'address'], 'balance_parser'):
        print(fetch_balance(option.address[0], option.net[0]))
    elif option.subparser_name == 'fetch-history' and \
            check_args(option, ['net', 'address'], 'history_parser'):
        print(fetch_history(option.address[0], option.net[0]))
    else:
        arg_parser.print_help()
