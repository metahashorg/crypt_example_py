# Crypt example python

This repository contains a script written in Python that describes the algorithm for the Metahash address generation using cryptography module, fetching balance and history for wallet, creating and sending transaction as well as getting information about performing transaction by hash.

## Dependencies

```shell
pip install python3
pip install cryptography
pip install dnspython
pip install requests
```

## Usage

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

### Outputs

```shell
mh_private.pem - private key file
mh_public.pub - public key file
mh_address.txt - metahash address file
```

### Outputs examples

```shell
#python crypt_example_bin.py generate
Start generate MetaHash address...
Step 1. Generate private and public keys. Take part of the public key that equals to 65 bytes.
Step 2. Perform SHA-256 hash on the public key.
Done
Step 3. Perform RIPEMD-160 hash on the result of previous step.
Done
Step 4. SHA-256 hash is calculated on the result of previous step.
Done
Step 5. Another SHA-256 hash performed on value from Step 4.  Save first 4 bytes.
Done
Step 6. These 4 bytes from last step added to RIPEMD-160 hash with prefix 0x. 
Your Metahash address is 0x003d3b27f544d1dc03d6802e6379fdcfc25e0b73272b62496b

#python crypt_example_bin.py fetch-balance --net=dev --address=0x003d3b27f544d1dc03d6802e6379fdcfc25e0b73272b62496b
{
    "id": 1,
    "result": {
        "address": "0x003d3b27f544d1dc03d6802e6379fdcfc25e0b73272b62496b",
        "received": 10000,
        "spent": 2000,
        "count_received": 1,
        "count_spent": 2,
        "block_number": 1501,
        "currentBlock": 1512
    }
}

#python crypt_example_bin.py fetch-history --net=dev --address=0x003d3b27f544d1dc03d6802e6379fdcfc25e0b73272b62496b
{
    "id": 1,
    "result": [
        {
            "from": "0x00525d3f6326549b8974ef669f8fced6153109ba60d52d547d",
            "to": "0x003d3b27f544d1dc03d6802e6379fdcfc25e0b73272b62496b",
            "value": 10000,
            "transaction": "53a14ebb8bd111a80d013d015c14a856facff40a55852ad83e2934346df18d5d",
            "timestamp": 1529306546
        },
        {
            "from": "0x003d3b27f544d1dc03d6802e6379fdcfc25e0b73272b62496b",
            "to": "0x00525d3f6326549b8974ef669f8fced6153109ba60d52d547d",
            "value": 1000,
            "transaction": "babd020d4f33bbf208a62f39e32de3a37e4a81c1cd607cd4d4bcd4e7d4bcf701",
            "timestamp": 1529306666
        },
        {
            "from": "0x003d3b27f544d1dc03d6802e6379fdcfc25e0b73272b62496b",
            "to": "0x00525d3f6326549b8974ef669f8fced6153109ba60d52d547d",
            "value": 1000,
            "transaction": "ee0e11b793ff5a5b0d6954f0da4964ceb53f9887480e9a5e42608830ed401963",
            "timestamp": 1529308272
        }
    ]
}

#python crypt_example_bin.py get-tx --net=dev --hash=ee0e11b793ff5a5b0d6954f0da4964ceb53f9887480e9a5e42608830ed401963
{
    "id": 1,
    "result": {
        "transaction": {
            "from": "0x003d3b27f544d1dc03d6802e6379fdcfc25e0b73272b62496b",
            "to": "0x00525d3f6326549b8974ef669f8fced6153109ba60d52d547d",
            "value": 1000,
            "transaction": "ee0e11b793ff5a5b0d6954f0da4964ceb53f9887480e9a5e42608830ed401963",
            "timestamp": 1529308272
        }
    }
}

#python crypt_example_bin.py create-tx --to=0x00525d3f6326549b8974ef669f8fced6153109ba60d52d547d --value=1000 --nonce=3 --pubkey=mh_public.pub --privkey=mh_private.pem
{
    "jsonrpc": "2.0",
    "method": "mhc_send",
    "params": {
        "to": "0x00525d3f6326549b8974ef669f8fced6153109ba60d52d547d",
        "value": "1000",
        "fee": "",
        "nonce": "3",
        "data": "",
        "pubkey": "3056301006072a8648ce3d020106052b8104000a034200042fe59a96a81e55a592f5deedc331218f865a707e78254e2e5b476aa81e6dba17da86010a36a952c71d839dcdb9e20fbb5d29e7a739ee61444fe008d35c7557e8",
        "sign": "3046022100c3a396b901bc856063a86c031edbd12de4ac3d8a47d4f447417b787eb6935845022100f0d5def340f8265f390bd025afcc36bb50523a5ec2e75a77ca38dbeaf6735d34"
    }
}

#python crypt_example_bin.py send-tx --net=dev --to=0x00525d3f6326549b8974ef669f8fced6153109ba60d52d547d --value=1000 --pubkey=mh_public.pub --privkey=mh_private.pem
{
    "result": "ok",
    "params": "e5147c8c42c94344a067fe2ded493f15cc8e4299b3333f6651ecd3e6381bfefa"
}
```
