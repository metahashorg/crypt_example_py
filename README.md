# Crypt example python

This repository contains a script written in python, that describes the algorithm for the Metahash address generation using cryptography module, fetching balance and history for wallet, getting information about transaction by hash and creating transaction. 

## Dependencies

```shell
pip install python3
pip install cryptography
pip install dnspython
pip install requests
```

## Usage

```shell
usage: python crypt_example.py [functions]

Crypt example python

optional arguments:
  -h, --help        show this help message and exit

List of functions:
  
    generate        generate MH address to mh_address.txt
    fetch-balance   get balance for MH address
    fetch-history   get history for MH address
    get-tx          get transaction information by hash
    formation-tx    create transaction using input params
```

### Outputs

```shell
mh_private.pem - private key file
mh_public.pub - public key file
mh_address.txt - metahash address file
```

### Outputs examples

```shell
#python crypt_example.py generate
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

#python crypt_example.py fetch-balance --net=dev --address=0x003d3b27f544d1dc03d6802e6379fdcfc25e0b73272b62496b
{
    "id": 1,
    "result": {
        "address": "0x003d3b27f544d1dc03d6802e6379fdcfc25e0b73272b62496b",
        "received": 0,
        "spent": 0,
        "count_received": 0,
        "count_spent": 0,
        "block_number": 0,
        "currentBlock": 1457
    }
}

#python crypt_example.py fetch-history --net=dev --address=0x0074bcb34e85b717dc3bf356001c7e733209572c9eaf138628
{
    "id": 1,
    "result": [
        {
            "from": "0x00326a4faadbfd478724ea248cf20e671fff885219f2649489",
            "to": "0x0074bcb34e85b717dc3bf356001c7e733209572c9eaf138628",
            "value": 10000000,
            "transaction": "5086a55d75c0d77a09996dd17b776a1a9f4066db7dd0213ba03730517a8b4927",
            "timestamp": 1528895556
        },
        {
            "from": "0x00525d3f6326549b8974ef669f8fced6153109ba60d52d547d",
            "to": "0x0074bcb34e85b717dc3bf356001c7e733209572c9eaf138628",
            "value": 10000,
            "transaction": "c644850f36a63b5c4b65c449ee543b53e594cf79a0eda541ae6eefcd89cbe127",
            "timestamp": 1528895598
        },
        ...
        {
            "from": "0x00525d3f6326549b8974ef669f8fced6153109ba60d52d547d",
            "to": "0x0074bcb34e85b717dc3bf356001c7e733209572c9eaf138628",
            "value": 10000,
            "transaction": "bf45ace5ab6ef6f8a2f0825cbf70c578bdf2aede2b80341141dd71b90d6a96ee",
            "timestamp": 1528971011
        }
    ]
}

#python crypt_example.py get-tx --net=dev --hash=bf45ace5ab6ef6f8a2f0825cbf70c578bdf2aede2b80341141dd71b90d6a96ee
{
    "id": 1,
    "result": {
        "transaction": {
            "from": "0x00525d3f6326549b8974ef669f8fced6153109ba60d52d547d",
            "to": "0x0074bcb34e85b717dc3bf356001c7e733209572c9eaf138628",
            "value": 10000,
            "transaction": "bf45ace5ab6ef6f8a2f0825cbf70c578bdf2aede2b80341141dd71b90d6a96ee",
            "timestamp": 1528971011
        }
    }
}

#python crypt_example.py formation-tx --to=0x0074bcb34e85b717dc3bf356001c7e733209572c9eaf138628 --value=12 --nonce=1 --pubkey=mh_public.pub --privkey=mh_private.pem
{
    "jsonrpc": "2.0",
    "method": "mhc_send",
    "params": {
        "to": "0x0074bcb34e85b717dc3bf356001c7e733209572c9eaf138628",
        "value": "12",
        "fee": "",
        "nonce": "1",
        "data": "",
        "pubkey": "3056301006072a8648ce3d020106052b8104000a034200042fe59a96a81e55a592f5deedc331218f865a707e78254e2e5b476aa81e6dba17da86010a36a952c71d839dcdb9e20fbb5d29e7a739ee61444fe008d35c7557e8",
        "sign": "3046022100967873551b880137e7bf9671a1594cdb9f5abeb47f0c1273ff93f335736db03f022100e81a642fb5c917344519b80c3b93f593b90b3ccb5e79c09589d21f27ababd127"
    }
}
```
