# FheLib

`FheLib` is a library implemented inside fhevm-go. It offers FHE-related functionalities such as homomorphic operations, decryption/reencryption requests and so on. FheLib is exposed as a single `precompiled` contract (or a `precompile` for short) that is integrated into the underlying blockchain.

FheLib functions can be called by calling the FheLib precompile with a respective EVM function selector.

This page describes the required inputs, behaviours and outputs of some of these functions.

## GetCiphertext Function (selector: e4b808cb)

The `GetCiphertext` function returns a serialized TFHE ciphertext from protected storage given:
 * contract address where the ciphertext is stored at
 * the ebool/e(u)int value (also called a handle) for which the ciphertext is requested

GetCiphertext only works via the `eth_call` RPC.

To call GetCiphertext via `eth_call`, the following Python can serve as an example:

```python
import http.client
import json

# This is the address of the FheLib precompile. This value is hardcoded per blockchain.
fhe_lib_precompile_address = "0x000000000000000000000000000000000000005d"

# The contract address where the ciphertext is stored at.
contract_address = "ACD7Be4EBF68Bf2A5b6eB0CaFb15460C169BC459"
# 12 bytes of 0s for padding the contract address.
address_zero_padding = "000000000000000000000000"

# The ebool/e(u)int value for which the ciphertext is requested.
handle = "f038cdc8bf630e239f143abeb039b91ec82ec17a8460582e7a409fa551030c06"

# The function selector of GetCiphertext.
get_ciphertext_selector = "e4b808cb"

# Call the FheLib precompile with `data` being the concatenation of:
#  - getCiphertext function selector;
#  - 12 bytes of 0s to padd the contract address;
#  - contract address;
#  - the handle to the ciphertext.
payload = {
    "jsonrpc": "2.0",
    "method": "eth_call",
    "params": [
        {
            "to": fhe_lib_precompile_address,
            "data": "0x" + get_ciphertext_selector + address_zero_padding +
                    contract_address + handle
        },
        "latest"
    ],
    "id": 1,
}

con = http.client.HTTPConnection("localhost", 8545)
con.request("POST", "/", body=json.dumps(payload),
            headers={"Content-Type": "application/json"})
resp = json.loads(con.getresponse().read())

# Remove leading "0x" and decode hex to get a byte buffer with the ciphertext.
ciphertext = bytes.fromhex(resp["result"][2:])
```