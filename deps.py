import json
from web3 import Web3, EthereumTesterProvider, HTTPProvider, WebsocketProvider, IPCProvider
from eth_account.messages import encode_defunct, _hash_eip191_message
from web3.middleware import geth_poa_middleware
from web3.middleware import construct_sign_and_send_raw_middleware


w3 = Web3(HTTPProvider('https://api.avax-test.network/ext/bc/C/rpc'))

if w3.is_connected():
    print("Connected to Ethereum node")
else:
    print("Failed to connect to Ethereum node")


address = '0x99baFA590a24755f94F5815df06102C2450AcD3D'
private_key = 'b0f075c393877e332ed691e1341c3897c5b7a28e20861eed200bcdb199c0e745'

address1 = '0x2392bAE123ECd96eE997Be6BFA43d9AE98039BDC'
private_key2 = '0xde4f925a22929a8766e16d921b4123c78561b61e6a5cb1bdbb60cf5705de7caa'


# type 1
# transaction = {
#     'chainId': 11155111,
#     'from': address,
#     'to': address1,
#     'value': 1000000000,
#     'nonce': w3.eth.get_transaction_count(address),
#     'gas': 200000,
#     # 'maxFeePerGas': 2000000000,
#     'gasPrice': 67101372135,
# }


# # 2. Sign tx with a private key
# signed = w3.eth.account.sign_transaction(transaction, private_key)

# # 3. Send the signed transaction
# tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
# print(tx_hash)
# tx = w3.eth.get_transaction(tx_hash)
# assert tx["from"] == address


# amount = w3.to_wei(0.0001, 'ether')

# nonce = w3.eth.get_transaction_count(address)
# gas_price = w3.eth.gas_price
# gas_limit = 21000
# value = amount

# transaction = {
#     'chainId': 11155111,
#     'from': address,
#     'to': address1,
#     'value': value,
#     'gas': gas_limit,
#     'gasPrice': gas_price,
#     'nonce': nonce,
# }

# signed_tx = w3.eth.account.sign_transaction(transaction, private_key=private_key)

# tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)

# print(f'Transaction sent: {tx_hash.hex()}')


private_key_from = private_key

address_from = address

private_key_to = private_key2
nonce = w3.eth.get_transaction_count(address_from)
max_priority_fee_per_gas = w3.to_wei('5', 'gwei')
address_to = address1

amount = w3.to_wei(0.0001, 'ether')

tx = {'to': '0x2392bAE123ECd96eE997Be6BFA43d9AE98039BDC', 'value': 100000000000000, 'gas': 21000,
      'maxPriorityFeePerGas': 5000000000, 'maxFeePerGas': 25000000000, 'chainId': 4002, 'nonce': 6, 'type': 2}


signed_tx = w3.eth.account.sign_transaction(tx, private_key_from)

tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
print(f'Transaction hash: {w3.to_hex(tx_hash)}')


non_checksum_address = '0x5425890298aed601595a70AB815c96711a31Bc65'
token_address = w3.to_checksum_address(non_checksum_address)
# ---------------------------------------------------------------------------------

sender_address = address
sender_private_key = private_key

with open('abi.json') as f:
    token_abi = json.load(f)['abi']

recipient_address = address1

token_contract = w3.eth.contract(address=token_address, abi=token_abi)
nonce = w3.eth.get_transaction_count(sender_address)

transfer = token_contract.functions.transfer(recipient_address, 1000)
tx = transfer.build_transaction({
    'from': sender_address,
    'nonce': nonce,
    'gas': 100000,
    'gasPrice': w3.to_wei('50', 'gwei')
})

signed_tx = w3.eth.account.sign_transaction(tx, sender_private_key)
tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
print(f'Transaction hash: {w3.to_hex(tx_hash)}')


balance = token_contract.functions.balanceOf(sender_address).call()
print(f"Your balance is: {balance}")
