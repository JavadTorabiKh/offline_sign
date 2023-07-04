from web3 import Web3
from account import Account
import utils
from eth_account.datastructures import SignedTransaction
from hexbytes.main import HexBytes

address = '0x99baFA590a24755f94F5815df06102C2450AcD3D'
private_key = 'b0f075c393877e332ed691e1341c3897c5b7a28e20861eed200bcdb199c0e745'
address1 = '0x2392bAE123ECd96eE997Be6BFA43d9AE98039BDC'
private_key2 = '0xde4f925a22929a8766e16d921b4123c78561b61e6a5cb1bdbb60cf5705de7caa'


provider = Web3.HTTPProvider('https://sepolia.infura.io/v3/cc1dea670fb5488eb123c82350ed8944')
w3 = Web3(provider)
# account = Account.create()

# ساخت یک تراکنش
value = 100000
nonce = 0
gas_price = 200000
gas_limit = 21000
chain_id = 1254

transaction = {'nonce': 12, 'gasPrice': 15805, 'gas': 21000, 'to': '0x2392bAE123ECd96eE997Be6BFA43d9AE98039BDC', 'value': 1000000, 'data': b''}

# value = w3.to_wei(0.000001, 'ether')  # 0.1 Ether
# to_address = '0x2392bAE123ECd96eE997Be6BFA43d9AE98039BDC'
# from_address = '0x99baFA590a24755f94F5815df06102C2450AcD3D'
# nonce = w3.eth.get_transaction_count(from_address)
# gas_price = w3.eth.gas_price
# gas_limit = 21000
# transaction = {
#     'nonce': nonce,
#     'gasPrice': gas_price,
#     'gas': gas_limit,
#     'to': to_address,
#     'value': value,
#     'data': b''
# }

def offline_send(transaction_dict):
    tx =  w3.eth.account.sign_transaction(transaction_dict , private_key)    
    return tx
    
    

def offline_sign(prv_key, transaction_data):
    (v ,r , s ,tx_hash , en_tx ) = Account.sign_transaction(prv_key ,transaction_data)
    # print('[v ,r , s ,transaction_hash] is : ',signed_tx)
    
    return ( v ,r , s ,tx_hash , en_tx)


def broadcast(b):
    signed_tx = SignedTransaction( 
            rawTransaction=b[4],
            hash=b[3],
            r=b[1],
            s=b[2],
            v=b[0],
            )
    
    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    print(f'Transaction hash: {w3.to_hex(tx_hash)}')

# a = offline_send(transaction)
# print(a)
b = offline_sign(transaction,private_key)
broadcast(b)