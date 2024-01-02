import ecdsa
pub = 'MCowBQYDK2VwAyEAbLSPHLbBraoomQExUdAHDU+F5wScnSsjgThOn7VtQb8='
prv = 'MC4CAQAwBQYDK2VwBCIEIJJTnG4LwVOCpZW2bPlVEZlFcQn/xvHcJdTLzAtQ/zJg'


tx_bytes = b''.join([
    tx['nonce'].to_bytes(32, byteorder='big'),
    tx['gasPrice'].to_bytes(32, byteorder='big'),
    tx['gas'].to_bytes(32, byteorder='big'),
    bytes.fromhex(tx['to'][2:]),
    tx['value'].to_bytes(32, byteorder='big'),
    b'',
])
tx_hash = ecdsa.util.sha3_256(tx_bytes)

sk = ecdsa.SigningKey.from_secret_exponent(
    private_key_bin, curve=ecdsa.SECP256k1)
signature = sk.sign(tx_hash)

vk = sk.get_verifying_key()
v = 27 + vk.pubkey.point.y() % 2
r, s = ecdsa.util.sigdecode_string(signature, sk.curve.order)
