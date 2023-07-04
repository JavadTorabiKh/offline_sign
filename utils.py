from cytoolz import (
    pipe,
)
from eth_utils import (
    to_bytes,
    to_int,
)

from eth_account._utils.legacy_transactions import (
    ChainAwareUnsignedTransaction,
    Transaction,
    UnsignedTransaction,
    encode_transaction,
    serializable_unsigned_transaction_from_dict,
    strip_signature,
)
from eth_account._utils.typed_transactions import (
    TypedTransaction,
)


CHAIN_ID_OFFSET = 35
V_OFFSET = 27

# signature versions
PERSONAL_SIGN_VERSION = b"E"  # Hex value 0x45
INTENDED_VALIDATOR_SIGN_VERSION = b"\x00"  # Hex value 0x00
STRUCTURED_DATA_SIGN_VERSION = b"\x01"  # Hex value 0x01



def sign_transaction_dict(eth_key, transaction_dict):
    # generate RLP-serializable transaction, with defaults filled
    unsigned_transaction = serializable_unsigned_transaction_from_dict(transaction_dict)
    transaction_hash = unsigned_transaction.hash()
    
    # detect chain
    if isinstance(unsigned_transaction, UnsignedTransaction):
        chain_id = None
        (v, r, s) = sign_transaction_hash(eth_key, transaction_hash, chain_id)
    elif isinstance(unsigned_transaction, Transaction):
        chain_id = unsigned_transaction.v
        (v, r, s) = sign_transaction_hash(eth_key, transaction_hash, chain_id)
    elif isinstance(unsigned_transaction, TypedTransaction):
        # Each transaction type dictates its payload, and consequently,
        # all the funky logic around the `v` signature field is both obsolete &&
        # incorrect. We want to obtain the raw `v` and delegate
        # to the transaction type itself.
        (v, r, s) = eth_key.sign_msg_hash(transaction_hash).vrs
    else:
        # Cannot happen, but better for code to be defensive + self-documenting.
        raise TypeError("unknown Transaction object: %s" % type(unsigned_transaction))
    # serialize transaction with rlp
    encoded_transaction = encode_transaction(unsigned_transaction, vrs=(v, r, s))

    return (v, r, s, encoded_transaction)



def sign_transaction_hash(account, transaction_hash, chain_id):
    signature = account.sign_msg_hash(transaction_hash)
    (v_raw, r, s) = signature.vrs
    v = to_eth_v(v_raw, chain_id)
    return (v, r, s)


def to_eth_v(v_raw, chain_id=None):
    if chain_id is None:
        v = v_raw + V_OFFSET
    else:
        v = v_raw + CHAIN_ID_OFFSET + 2 * chain_id
    return v


# _________________________________________________________________________________________

