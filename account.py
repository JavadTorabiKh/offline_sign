from utils import sign_transaction_dict

from collections.abc import (
    Mapping,
)
from hexbytes.main import HexBytes
import json
import os
from typing import (
    Optional,
    Tuple,
    TypeVar,
    Union,
    cast,
)
import warnings

from cytoolz import (
    dissoc,
)
from eth_keyfile import (
    create_keyfile_json,
    decode_keyfile_json,
)
from eth_keys import (
    KeyAPI,
    keys,
)
from eth_keys.exceptions import (
    ValidationError,
)
from eth_typing import (
    ChecksumAddress,
    Hash32,
    HexStr,
)
from eth_utils.curried import (
    combomethod,
    hexstr_if_str,
    is_dict,
    keccak,
    text_if_str,
    to_bytes,
    to_int,
)
from hexbytes import (
    HexBytes,
)

from eth_account._utils.legacy_transactions import (
    Transaction,
    vrs_from,
)
from eth_account._utils.signing import (
    hash_of_signed_transaction,
    sign_message_hash,
    to_standard_signature_bytes,
    to_standard_v,
)

from eth_account._utils.typed_transactions import (
    TypedTransaction,
)
from eth_account.datastructures import (
    SignedMessage,
    SignedTransaction,
)
from eth_account.hdaccount import (
    ETHEREUM_DEFAULT_PATH,
    generate_mnemonic,
    key_from_seed,
    seed_from_mnemonic,
)
from eth_account.messages import (
    SignableMessage,
    _hash_eip191_message,
)
from eth_account.signers.local import (
    LocalAccount,
)

VRS = TypeVar("VRS", bytes, HexStr, int)


class Account:

    _keys = keys

    _default_kdf = os.getenv("ETH_ACCOUNT_KDF", "scrypt")

    _use_unaudited_hdwallet_features = False

    @classmethod
    def enable_unaudited_hdwallet_features(cls):

        cls._use_unaudited_hdwallet_features = True

    @combomethod
    def create(self, extra_entropy=""):
        
        extra_key_bytes = text_if_str(to_bytes, extra_entropy)
        key_bytes = keccak(os.urandom(32) + extra_key_bytes)
        return self.from_key(key_bytes)

    @staticmethod
    def decrypt(keyfile_json, password):
        
        if isinstance(keyfile_json, str):
            keyfile = json.loads(keyfile_json)
        elif is_dict(keyfile_json):
            keyfile = keyfile_json
        else:
            raise TypeError(
                "The keyfile should be supplied as a JSON string, or a dictionary."
            )
        password_bytes = text_if_str(to_bytes, password)
        return HexBytes(decode_keyfile_json(keyfile, password_bytes))

    @classmethod
    def encrypt(cls, private_key, password, kdf=None, iterations=None):
        
        if isinstance(private_key, keys.PrivateKey):
            key_bytes = private_key.to_bytes()
        else:
            key_bytes = HexBytes(private_key)

        if kdf is None:
            kdf = cls._default_kdf

        password_bytes = text_if_str(to_bytes, password)
        assert len(key_bytes) == 32

        return create_keyfile_json(
            key_bytes, password_bytes, kdf=kdf, iterations=iterations
        )

    @combomethod
    def from_key(self, private_key):
        
        key = self._parsePrivateKey(private_key)
        return LocalAccount(key, self)

    @combomethod
    def from_mnemonic(
        self,
        mnemonic: str,
        passphrase: str = "",
        account_path: str = ETHEREUM_DEFAULT_PATH,
    ) -> LocalAccount:
        
        if not self._use_unaudited_hdwallet_features:
            raise AttributeError(
                "The use of the Mnemonic features of Account is disabled by "
                "default until its API stabilizes. To use these features, please "
                "enable them by running `Account.enable_unaudited_hdwallet_features()` "
                "and try again."
            )
        seed = seed_from_mnemonic(mnemonic, passphrase)
        private_key = key_from_seed(seed, account_path)
        key = self._parsePrivateKey(private_key)
        return LocalAccount(key, self)

    @combomethod
    def create_with_mnemonic(
        self,
        passphrase: str = "",
        num_words: int = 12,
        language: str = "english",
        account_path: str = ETHEREUM_DEFAULT_PATH,
    ) -> Tuple[LocalAccount, str]:
        
        if not self._use_unaudited_hdwallet_features:
            raise AttributeError(
                "The use of the Mnemonic features of Account is disabled by "
                "default until its API stabilizes. To use these features, please "
                "enable them by running `Account.enable_unaudited_hdwallet_features()` "
                "and try again."
            )
        mnemonic = generate_mnemonic(num_words, language)
        return self.from_mnemonic(mnemonic, passphrase, account_path), mnemonic

    @combomethod
    def recover_message(
        self,
        signable_message: SignableMessage,
        vrs: Optional[Tuple[VRS, VRS, VRS]] = None,
        signature: bytes = None,
    ) -> ChecksumAddress:
        
        message_hash = _hash_eip191_message(signable_message)
        return cast(ChecksumAddress, self._recover_hash(message_hash, vrs, signature))

    @combomethod
    def _recover_hash(
        self,
        message_hash: Hash32,
        vrs: Optional[Tuple[VRS, VRS, VRS]] = None,
        signature: bytes = None,
    ) -> ChecksumAddress:
        hash_bytes = HexBytes(message_hash)
        if len(hash_bytes) != 32:
            raise ValueError("The message hash must be exactly 32-bytes")
        if vrs is not None:
            v, r, s = map(hexstr_if_str(to_int), vrs)
            v_standard = to_standard_v(v)
            signature_obj = self._keys.Signature(vrs=(v_standard, r, s))
        elif signature is not None:
            signature_bytes = HexBytes(signature)
            signature_bytes_standard = to_standard_signature_bytes(signature_bytes)
            signature_obj = self._keys.Signature(
                signature_bytes=signature_bytes_standard
            )
        else:
            raise TypeError("You must supply the vrs tuple or the signature bytes")
        pubkey = signature_obj.recover_public_key_from_msg_hash(hash_bytes)
        return cast(ChecksumAddress, pubkey.to_checksum_address())

    @combomethod
    def recover_transaction(self, serialized_transaction):
        
        txn_bytes = HexBytes(serialized_transaction)
        if len(txn_bytes) > 0 and txn_bytes[0] <= 0x7F:
            # We are dealing with a typed transaction.
            typed_transaction = TypedTransaction.from_bytes(txn_bytes)
            msg_hash = typed_transaction.hash()
            vrs = typed_transaction.vrs()
            return self._recover_hash(msg_hash, vrs=vrs)

        txn = Transaction.from_bytes(txn_bytes)
        msg_hash = hash_of_signed_transaction(txn)
        return self._recover_hash(msg_hash, vrs=vrs_from(txn))

    def set_key_backend(self, backend):
        
        self._keys = KeyAPI(backend)

    @combomethod
    def sign_message(
        self,
        signable_message: SignableMessage,
        private_key: Union[bytes, HexStr, int, keys.PrivateKey],
    ) -> SignedMessage:
        
        message_hash = _hash_eip191_message(signable_message)
        return cast(SignedMessage, self._sign_hash(message_hash, private_key))

    @combomethod
    def signHash(self, message_hash, private_key):
        
        warnings.warn(
            "signHash is deprecated in favor of sign_message",
            category=DeprecationWarning,
            stacklevel=2,
        )
        return self._sign_hash(message_hash, private_key)

    @combomethod
    def _sign_hash(
        self,
        message_hash: Hash32,
        private_key: Union[bytes, HexStr, int, keys.PrivateKey],
    ) -> SignedMessage:
        msg_hash_bytes = HexBytes(message_hash)
        if len(msg_hash_bytes) != 32:
            raise ValueError("The message hash must be exactly 32-bytes")

        key = self._parsePrivateKey(private_key)

        (v, r, s, eth_signature_bytes) = sign_message_hash(key, msg_hash_bytes)
        return SignedMessage(
            messageHash=msg_hash_bytes,
            r=r,
            s=s,
            v=v,
            signature=HexBytes(eth_signature_bytes),
        )

    @combomethod
    def sign_transaction(self, transaction_dict, private_key):
        
        # if not isinstance(transaction_dict, Mapping):
        #     raise TypeError(
        #         "transaction_dict must be dict-like, got %r" % transaction_dict
        #     )

        account = self.from_key(private_key)

        # allow from field, *only* if it matches the private key
        # if "from" in transaction_dict:
        #     if transaction_dict["from"] == account.address:
        #         sanitized_transaction = dissoc(transaction_dict, "from")
        #     else:
        #         raise TypeError(
        #             "from field must match key's %s, but it was %s"
        #             % (
        #                 account.address,
        #                 transaction_dict["from"],
        #             )
        #         )
        # else:
        #     sanitized_transaction = transaction_dict
        
        # print(sanitized_transaction)
        # return sanitized_transaction
        # sign transaction
        (
            v,
            r,
            s,
            encoded_transaction,
        ) = sign_transaction_dict(account._key_obj, transaction_dict)
        transaction_hash =  (encoded_transaction)
        tx_hash = HexBytes(transaction_hash)
        en_tx = HexBytes(encoded_transaction)
        return (v ,r , s ,tx_hash , en_tx)


    @combomethod
    def _parsePrivateKey(self, key):

        if isinstance(key, self._keys.PrivateKey):
            return key

        try:
            return self._keys.PrivateKey(HexBytes(key))
        except ValidationError as original_exception:
            raise ValueError(
                "The private key must be exactly 32 bytes long, instead of "
                "%d bytes." % len(key)
            ) from original_exception
