from enum import Enum
from typing import Iterator

from ntruencrypt import _ntru

EncryptionParameter = _ntru.EncryptParamSetId


class KeyType(Enum):
    """Represents the parameter type using IEEE 1363.1 standards"""
    PRODUCT = 0
    SIZE = 1
    BALANCED = 2
    SPEED = 3


"""Parameter length using IEEE 1363.1 standards"""
possible_key_sizes = (112, 128, 192, 256)

_KEY_TYPES_TO_RAW = {
    KeyType.PRODUCT: {
        112: EncryptionParameter.NTRU_EES401EP2,
        128: EncryptionParameter.NTRU_EES439EP1,
        192: EncryptionParameter.NTRU_EES593EP1,
        256: EncryptionParameter.NTRU_EES743EP1,
    },
    KeyType.SIZE: {
        112: EncryptionParameter.NTRU_EES401EP1,
        128: EncryptionParameter.NTRU_EES449EP1,
        192: EncryptionParameter.NTRU_EES677EP1,
        256: EncryptionParameter.NTRU_EES1087EP2,
    },
    KeyType.BALANCED: {
        112: EncryptionParameter.NTRU_EES541EP1,
        128: EncryptionParameter.NTRU_EES613EP1,
        192: EncryptionParameter.NTRU_EES887EP1,
        256: EncryptionParameter.NTRU_EES1171EP1,
    },
    KeyType.SPEED: {
        112: EncryptionParameter.NTRU_EES659EP1,
        128: EncryptionParameter.NTRU_EES761EP1,
        192: EncryptionParameter.NTRU_EES1087EP1,
        256: EncryptionParameter.NTRU_EES1499EP1,
    },
}

# Default random number generator (initialized afterwards)
_def_drbg = None  # type: Drbg


class Key:
    """Represent a generic key, it could be both private or public"""

    def __init__(self, handle, params=None):
        self._handle = handle
        self._params = params if params is not None else _ntru.get_parameter_from_key(handle)

    @property
    def params(self):
        return self._params

    @property
    def as_binary(self):
        return self._handle

    @classmethod
    def from_binary(cls, data):
        return cls(data)


class PublicKey(Key):
    """This class represents a NTRU public key

    The only difference from a private key (apart from encrypt/decrypt) is that a PublicKey can
    be translated into DER format using :func:`to_der`.
    A shorthand to check the maximum message length has been added via the property `max_message_len`.
    Note that it is completely equal to checking the `max_message_len` from the `params` property
    """

    def encrypt(self, data, drbg=None):
        if not drbg:
            drbg = _def_drbg

        if not isinstance(data, bytes):
            raise ValueError("Passed data isn't bytes, cannot encrypt %s" % type(data).__name__)

        if len(data) > self.max_message_len:
            raise ValueError("The data to encrypt is too big for this encryption parameter (given: %s bytes, max: %s "
                             "bytes)" % (len(data), self.max_message_len))
        return _ntru.encrypt(drbg.id, self._handle, data)

    def to_der(self):
        return _ntru.public_key_to_subject_public_key_info(self._handle)

    @property
    def max_message_len(self):
        return self._params.max_msg_len

    @classmethod
    def from_der(cls, data):
        binary_data = _ntru.public_key_info_to_subject_public_key(data)
        return cls(binary_data)


class PrivateKey(Key):
    """This class represent a NTRU private key"""

    def decrypt(self, data):
        return _ntru.decrypt(self._handle, data)


class KeyPair:
    """A KeyPair containing both public and private keys

    This class provides a container for two read-only private and public keys.
    To access those keys you can use two methods, the first is to get them from the
    properties named `public_key` and `private_key`.
    The other method is to use the tuple-like decomposition method, in this case the
    order will be public key first, private key last.
    :example:`public_key, private_key = key_pair`
    """

    def __init__(self, public_key: PublicKey, private_key: PrivateKey):
        self._public_key = public_key
        self._private_key = private_key

    @property
    def public_key(self) -> PublicKey:
        return self._public_key

    @property
    def private_key(self) -> PrivateKey:
        return self._private_key

    def __iter__(self) -> Iterator[Key]:
        yield self.public_key
        yield self.private_key


class Drbg:
    """A Random source for the ntru operation

    This class provides a random source that is needed by the key creation and message encryption
    """

    def __init__(self):
        self._handle = _ntru.create_drbg()

    def __del__(self):
        _ntru.destory_drbg(self._handle)

    def create_keys(self, param: EncryptionParameter = None, key_type=KeyType.PRODUCT, key_size=256) -> KeyPair:
        """Creates a public + private KeyPair using this random generator as a random source

        You can use a specific encryption parameter overriding the parameter param,
        if none is specified then the parameter is computed using :func:`get_parameter` with arguments `key_type`
        and `key_size`

        :param param: the encryption parameter to use for the keys (default `None`)
        :param key_type: The type of the parameter to use when generating the keys (default `KeyType.PRODUCT`)
        :param key_size: The size of the parameter to use when generating the keys (default `256`)
        :returns: a KeyPair containing the two generated keys
        """
        if not param:
            param = get_parameter(key_type, key_size)

        pub_key, prv_key = _ntru.create_keys(self._handle, param)
        return KeyPair(PublicKey(pub_key, params=param), PrivateKey(prv_key))

    @property
    def id(self):
        return self._handle


_def_drbg = Drbg()  # type: Drbg


# Can't do `create_keys = __def_drbg.create_keys` because PyCharm would complain
def create_keys(*args, **kwargs) -> KeyPair:
    """Creates a public + private KeyPair using this random generator as a random source

    You can use a specific encryption parameter overriding the parameter param,
    if none is specified then the parameter is computed using :func:`get_parameter` with arguments `key_type`
    and `key_size`

    :param param: the encryption parameter to use for the keys (default `None`)
    :param key_type: The type of the parameter to use when generating the keys (default `KeyType.PRODUCT`)
    :param key_size: The size of the parameter to use when generating the keys (default `256`)
    :returns: a KeyPair containing the two generated keys
    """
    return _def_drbg.create_keys(*args, **kwargs)


def get_parameter(key_type=KeyType.PRODUCT, key_size=256) -> EncryptionParameter:
    """Finds `EncryptionParameter` woth the given type and size

    :param key_type: the parameter's type
    :param key_size: the parameter's size
    :return: a KeyParameter matching these specifics
    """
    if key_size not in possible_key_sizes:
        raise ValueError("Invalid key_size: %d" % key_size)
    return _KEY_TYPES_TO_RAW[key_type][key_size]
