import ctypes
import os
import secrets
import sys
from ctypes import CFUNCTYPE, POINTER, byref, c_char, c_uint8, c_uint16, c_uint32
from ctypes import cast, c_void_p
import ctypes.util
from enum import Enum

if os.name == 'nt':
    LIB_SUFFIX = '.dll'
elif os.name == 'posix':
    LIB_SUFFIX = '.dylib' if sys.platform == 'darwin' else '.so'
else:
    raise Exception("Unknown OS name")


__location__ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))


NTRU_PATHS = ['libntruencrypt', os.path.join(__location__, 'libntruencrypt')]
NULL = 0
NULL_BYTEBUF = cast(NULL, POINTER(c_char))


def search_ntru():
    global ntru
    for path in NTRU_PATHS:
        try:
            ntru = ctypes.CDLL(path + LIB_SUFFIX)
            return
        except OSError:
            pass
    raise EnvironmentError("Cannot find libntruencrypt library, please install libntruencrypt and try again")


search_ntru()
randbytesfunction = CFUNCTYPE(c_uint32, POINTER(c_uint8), c_uint32)


def randbytes(out, num_bytes):
    other = secrets.randbits(num_bytes * 8).to_bytes(num_bytes, 'big')
    for i in range(0, num_bytes):
        out[i] = other[i]
    return 0


crandbytes = randbytesfunction(randbytes)


class EncryptParamSetId(Enum):
    def __new__(cls, *args, **kwargs):
        value = len(cls.__members__)
        obj = object.__new__(cls)
        obj._value_ = value
        return obj

    def __init__(self, max_msg_len, oid):
        self.max_msg_len = max_msg_len
        self.oid = oid

    NTRU_EES401EP1 = 60, 0x000204
    NTRU_EES449EP1 = 67, 0x000303
    NTRU_EES677EP1 = 101, 0x000503
    NTRU_EES1087EP2 = 170, 0x000603
    NTRU_EES541EP1 = 86, 0x000205
    NTRU_EES613EP1 = 97, 0x000304
    NTRU_EES887EP1 = 141, 0x000504
    NTRU_EES1171EP1 = 186, 0x000604
    NTRU_EES659EP1 = 108, 0x000206
    NTRU_EES761EP1 = 125, 0x000305
    NTRU_EES1087EP1 = 178, 0x000505
    NTRU_EES1499EP1 = 247, 0x000605
    NTRU_EES401EP2 = 60, 0x000210
    NTRU_EES439EP1 = 65, 0x000310
    NTRU_EES593EP1 = 86, 0x000510
    NTRU_EES743EP1 = 106, 0x000610
    NTRU_EES443EP1 = 49, 0x000311
    NTRU_EES587EP1 = 76, 0x000511


EncryptParamSetId.__OID_MAPPING__ = {e.oid: e for e in EncryptParamSetId}
EncryptParamSetId.from_oid = lambda oid: EncryptParamSetId.__OID_MAPPING__[oid]


# ---------------- ERRORS ----------------


NTRU_ERROR_CODE_TO_MESSAGE = {
    1: "Fail",
    2: "Bad parameter",
    3: "Bad length",
    4: "Buffer too small",
    5: "Invalid parameter set",
    6: "Bad public key",
    7: "Bad private key",
    8: "Out of memory",
    9: "Bad encoding",
    10: "OID not recognized",
    11: "Unsupported parameter set",
}

HASH_ERROR_BASE = 0x00000100
HMAC_ERROR_BASE = 0x00000200
SHA_ERROR_BASE = 0x00000400
DRBG_ERROR_BASE = 0x00000a00
NTRU_ERROR_BASE = 0x00003000
MGF1_ERROR_BASE = 0x00004100


def parse_error(return_code):
    if return_code != 0:
        raise ValueError(NTRU_ERROR_CODE_TO_MESSAGE[return_code - NTRU_ERROR_BASE])


DRBG_ERROR_CODE_TO_MESSAGE = {
    1: "Out of memory",
    2: "Null pointer",
    3: "Invalid number of bytes",
    4: "No instantiation slot available",
    5: "Entropy function failure",
}


def parse_error_drbg(return_code):
    if return_code != 0:
        raise ValueError(DRBG_ERROR_CODE_TO_MESSAGE[return_code - DRBG_ERROR_BASE])


# ---------------- Define used ntru methods ----------------


drgb_external_instantiate = ntru.ntru_crypto_drbg_external_instantiate
drgb_external_instantiate.argtypes = [randbytesfunction, POINTER(c_uint32)]
drgb_external_instantiate.restype = c_uint32

drgb_uninstantiate = ntru.ntru_crypto_drbg_uninstantiate
drgb_uninstantiate.argtypes = [c_uint32]
drgb_uninstantiate.restype = c_uint32

ntru_encrypt_keygen = ntru.ntru_crypto_ntru_encrypt_keygen
ntru_encrypt_keygen.argtypes = [c_uint32, c_uint8, POINTER(c_uint16), POINTER(c_char), POINTER(c_uint16), POINTER(c_char)]
ntru_encrypt_keygen.restype = c_uint32

ntru_encrypt_public_key_info_to_subject_public_key_info = ntru.ntru_crypto_ntru_encrypt_publicKey2SubjectPublicKeyInfo
ntru_encrypt_public_key_info_to_subject_public_key_info.argtypes = [
    c_uint16, POINTER(c_char), POINTER(c_uint16), POINTER(c_char)
]
ntru_encrypt_public_key_info_to_subject_public_key_info.restype = c_uint32

ntru_encrypt_subject_public_key_info_to_public_key = ntru.ntru_crypto_ntru_encrypt_subjectPublicKeyInfo2PublicKey
ntru_encrypt_subject_public_key_info_to_public_key.argtypes = [
    POINTER(c_char), POINTER(c_uint16), POINTER(c_char), POINTER(POINTER(c_char)), POINTER(c_uint32)
]
ntru_encrypt_subject_public_key_info_to_public_key.restype = c_uint32

ntru_encrypt = ntru.ntru_crypto_ntru_encrypt
ntru_encrypt.argtypes = [c_uint32, c_uint16, POINTER(c_char), c_uint16, POINTER(c_char), POINTER(c_uint16), POINTER(c_char)]
ntru_encrypt.restype = c_uint32

ntru_decrypt = ntru.ntru_crypto_ntru_decrypt
ntru_decrypt.argtypes = [c_uint16, POINTER(c_char), c_uint16, POINTER(c_char), POINTER(c_uint16), POINTER(c_char)]
ntru_decrypt.restype = c_uint32


# ---------------- Wrapper functions ----------------


def create_drbg(rand_bytes_func=crandbytes):
    handle = c_uint32()
    rc = drgb_external_instantiate(rand_bytes_func, byref(handle))
    parse_error_drbg(rc)
    return handle


def destory_drbg(drbg):
    rc = drgb_uninstantiate(drbg)
    parse_error_drbg(rc)


def create_keys(drbg, encryption_param_set: EncryptParamSetId):
    public_key_len, private_key_len = c_uint16(), c_uint16()

    rc = ntru_encrypt_keygen(
        drbg, encryption_param_set.value,
        byref(public_key_len), NULL_BYTEBUF,
        byref(private_key_len), NULL_BYTEBUF
    )
    parse_error(rc)

    public_key = (c_char * public_key_len.value)()
    private_key = (c_char * private_key_len.value)()

    rc = ntru_encrypt_keygen(
        drbg, encryption_param_set.value,
        byref(public_key_len), public_key,
        byref(private_key_len), private_key
    )
    parse_error(rc)
    return public_key.raw, private_key.raw  # public_key.raw, private_key.raw


def public_key_to_subject_public_key_info(public_key):
    encoded_len = c_uint16()
    rc = ntru.ntru_crypto_ntru_encrypt_publicKey2SubjectPublicKeyInfo(
        len(public_key), public_key, byref(encoded_len), NULL_BYTEBUF
    )
    parse_error(rc)
    encoded_public_key = (c_char * encoded_len.value)()
    rc = ntru_encrypt_public_key_info_to_subject_public_key_info(
        len(public_key), public_key, byref(encoded_len), encoded_public_key
    )
    parse_error(rc)
    return encoded_public_key.raw[:encoded_len.value]


def public_key_info_to_subject_public_key(public_key_info):
    # uint_8_pointer = pointer(c_uint8)
    n = POINTER(c_char).from_buffer(cast(public_key_info, c_void_p))
    next_len = c_uint32(len(public_key_info))
    public_key_len = c_uint16()

    rc = ntru_encrypt_subject_public_key_info_to_public_key(
        n, byref(public_key_len), NULL_BYTEBUF, byref(n), byref(next_len)
    )
    parse_error(rc)

    public_key = (c_char * public_key_len.value)()

    rc = ntru_encrypt_subject_public_key_info_to_public_key(
        n, byref(public_key_len), public_key, byref(n), byref(next_len)
    )
    parse_error(rc)
    return public_key.raw[:public_key_len.value]


def encrypt(drbg, public_key, data):
    encrypted_len = c_uint16()

    rt = ntru_encrypt(
        drbg, len(public_key), public_key, len(data), data, byref(encrypted_len), NULL_BYTEBUF
    )
    parse_error(rt)

    encrypted = (c_char * encrypted_len.value)()

    rt = ntru_encrypt(
        drbg, len(public_key), public_key, len(data), data, byref(encrypted_len), encrypted
    )
    parse_error(rt)

    return encrypted.raw


def decrypt(private_key, encrypted):
    original_len = c_uint16()
    rc = ntru_decrypt(
        len(private_key), private_key, len(encrypted), encrypted, byref(original_len), NULL_BYTEBUF
    )
    parse_error(rc)

    original = (c_char * original_len.value)()

    rc = ntru_decrypt(
        len(private_key), private_key, len(encrypted), encrypted, byref(original_len), original
    )
    parse_error(rc)
    return original.raw[:original_len.value]


def get_parameter_from_key(public_key):
    # (Taken from libntruencrypt)
    # Version 0:
    #  byte  0:   tag
    #  byte  1:   no. of octets in OID
    #  bytes 2-4: OID
    #  bytes 5- : packed pubkey
    #             [packed privkey]
    #
    oid = int.from_bytes(public_key[2:5], 'big')
    params = EncryptParamSetId.from_oid(oid)
    return params
