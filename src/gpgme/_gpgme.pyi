import enum
from typing import (
    BinaryIO, Callable, Iterator, Literal, Optional, Sequence, Union)

class Context:
    def __init__(self) -> None: ...
    def set_engine_info(self, protocol: Protocol, file_name: Optional[str],
                        home_dir: Optional[str]) -> None: ...
    def set_locale(self, category: int, value: Optional[str]) -> None: ...
    def get_key(self, fingerprint: str, secret: bool = False) -> Key: ...
    def encrypt(self, recipients: Optional[Sequence[Key]], flags: EncryptFlags | Literal[0],
                plain: BinaryIO, cipher: BinaryIO) -> None: ...
    def encrypt_sign(self, recipients: Optional[Sequence[Key]], flags: EncryptFlags | Literal[0],
                     plain: BinaryIO, cipher: BinaryIO) -> Sequence[NewSignature]: ...
    def decrypt(self, cipher: BinaryIO, plain: BinaryIO) -> None: ...
    def decrypt_verify(self, cipher: BinaryIO, plain: BinaryIO) -> Sequence[Signature]: ...
    def sign(self, plain: BinaryIO, sig: BinaryIO,
             sig_mode: SigMode = SigMode.NORMAL) -> Sequence[NewSignature]: ...
    def verify(self, sig: BinaryIO, signed_test: Optional[BinaryIO], plaintext: Optional[BinaryIO]) -> Sequence[Signature]: ...
    def import_(self, keydata: BinaryIO) -> ImportResult: ...
    def export(self, pattern: Union[None, str, Sequence[str]],
               keydata: BinaryIO, export_mode: ExportMode | Literal[0] = 0) -> None: ...
    def genkey(self, params: Optional[str], pubkey: Optional[BinaryIO] = None,
               seckey: Optional[BinaryIO] = None) -> GenkeyResult: ...
    def delete(self, key: Key, allow_secret: bool = False) -> None: ...
    def edit(self, key: Key, callback: Callable[[Status, Optional[str], int], None],
             out: BinaryIO) -> None: ...
    def card_edit(self, key: Key, callback: Callable[[Status, Optional[str], int], None],
                  out: BinaryIO) -> None: ...
    def keylist(self, pattern: Union[None, str, Sequence[str]] = None,
                secret_only: bool = False) -> Iterator[Key]: ...
    protocol: Protocol
    armor: bool
    textmode: bool
    include_certs: int
    keylist_mode: KeylistMode | Literal[0]
    pinentry_mode: PinentryMode
    passphrase_cb: Optional[Callable[[Optional[str], Optional[str], bool, int], None]]
    progress_cb: Optional[Callable[[Optional[str], int, int, int], None]]
    signers: Sequence[Key]
    sig_notations: Sequence[SigNotation]

class Key:
    revoked: bool
    expired: bool
    disabled: bool
    invalid: bool
    can_encrypt: bool
    can_sign: bool
    can_certify: bool
    secret: bool
    can_authenticate: bool
    protocol: Protocol
    issuer_serial: str
    issuer_name: str
    chain_id: str
    owner_trust: Validity
    subkeys: Sequence[Subkey]
    uids: Sequence[UserId]
    keylist_mode: KeylistMode | Literal[0]

class Subkey:
    revoked: bool
    expired: bool
    disabled: bool
    invalid: bool
    can_encrypt: bool
    can_sign: bool
    can_certify: bool
    secret: bool
    can_authenticate: bool
    pubkey_algo: PubkeyAlgo
    length: int
    keyid: str
    fpr: str
    timestamp: int
    expires: int

class UserId:
    revoked: bool
    invalid: bool
    validity: bool
    uid: Optional[str]
    name: Optional[str]
    email: Optional[str]
    comment: Optional[str]
    signatures: Sequence[KeySig]

class KeySig:
    revoked: bool
    expired: bool
    invalid: bool
    exportable: bool
    pubkey_algo: PubkeyAlgo
    keyid: str
    timestamp: int
    expires: int
    status: Optional[GpgmeError]
    uid: Optional[str]
    name: Optional[str]
    email: Optional[str]
    comment: Optional[str]
    sig_class: int

class NewSignature:
    type: SigMode
    pubkey_algo: PubkeyAlgo
    hash_algo: HashAlgo
    timestamp: int
    fpr: Optional[str]
    sig_class: int

class Signature:
    summary: Sigsum | Literal[0]
    fpr: Optional[str]
    status: Optional[GpgmeError]
    notations: Sequence[SigNotation]
    timestamp: int
    exp_timestamp: int
    wrong_key_usage: bool
    validity: Validity
    validity_reason: Optional[GpgmeError]
    pubkey_algo: PubkeyAlgo
    hash_algo: HashAlgo

class SigNotation:
    def __init__(self, name: Optional[str], value: str | bytes, flags: SigNotationFlags = SigNotationFlags.HUMAN_READABLE) -> None: ...
    name: Optional[str]
    value: str | bytes
    flags: SigNotationFlags | Literal[0]
    human_readable: bool
    critical: bool

class ImportResult:
    considered: int
    no_user_id: int
    imported: int
    imported_rsa: int
    unchanged: int
    new_user_ids: int
    new_sub_keys: int
    new_signatures: int
    new_revocations: int
    secret_read: int
    secret_imported: int
    secret_unchanged: int
    skipped_new_keys: int
    not_imported: int
    imports: Sequence[tuple[Optional[str], Optional[GpgmeError], Import]]

class GenkeyResult:
    primary: bool
    sub: bool
    fpr: str

class KeyIter:
    def __iter__(self) -> KeyIter: ...
    def __next__(self) -> Key: ...

class GpgmeError(RuntimeError):
    def __init__(self, source: ErrSource, code: ErrCode, message: Optional[str] = None) -> None: ...
    source: ErrSource
    code: ErrCode
    strerror: str
    result: ImportResult | GenkeyResult

class DataEncoding(enum.IntEnum):
    NONE: int
    BINARY: int
    BASE64: int
    ARMOR: int

class PubkeyAlgo(enum.IntEnum):
    RSA: int
    RSA_E: int
    RSA_S: int
    ELG_E: int
    DSA: int
    ELG: int
    ECDSA: int
    ECDH: int
    EDDSA: int

class HashAlgo(enum.IntEnum):
    NONE: int
    MD5: int
    SHA1: int
    RMD160: int
    MD2: int
    TIGER: int
    HAVAL: int
    SHA256: int
    SHA384: int
    SHA512: int
    MD4: int
    CRC32: int
    CRC32_RFC1510: int
    CRC24_RFC2440: int

class SigMode(enum.IntEnum):
    NORMAL: int
    DETACH: int
    CLEAR: int

class Validity(enum.IntEnum):
    UNKNOWN: int
    UNDEFINED: int
    NEVER: int
    MARGINAL: int
    FULL: int
    ULTIMATE: int

class Protocol(enum.IntEnum):
    OpenPGP: int
    CMS: int
    GPGCONF: int
    ASSUAN: int
    G13: int
    UISERVER: int
    SPAWN: int
    DEFAULT: int
    UNKNOWN: int

class KeylistMode(enum.IntFlag):
    LOCAL: int
    EXTERN: int
    SIGS: int
    SIG_NOTATIONS: int
    WITH_SECRET: int
    WITH_TOFU: int
    WITH_KEYGRIP: int
    EPHEMERAL: int
    VALIDATE: int
    LOCATE: int
    FORCE_EXTERN: int
    LOCATE_EXTERNAL: int

class PinentryMode(enum.IntEnum):
    DEFAULT: int
    ASK: int
    CANCEL: int
    ERROR: int
    LOOPBACK: int

class ExportMode(enum.IntFlag):
    EXTERN: int
    MINIMAL: int
    SECRET: int
    RAW: int
    PKCS12: int
    SSH: int
    SECRET_SUBKEY: int

class SigNotationFlags(enum.IntFlag):
    HUMAN_READABLE: int
    CRITICAL: int

class Status(enum.IntEnum):
    EOF: int
    ENTER: int
    LEAVE: int
    ABORT: int
    GOODSIG: int
    BADSIG: int
    ERRSIG: int
    BADARMOR: int
    RSA_OR_IDEA: int
    KEYEXPIRED: int
    KEYREVOKED: int
    TRUST_UNDEFINED: int
    TRUST_NEVER: int
    TRUST_MARGINAL: int
    TRUST_FULLY: int
    TRUST_ULTIMATE: int
    SHM_INFO: int
    SHM_GET: int
    SHM_GET_BOOL: int
    SHM_GET_HIDDEN: int
    NEED_PASSPHRASE: int
    VALIDSIG: int
    SIG_ID: int
    ENC_TO: int
    NODATA: int
    BAD_PASSPHRASE: int
    NO_PUBKEY: int
    NO_SECKEY: int
    NEED_PASSPHRASE_SYM: int
    DECRYPTION_FAILED: int
    DECRYPTION_OKAY: int
    MISSING_PASSPHRASE: int
    GOOD_PASSPHRASE: int
    GOODMDC: int
    BADMDC: int
    ERRMDC: int
    IMPORTED: int
    IMPORT_OK: int
    IMPORT_PROBLEM: int
    IMPORT_RES: int
    FILE_START: int
    FILE_DONE: int
    FILE_ERROR: int
    BEGIN_DECRYPTION: int
    END_DECRYPTION: int
    BEGIN_ENCRYPTION: int
    END_ENCRYPTION: int
    DELETE_PROBLEM: int
    GET_BOOL: int
    GET_LINE: int
    GET_HIDDEN: int
    GOT_IT: int
    PROGRESS: int
    SIG_CREATED: int
    SESSION_KEY: int
    NOTATION_NAME: int
    NOTATION_DATA: int
    POLICY_URL: int
    BEGIN_STREAM: int
    END_STREAM: int
    KEY_CREATED: int
    USERID_HINT: int
    UNEXPECTED: int
    INV_RECP: int
    NO_RECP: int
    ALREADY_SIGNED: int
    SIGEXPIRED: int
    EXPSIG: int
    EXPKEYSIG: int
    TRUNCATED: int
    ERROR: int
    NEWSIG: int
    REVKEYSIG: int
    SIG_SUBPACKET: int
    NEED_PASSPHRASE_PIN: int
    SC_OP_FAILURE: int
    SC_OP_SUCCESS: int
    CARDCTRL: int
    BACKUP_KEY_CREATED: int
    PKA_TRUST_BAD: int
    PKA_TRUST_GOOD: int
    PLAINTEXT: int
    INV_SGNR: int
    NO_SGNR: int
    SUCCESS: int
    DECRYPTION_INFO: int
    PLAINTEXT_LENGTH: int
    MOUNTPOINT: int
    PINENTRY_LAUNCHED: int
    ATTRIBUTE: int
    BEGIN_SIGNING: int
    KEY_NOT_CREATED: int
    INQUIRE_MAXLEN: int
    FAILURE: int
    KEY_CONSIDERED: int
    TOFU_USER: int
    TOFU_STATS: int
    TOFU_STATS_LONG: int
    NOTATION_FLAGS: int
    DECRYPTION_COMPLIANCE_MODE: int
    VERIFICATION_COMPLIANCE_MODE: int
    CANCELED_BY_USER: int

class EncryptFlags(enum.IntFlag):
    ALWAYS_TRUST: int
    NO_ENCRYPT_TO: int
    PREPARE: int
    EXPECT_SIGN: int
    NO_COMPRESS: int
    SYMMETRIC: int
    THROW_KEYIDS: int
    WRAP: int
    WANT_ADDRESS: int

class Sigsum(enum.IntFlag):
    VALID: int
    GREEN: int
    RED: int
    KEY_REVOKED: int
    KEY_EXPIRED: int
    SIG_EXPIRED: int
    KEY_MISSING: int
    CRL_MISSING: int
    CRL_TOO_OLD: int
    BAD_POLICY: int
    SYS_ERROR: int
    TOFU_CONFLICT: int

class Import(enum.IntFlag):
    NEW: int
    UID: int
    SIG: int
    SUBKEY: int
    SECRET: int

class ErrSource(enum.IntEnum):
    UNKNOWN: int
    GCRYPT: int
    GPG: int
    GPGSM: int
    GPGAGENT: int
    PINENTRY: int
    SCD: int
    GPGME: int
    KEYBOX: int
    KSBA: int
    DIRMNGR: int
    GSTI: int
    GPA: int
    KLEO: int
    G13: int
    ASSUAN: int
    TLS: int
    TKD: int
    ANY: int
    USER_1: int
    USER_2: int
    USER_3: int
    USER_4: int

class ErrCode(enum.IntEnum):
    NO_ERROR: int
    GENERAL: int
    UNKNOWN_PACKET: int
    UNKNOWN_VERSION: int
    PUBKEY_ALGO: int
    DIGEST_ALGO: int
    BAD_PUBKEY: int
    BAD_SECKEY: int
    BAD_SIGNATURE: int
    NO_PUBKEY: int
    CHECKSUM: int
    BAD_PASSPHRASE: int
    CIPHER_ALGO: int
    KEYRING_OPEN: int
    INV_PACKET: int
    INV_ARMOR: int
    NO_USER_ID: int
    NO_SECKEY: int
    WRONG_SECKEY: int
    BAD_KEY: int
    COMPR_ALGO: int
    NO_PRIME: int
    NO_ENCODING_METHOD: int
    NO_ENCRYPTION_SCHEME: int
    NO_SIGNATURE_SCHEME: int
    INV_ATTR: int
    NO_VALUE: int
    NOT_FOUND: int
    VALUE_NOT_FOUND: int
    SYNTAX: int
    BAD_MPI: int
    INV_PASSPHRASE: int
    SIG_CLASS: int
    RESOURCE_LIMIT: int
    INV_KEYRING: int
    TRUSTDB: int
    BAD_CERT: int
    INV_USER_ID: int
    UNEXPECTED: int
    TIME_CONFLICT: int
    KEYSERVER: int
    WRONG_PUBKEY_ALGO: int
    TRIBUTE_TO_D_A: int
    WEAK_KEY: int
    INV_KEYLEN: int
    INV_ARG: int
    BAD_URI: int
    INV_URI: int
    NETWORK: int
    UNKNOWN_HOST: int
    SELFTEST_FAILED: int
    NOT_ENCRYPTED: int
    NOT_PROCESSED: int
    UNUSABLE_PUBKEY: int
    UNUSABLE_SECKEY: int
    INV_VALUE: int
    BAD_CERT_CHAIN: int
    MISSING_CERT: int
    NO_DATA: int
    BUG: int
    NOT_SUPPORTED: int
    INV_OP: int
    TIMEOUT: int
    INTERNAL: int
    EOF_GCRYPT: int
    INV_OBJ: int
    TOO_SHORT: int
    TOO_LARGE: int
    NO_OBJ: int
    NOT_IMPLEMENTED: int
    CONFLICT: int
    INV_CIPHER_MODE: int
    INV_FLAG: int
    INV_HANDLE: int
    TRUNCATED: int
    INCOMPLETE_LINE: int
    INV_RESPONSE: int
    NO_AGENT: int
    AGENT: int
    INV_DATA: int
    ASSUAN_SERVER_FAULT: int
    ASSUAN: int
    INV_SESSION_KEY: int
    INV_SEXP: int
    UNSUPPORTED_ALGORITHM: int
    NO_PIN_ENTRY: int
    PIN_ENTRY: int
    BAD_PIN: int
    INV_NAME: int
    BAD_DATA: int
    INV_PARAMETER: int
    WRONG_CARD: int
    NO_DIRMNGR: int
    DIRMNGR: int
    CERT_REVOKED: int
    NO_CRL_KNOWN: int
    CRL_TOO_OLD: int
    LINE_TOO_LONG: int
    NOT_TRUSTED: int
    CANCELED: int
    BAD_CA_CERT: int
    CERT_EXPIRED: int
    CERT_TOO_YOUNG: int
    UNSUPPORTED_CERT: int
    UNKNOWN_SEXP: int
    UNSUPPORTED_PROTECTION: int
    CORRUPTED_PROTECTION: int
    AMBIGUOUS_NAME: int
    CARD: int
    CARD_RESET: int
    CARD_REMOVED: int
    INV_CARD: int
    CARD_NOT_PRESENT: int
    NO_PKCS15_APP: int
    NOT_CONFIRMED: int
    CONFIGURATION: int
    NO_POLICY_MATCH: int
    INV_INDEX: int
    INV_ID: int
    NO_SCDAEMON: int
    SCDAEMON: int
    UNSUPPORTED_PROTOCOL: int
    BAD_PIN_METHOD: int
    CARD_NOT_INITIALIZED: int
    UNSUPPORTED_OPERATION: int
    WRONG_KEY_USAGE: int
    NOTHING_FOUND: int
    WRONG_BLOB_TYPE: int
    MISSING_VALUE: int
    HARDWARE: int
    PIN_BLOCKED: int
    USE_CONDITIONS: int
    PIN_NOT_SYNCED: int
    INV_CRL: int
    BAD_BER: int
    INV_BER: int
    ELEMENT_NOT_FOUND: int
    IDENTIFIER_NOT_FOUND: int
    INV_TAG: int
    INV_LENGTH: int
    INV_KEYINFO: int
    UNEXPECTED_TAG: int
    NOT_DER_ENCODED: int
    NO_CMS_OBJ: int
    INV_CMS_OBJ: int
    UNKNOWN_CMS_OBJ: int
    UNSUPPORTED_CMS_OBJ: int
    UNSUPPORTED_ENCODING: int
    UNSUPPORTED_CMS_VERSION: int
    UNKNOWN_ALGORITHM: int
    INV_ENGINE: int
    PUBKEY_NOT_TRUSTED: int
    DECRYPT_FAILED: int
    KEY_EXPIRED: int
    SIG_EXPIRED: int
    ENCODING_PROBLEM: int
    INV_STATE: int
    DUP_VALUE: int
    MISSING_ACTION: int
    MODULE_NOT_FOUND: int
    INV_OID_STRING: int
    INV_TIME: int
    INV_CRL_OBJ: int
    UNSUPPORTED_CRL_VERSION: int
    INV_CERT_OBJ: int
    UNKNOWN_NAME: int
    LOCALE_PROBLEM: int
    NOT_LOCKED: int
    PROTOCOL_VIOLATION: int
    INV_MAC: int
    INV_REQUEST: int
    UNKNOWN_EXTN: int
    UNKNOWN_CRIT_EXTN: int
    LOCKED: int
    UNKNOWN_OPTION: int
    UNKNOWN_COMMAND: int
    NOT_OPERATIONAL: int
    NO_PASSPHRASE: int
    NO_PIN: int
    NOT_ENABLED: int
    NO_ENGINE: int
    MISSING_KEY: int
    TOO_MANY: int
    LIMIT_REACHED: int
    NOT_INITIALIZED: int
    MISSING_ISSUER_CERT: int
    NO_KEYSERVER: int
    INV_CURVE: int
    UNKNOWN_CURVE: int
    DUP_KEY: int
    AMBIGUOUS: int
    NO_CRYPT_CTX: int
    WRONG_CRYPT_CTX: int
    BAD_CRYPT_CTX: int
    CRYPT_CTX_CONFLICT: int
    BROKEN_PUBKEY: int
    BROKEN_SECKEY: int
    MAC_ALGO: int
    FULLY_CANCELED: int
    UNFINISHED: int
    BUFFER_TOO_SHORT: int
    SEXP_INV_LEN_SPEC: int
    SEXP_STRING_TOO_LONG: int
    SEXP_UNMATCHED_PAREN: int
    SEXP_NOT_CANONICAL: int
    SEXP_BAD_CHARACTER: int
    SEXP_BAD_QUOTATION: int
    SEXP_ZERO_PREFIX: int
    SEXP_NESTED_DH: int
    SEXP_UNMATCHED_DH: int
    SEXP_UNEXPECTED_PUNC: int
    SEXP_BAD_HEX_CHAR: int
    SEXP_ODD_HEX_NUMBERS: int
    SEXP_BAD_OCT_CHAR: int
    SUBKEYS_EXP_OR_REV: int
    DB_CORRUPTED: int
    SERVER_FAILED: int
    NO_NAME: int
    NO_KEY: int
    LEGACY_KEY: int
    REQUEST_TOO_SHORT: int
    REQUEST_TOO_LONG: int
    OBJ_TERM_STATE: int
    NO_CERT_CHAIN: int
    CERT_TOO_LARGE: int
    INV_RECORD: int
    BAD_MAC: int
    UNEXPECTED_MSG: int
    COMPR_FAILED: int
    WOULD_WRAP: int
    FATAL_ALERT: int
    NO_CIPHER: int
    MISSING_CLIENT_CERT: int
    CLOSE_NOTIFY: int
    TICKET_EXPIRED: int
    BAD_TICKET: int
    UNKNOWN_IDENTITY: int
    BAD_HS_CERT: int
    BAD_HS_CERT_REQ: int
    BAD_HS_CERT_VER: int
    BAD_HS_CHANGE_CIPHER: int
    BAD_HS_CLIENT_HELLO: int
    BAD_HS_SERVER_HELLO: int
    BAD_HS_SERVER_HELLO_DONE: int
    BAD_HS_FINISHED: int
    BAD_HS_SERVER_KEX: int
    BAD_HS_CLIENT_KEX: int
    BOGUS_STRING: int
    FORBIDDEN: int
    KEY_DISABLED: int
    KEY_ON_CARD: int
    INV_LOCK_OBJ: int
    TRUE: int
    FALSE: int
    ASS_GENERAL: int
    ASS_ACCEPT_FAILED: int
    ASS_CONNECT_FAILED: int
    ASS_INV_RESPONSE: int
    ASS_INV_VALUE: int
    ASS_INCOMPLETE_LINE: int
    ASS_LINE_TOO_LONG: int
    ASS_NESTED_COMMANDS: int
    ASS_NO_DATA_CB: int
    ASS_NO_INQUIRE_CB: int
    ASS_NOT_A_SERVER: int
    ASS_NOT_A_CLIENT: int
    ASS_SERVER_START: int
    ASS_READ_ERROR: int
    ASS_WRITE_ERROR: int
    ASS_TOO_MUCH_DATA: int
    ASS_UNEXPECTED_CMD: int
    ASS_UNKNOWN_CMD: int
    ASS_SYNTAX: int
    ASS_CANCELED: int
    ASS_NO_INPUT: int
    ASS_NO_OUTPUT: int
    ASS_PARAMETER: int
    ASS_UNKNOWN_INQUIRE: int
    ENGINE_TOO_OLD: int
    WINDOW_TOO_SMALL: int
    WINDOW_TOO_LARGE: int
    MISSING_ENVVAR: int
    USER_ID_EXISTS: int
    NAME_EXISTS: int
    DUP_NAME: int
    TOO_YOUNG: int
    TOO_OLD: int
    UNKNOWN_FLAG: int
    INV_ORDER: int
    ALREADY_FETCHED: int
    TRY_LATER: int
    WRONG_NAME: int
    NO_AUTH: int
    BAD_AUTH: int
    NO_KEYBOXD: int
    KEYBOXD: int
    NO_SERVICE: int
    SERVICE: int
    BAD_PUK: int
    NO_RESET_CODE: int
    BAD_RESET_CODE: int
    SYSTEM_BUG: int
    DNS_UNKNOWN: int
    DNS_SECTION: int
    DNS_ADDRESS: int
    DNS_NO_QUERY: int
    DNS_NO_ANSWER: int
    DNS_CLOSED: int
    DNS_VERIFY: int
    DNS_TIMEOUT: int
    LDAP_GENERAL: int
    LDAP_ATTR_GENERAL: int
    LDAP_NAME_GENERAL: int
    LDAP_SECURITY_GENERAL: int
    LDAP_SERVICE_GENERAL: int
    LDAP_UPDATE_GENERAL: int
    LDAP_E_GENERAL: int
    LDAP_X_GENERAL: int
    LDAP_OTHER_GENERAL: int
    LDAP_X_CONNECTING: int
    LDAP_REFERRAL_LIMIT: int
    LDAP_CLIENT_LOOP: int
    LDAP_NO_RESULTS: int
    LDAP_CONTROL_NOT_FOUND: int
    LDAP_NOT_SUPPORTED: int
    LDAP_CONNECT: int
    LDAP_NO_MEMORY: int
    LDAP_PARAM: int
    LDAP_USER_CANCELLED: int
    LDAP_FILTER: int
    LDAP_AUTH_UNKNOWN: int
    LDAP_TIMEOUT: int
    LDAP_DECODING: int
    LDAP_ENCODING: int
    LDAP_LOCAL: int
    LDAP_SERVER_DOWN: int
    LDAP_SUCCESS: int
    LDAP_OPERATIONS: int
    LDAP_PROTOCOL: int
    LDAP_TIMELIMIT: int
    LDAP_SIZELIMIT: int
    LDAP_COMPARE_FALSE: int
    LDAP_COMPARE_TRUE: int
    LDAP_UNSUPPORTED_AUTH: int
    LDAP_STRONG_AUTH_RQRD: int
    LDAP_PARTIAL_RESULTS: int
    LDAP_REFERRAL: int
    LDAP_ADMINLIMIT: int
    LDAP_UNAVAIL_CRIT_EXTN: int
    LDAP_CONFIDENT_RQRD: int
    LDAP_SASL_BIND_INPROG: int
    LDAP_NO_SUCH_ATTRIBUTE: int
    LDAP_UNDEFINED_TYPE: int
    LDAP_BAD_MATCHING: int
    LDAP_CONST_VIOLATION: int
    LDAP_TYPE_VALUE_EXISTS: int
    LDAP_INV_SYNTAX: int
    LDAP_NO_SUCH_OBJ: int
    LDAP_ALIAS_PROBLEM: int
    LDAP_INV_DN_SYNTAX: int
    LDAP_IS_LEAF: int
    LDAP_ALIAS_DEREF: int
    LDAP_X_PROXY_AUTH_FAIL: int
    LDAP_BAD_AUTH: int
    LDAP_INV_CREDENTIALS: int
    LDAP_INSUFFICIENT_ACC: int
    LDAP_BUSY: int
    LDAP_UNAVAILABLE: int
    LDAP_UNWILL_TO_PERFORM: int
    LDAP_LOOP_DETECT: int
    LDAP_NAMING_VIOLATION: int
    LDAP_OBJ_CLS_VIOLATION: int
    LDAP_NOT_ALLOW_NONLEAF: int
    LDAP_NOT_ALLOW_ON_RDN: int
    LDAP_ALREADY_EXISTS: int
    LDAP_NO_OBJ_CLASS_MODS: int
    LDAP_RESULTS_TOO_LARGE: int
    LDAP_AFFECTS_MULT_DSAS: int
    LDAP_VLV: int
    LDAP_OTHER: int
    LDAP_CUP_RESOURCE_LIMIT: int
    LDAP_CUP_SEC_VIOLATION: int
    LDAP_CUP_INV_DATA: int
    LDAP_CUP_UNSUP_SCHEME: int
    LDAP_CUP_RELOAD: int
    LDAP_CANCELLED: int
    LDAP_NO_SUCH_OPERATION: int
    LDAP_TOO_LATE: int
    LDAP_CANNOT_CANCEL: int
    LDAP_ASSERTION_FAILED: int
    LDAP_PROX_AUTH_DENIED: int
    USER_1: int
    USER_2: int
    USER_3: int
    USER_4: int
    USER_5: int
    USER_6: int
    USER_7: int
    USER_8: int
    USER_9: int
    USER_10: int
    USER_11: int
    USER_12: int
    USER_13: int
    USER_14: int
    USER_15: int
    USER_16: int
    SQL_OK: int
    SQL_ERROR: int
    SQL_INTERNAL: int
    SQL_PERM: int
    SQL_ABORT: int
    SQL_BUSY: int
    SQL_LOCKED: int
    SQL_NOMEM: int
    SQL_READONLY: int
    SQL_INTERRUPT: int
    SQL_IOERR: int
    SQL_CORRUPT: int
    SQL_NOTFOUND: int
    SQL_FULL: int
    SQL_CANTOPEN: int
    SQL_PROTOCOL: int
    SQL_EMPTY: int
    SQL_SCHEMA: int
    SQL_TOOBIG: int
    SQL_CONSTRAINT: int
    SQL_MISMATCH: int
    SQL_MISUSE: int
    SQL_NOLFS: int
    SQL_AUTH: int
    SQL_FORMAT: int
    SQL_RANGE: int
    SQL_NOTADB: int
    SQL_NOTICE: int
    SQL_WARNING: int
    SQL_ROW: int
    SQL_DONE: int
    MISSING_ERRNO: int
    UNKNOWN_ERRNO: int
    EOF: int
    E2BIG: int
    EACCES: int
    EADDRINUSE: int
    EADDRNOTAVAIL: int
    EADV: int
    EAFNOSUPPORT: int
    EAGAIN: int
    EALREADY: int
    EAUTH: int
    EBACKGROUND: int
    EBADE: int
    EBADF: int
    EBADFD: int
    EBADMSG: int
    EBADR: int
    EBADRPC: int
    EBADRQC: int
    EBADSLT: int
    EBFONT: int
    EBUSY: int
    ECANCELED: int
    ECHILD: int
    ECHRNG: int
    ECOMM: int
    ECONNABORTED: int
    ECONNREFUSED: int
    ECONNRESET: int
    ED: int
    EDEADLK: int
    EDEADLOCK: int
    EDESTADDRREQ: int
    EDIED: int
    EDOM: int
    EDOTDOT: int
    EDQUOT: int
    EEXIST: int
    EFAULT: int
    EFBIG: int
    EFTYPE: int
    EGRATUITOUS: int
    EGREGIOUS: int
    EHOSTDOWN: int
    EHOSTUNREACH: int
    EIDRM: int
    EIEIO: int
    EILSEQ: int
    EINPROGRESS: int
    EINTR: int
    EINVAL: int
    EIO: int
    EISCONN: int
    EISDIR: int
    EISNAM: int
    EL2HLT: int
    EL2NSYNC: int
    EL3HLT: int
    EL3RST: int
    ELIBACC: int
    ELIBBAD: int
    ELIBEXEC: int
    ELIBMAX: int
    ELIBSCN: int
    ELNRNG: int
    ELOOP: int
    EMEDIUMTYPE: int
    EMFILE: int
    EMLINK: int
    EMSGSIZE: int
    EMULTIHOP: int
    ENAMETOOLONG: int
    ENAVAIL: int
    ENEEDAUTH: int
    ENETDOWN: int
    ENETRESET: int
    ENETUNREACH: int
    ENFILE: int
    ENOANO: int
    ENOBUFS: int
    ENOCSI: int
    ENODATA: int
    ENODEV: int
    ENOENT: int
    ENOEXEC: int
    ENOLCK: int
    ENOLINK: int
    ENOMEDIUM: int
    ENOMEM: int
    ENOMSG: int
    ENONET: int
    ENOPKG: int
    ENOPROTOOPT: int
    ENOSPC: int
    ENOSR: int
    ENOSTR: int
    ENOSYS: int
    ENOTBLK: int
    ENOTCONN: int
    ENOTDIR: int
    ENOTEMPTY: int
    ENOTNAM: int
    ENOTSOCK: int
    ENOTSUP: int
    ENOTTY: int
    ENOTUNIQ: int
    ENXIO: int
    EOPNOTSUPP: int
    EOVERFLOW: int
    EPERM: int
    EPFNOSUPPORT: int
    EPIPE: int
    EPROCLIM: int
    EPROCUNAVAIL: int
    EPROGMISMATCH: int
    EPROGUNAVAIL: int
    EPROTO: int
    EPROTONOSUPPORT: int
    EPROTOTYPE: int
    ERANGE: int
    EREMCHG: int
    EREMOTE: int
    EREMOTEIO: int
    ERESTART: int
    EROFS: int
    ERPCMISMATCH: int
    ESHUTDOWN: int
    ESOCKTNOSUPPORT: int
    ESPIPE: int
    ESRCH: int
    ESRMNT: int
    ESTALE: int
    ESTRPIPE: int
    ETIME: int
    ETIMEDOUT: int
    ETOOMANYREFS: int
    ETXTBSY: int
    EUCLEAN: int
    EUNATCH: int
    EUSERS: int
    EWOULDBLOCK: int
    EXDEV: int
    EXFULL: int

gpgme_version: str
