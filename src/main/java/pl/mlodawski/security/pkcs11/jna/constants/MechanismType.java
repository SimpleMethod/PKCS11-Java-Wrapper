package pl.mlodawski.security.pkcs11.jna.constants;

import java.util.HashMap;
import java.util.Map;

/**
 * PKCS#11 mechanism types (CKM_*).
 * Based on OASIS PKCS#11 specification.
 */
public final class MechanismType {

    private MechanismType() {}

    public static final long RSA_PKCS_KEY_PAIR_GEN = 0x00000000L;
    public static final long RSA_PKCS = 0x00000001L;
    public static final long RSA_9796 = 0x00000002L;
    public static final long RSA_X_509 = 0x00000003L;
    public static final long MD2_RSA_PKCS = 0x00000004L;
    public static final long MD5_RSA_PKCS = 0x00000005L;
    public static final long SHA1_RSA_PKCS = 0x00000006L;
    public static final long RIPEMD128_RSA_PKCS = 0x00000007L;
    public static final long RIPEMD160_RSA_PKCS = 0x00000008L;
    public static final long RSA_PKCS_OAEP = 0x00000009L;
    public static final long RSA_X9_31_KEY_PAIR_GEN = 0x0000000AL;
    public static final long RSA_X9_31 = 0x0000000BL;
    public static final long SHA1_RSA_X9_31 = 0x0000000CL;
    public static final long RSA_PKCS_PSS = 0x0000000DL;
    public static final long SHA1_RSA_PKCS_PSS = 0x0000000EL;

    public static final long DSA_KEY_PAIR_GEN = 0x00000010L;
    public static final long DSA = 0x00000011L;
    public static final long DSA_SHA1 = 0x00000012L;
    public static final long DSA_SHA224 = 0x00000013L;
    public static final long DSA_SHA256 = 0x00000014L;
    public static final long DSA_SHA384 = 0x00000015L;
    public static final long DSA_SHA512 = 0x00000016L;

    public static final long DH_PKCS_KEY_PAIR_GEN = 0x00000020L;
    public static final long DH_PKCS_DERIVE = 0x00000021L;

    public static final long X9_42_DH_KEY_PAIR_GEN = 0x00000030L;
    public static final long X9_42_DH_DERIVE = 0x00000031L;
    public static final long X9_42_DH_HYBRID_DERIVE = 0x00000032L;
    public static final long X9_42_MQV_DERIVE = 0x00000033L;

    public static final long SHA256_RSA_PKCS = 0x00000040L;
    public static final long SHA384_RSA_PKCS = 0x00000041L;
    public static final long SHA512_RSA_PKCS = 0x00000042L;
    public static final long SHA256_RSA_PKCS_PSS = 0x00000043L;
    public static final long SHA384_RSA_PKCS_PSS = 0x00000044L;
    public static final long SHA512_RSA_PKCS_PSS = 0x00000045L;

    public static final long SHA224_RSA_PKCS = 0x00000046L;
    public static final long SHA224_RSA_PKCS_PSS = 0x00000047L;

    public static final long SHA512_224 = 0x00000048L;
    public static final long SHA512_224_HMAC = 0x00000049L;
    public static final long SHA512_224_HMAC_GENERAL = 0x0000004AL;
    public static final long SHA512_224_KEY_DERIVATION = 0x0000004BL;
    public static final long SHA512_256 = 0x0000004CL;
    public static final long SHA512_256_HMAC = 0x0000004DL;
    public static final long SHA512_256_HMAC_GENERAL = 0x0000004EL;
    public static final long SHA512_256_KEY_DERIVATION = 0x0000004FL;

    public static final long RC2_KEY_GEN = 0x00000100L;
    public static final long RC2_ECB = 0x00000101L;
    public static final long RC2_CBC = 0x00000102L;
    public static final long RC2_MAC = 0x00000103L;
    public static final long RC2_MAC_GENERAL = 0x00000104L;
    public static final long RC2_CBC_PAD = 0x00000105L;

    public static final long RC4_KEY_GEN = 0x00000110L;
    public static final long RC4 = 0x00000111L;

    public static final long DES_KEY_GEN = 0x00000120L;
    public static final long DES_ECB = 0x00000121L;
    public static final long DES_CBC = 0x00000122L;
    public static final long DES_MAC = 0x00000123L;
    public static final long DES_MAC_GENERAL = 0x00000124L;
    public static final long DES_CBC_PAD = 0x00000125L;

    public static final long DES2_KEY_GEN = 0x00000130L;
    public static final long DES3_KEY_GEN = 0x00000131L;
    public static final long DES3_ECB = 0x00000132L;
    public static final long DES3_CBC = 0x00000133L;
    public static final long DES3_MAC = 0x00000134L;
    public static final long DES3_MAC_GENERAL = 0x00000135L;
    public static final long DES3_CBC_PAD = 0x00000136L;
    public static final long DES3_CMAC_GENERAL = 0x00000137L;
    public static final long DES3_CMAC = 0x00000138L;

    public static final long CDMF_KEY_GEN = 0x00000140L;
    public static final long CDMF_ECB = 0x00000141L;
    public static final long CDMF_CBC = 0x00000142L;
    public static final long CDMF_MAC = 0x00000143L;
    public static final long CDMF_MAC_GENERAL = 0x00000144L;
    public static final long CDMF_CBC_PAD = 0x00000145L;

    public static final long DES_OFB64 = 0x00000150L;
    public static final long DES_OFB8 = 0x00000151L;
    public static final long DES_CFB64 = 0x00000152L;
    public static final long DES_CFB8 = 0x00000153L;

    public static final long MD2 = 0x00000200L;
    public static final long MD2_HMAC = 0x00000201L;
    public static final long MD2_HMAC_GENERAL = 0x00000202L;

    public static final long MD5 = 0x00000210L;
    public static final long MD5_HMAC = 0x00000211L;
    public static final long MD5_HMAC_GENERAL = 0x00000212L;

    public static final long SHA_1 = 0x00000220L;
    public static final long SHA_1_HMAC = 0x00000221L;
    public static final long SHA_1_HMAC_GENERAL = 0x00000222L;

    public static final long RIPEMD128 = 0x00000230L;
    public static final long RIPEMD128_HMAC = 0x00000231L;
    public static final long RIPEMD128_HMAC_GENERAL = 0x00000232L;
    public static final long RIPEMD160 = 0x00000240L;
    public static final long RIPEMD160_HMAC = 0x00000241L;
    public static final long RIPEMD160_HMAC_GENERAL = 0x00000242L;

    public static final long SHA256 = 0x00000250L;
    public static final long SHA256_HMAC = 0x00000251L;
    public static final long SHA256_HMAC_GENERAL = 0x00000252L;

    public static final long SHA224 = 0x00000255L;
    public static final long SHA224_HMAC = 0x00000256L;
    public static final long SHA224_HMAC_GENERAL = 0x00000257L;

    public static final long SHA384 = 0x00000260L;
    public static final long SHA384_HMAC = 0x00000261L;
    public static final long SHA384_HMAC_GENERAL = 0x00000262L;

    public static final long SHA512 = 0x00000270L;
    public static final long SHA512_HMAC = 0x00000271L;
    public static final long SHA512_HMAC_GENERAL = 0x00000272L;

    public static final long SECURID_KEY_GEN = 0x00000280L;
    public static final long SECURID = 0x00000282L;
    public static final long HOTP_KEY_GEN = 0x00000290L;
    public static final long HOTP = 0x00000291L;
    public static final long ACTI = 0x000002A0L;
    public static final long ACTI_KEY_GEN = 0x000002A1L;

    public static final long CAST_KEY_GEN = 0x00000300L;
    public static final long CAST_ECB = 0x00000301L;
    public static final long CAST_CBC = 0x00000302L;
    public static final long CAST_MAC = 0x00000303L;
    public static final long CAST_MAC_GENERAL = 0x00000304L;
    public static final long CAST_CBC_PAD = 0x00000305L;
    public static final long CAST3_KEY_GEN = 0x00000310L;
    public static final long CAST3_ECB = 0x00000311L;
    public static final long CAST3_CBC = 0x00000312L;
    public static final long CAST3_MAC = 0x00000313L;
    public static final long CAST3_MAC_GENERAL = 0x00000314L;
    public static final long CAST3_CBC_PAD = 0x00000315L;
    public static final long CAST128_KEY_GEN = 0x00000320L;
    public static final long CAST128_ECB = 0x00000321L;
    public static final long CAST128_CBC = 0x00000322L;
    public static final long CAST128_MAC = 0x00000323L;
    public static final long CAST128_MAC_GENERAL = 0x00000324L;
    public static final long CAST128_CBC_PAD = 0x00000325L;

    public static final long RC5_KEY_GEN = 0x00000330L;
    public static final long RC5_ECB = 0x00000331L;
    public static final long RC5_CBC = 0x00000332L;
    public static final long RC5_MAC = 0x00000333L;
    public static final long RC5_MAC_GENERAL = 0x00000334L;
    public static final long RC5_CBC_PAD = 0x00000335L;

    public static final long IDEA_KEY_GEN = 0x00000340L;
    public static final long IDEA_ECB = 0x00000341L;
    public static final long IDEA_CBC = 0x00000342L;
    public static final long IDEA_MAC = 0x00000343L;
    public static final long IDEA_MAC_GENERAL = 0x00000344L;
    public static final long IDEA_CBC_PAD = 0x00000345L;

    public static final long GENERIC_SECRET_KEY_GEN = 0x00000350L;
    public static final long CONCATENATE_BASE_AND_KEY = 0x00000360L;
    public static final long CONCATENATE_BASE_AND_DATA = 0x00000362L;
    public static final long CONCATENATE_DATA_AND_BASE = 0x00000363L;
    public static final long XOR_BASE_AND_DATA = 0x00000364L;
    public static final long EXTRACT_KEY_FROM_KEY = 0x00000365L;

    public static final long SSL3_PRE_MASTER_KEY_GEN = 0x00000370L;
    public static final long SSL3_MASTER_KEY_DERIVE = 0x00000371L;
    public static final long SSL3_KEY_AND_MAC_DERIVE = 0x00000372L;
    public static final long SSL3_MASTER_KEY_DERIVE_DH = 0x00000373L;
    public static final long TLS_PRE_MASTER_KEY_GEN = 0x00000374L;
    public static final long TLS_MASTER_KEY_DERIVE = 0x00000375L;
    public static final long TLS_KEY_AND_MAC_DERIVE = 0x00000376L;
    public static final long TLS_MASTER_KEY_DERIVE_DH = 0x00000377L;
    public static final long TLS_PRF = 0x00000378L;

    public static final long SSL3_MD5_MAC = 0x00000380L;
    public static final long SSL3_SHA1_MAC = 0x00000381L;

    public static final long MD5_KEY_DERIVATION = 0x00000390L;
    public static final long MD2_KEY_DERIVATION = 0x00000391L;
    public static final long SHA1_KEY_DERIVATION = 0x00000392L;
    public static final long SHA256_KEY_DERIVATION = 0x00000393L;
    public static final long SHA384_KEY_DERIVATION = 0x00000394L;
    public static final long SHA512_KEY_DERIVATION = 0x00000395L;
    public static final long SHA224_KEY_DERIVATION = 0x00000396L;

    public static final long PBE_MD2_DES_CBC = 0x000003A0L;
    public static final long PBE_MD5_DES_CBC = 0x000003A1L;
    public static final long PBE_MD5_CAST_CBC = 0x000003A2L;
    public static final long PBE_MD5_CAST3_CBC = 0x000003A3L;
    public static final long PBE_MD5_CAST128_CBC = 0x000003A4L;
    public static final long PBE_SHA1_CAST128_CBC = 0x000003A5L;
    public static final long PBE_SHA1_RC4_128 = 0x000003A6L;
    public static final long PBE_SHA1_RC4_40 = 0x000003A7L;
    public static final long PBE_SHA1_DES3_EDE_CBC = 0x000003A8L;
    public static final long PBE_SHA1_DES2_EDE_CBC = 0x000003A9L;
    public static final long PBE_SHA1_RC2_128_CBC = 0x000003AAL;
    public static final long PBE_SHA1_RC2_40_CBC = 0x000003ABL;

    public static final long PKCS5_PBKD2 = 0x000003B0L;

    public static final long PBA_SHA1_WITH_SHA1_HMAC = 0x000003C0L;

    public static final long WTLS_PRE_MASTER_KEY_GEN = 0x000003D0L;
    public static final long WTLS_MASTER_KEY_DERIVE = 0x000003D1L;
    public static final long WTLS_MASTER_KEY_DERIVE_DH_ECC = 0x000003D2L;
    public static final long WTLS_PRF = 0x000003D3L;
    public static final long WTLS_SERVER_KEY_AND_MAC_DERIVE = 0x000003D4L;
    public static final long WTLS_CLIENT_KEY_AND_MAC_DERIVE = 0x000003D5L;

    public static final long TLS10_MAC_SERVER = 0x000003D6L;
    public static final long TLS10_MAC_CLIENT = 0x000003D7L;
    public static final long TLS12_MAC = 0x000003D8L;
    public static final long TLS12_KDF = 0x000003D9L;
    public static final long TLS12_MASTER_KEY_DERIVE = 0x000003E0L;
    public static final long TLS12_KEY_AND_MAC_DERIVE = 0x000003E1L;
    public static final long TLS12_MASTER_KEY_DERIVE_DH = 0x000003E2L;
    public static final long TLS12_KEY_SAFE_DERIVE = 0x000003E3L;
    public static final long TLS_MAC = 0x000003E4L;
    public static final long TLS_KDF = 0x000003E5L;

    public static final long KEY_WRAP_LYNKS = 0x00000400L;
    public static final long KEY_WRAP_SET_OAEP = 0x00000401L;

    public static final long CMS_SIG = 0x00000500L;
    public static final long KIP_DERIVE = 0x00000510L;
    public static final long KIP_WRAP = 0x00000511L;
    public static final long KIP_MAC = 0x00000512L;

    public static final long CAMELLIA_KEY_GEN = 0x00000550L;
    public static final long CAMELLIA_ECB = 0x00000551L;
    public static final long CAMELLIA_CBC = 0x00000552L;
    public static final long CAMELLIA_MAC = 0x00000553L;
    public static final long CAMELLIA_MAC_GENERAL = 0x00000554L;
    public static final long CAMELLIA_CBC_PAD = 0x00000555L;
    public static final long CAMELLIA_ECB_ENCRYPT_DATA = 0x00000556L;
    public static final long CAMELLIA_CBC_ENCRYPT_DATA = 0x00000557L;
    public static final long CAMELLIA_CTR = 0x00000558L;

    public static final long ARIA_KEY_GEN = 0x00000560L;
    public static final long ARIA_ECB = 0x00000561L;
    public static final long ARIA_CBC = 0x00000562L;
    public static final long ARIA_MAC = 0x00000563L;
    public static final long ARIA_MAC_GENERAL = 0x00000564L;
    public static final long ARIA_CBC_PAD = 0x00000565L;
    public static final long ARIA_ECB_ENCRYPT_DATA = 0x00000566L;
    public static final long ARIA_CBC_ENCRYPT_DATA = 0x00000567L;

    public static final long SEED_KEY_GEN = 0x00000650L;
    public static final long SEED_ECB = 0x00000651L;
    public static final long SEED_CBC = 0x00000652L;
    public static final long SEED_MAC = 0x00000653L;
    public static final long SEED_MAC_GENERAL = 0x00000654L;
    public static final long SEED_CBC_PAD = 0x00000655L;
    public static final long SEED_ECB_ENCRYPT_DATA = 0x00000656L;
    public static final long SEED_CBC_ENCRYPT_DATA = 0x00000657L;

    public static final long SKIPJACK_KEY_GEN = 0x00001000L;
    public static final long SKIPJACK_ECB64 = 0x00001001L;
    public static final long SKIPJACK_CBC64 = 0x00001002L;
    public static final long SKIPJACK_OFB64 = 0x00001003L;
    public static final long SKIPJACK_CFB64 = 0x00001004L;
    public static final long SKIPJACK_CFB32 = 0x00001005L;
    public static final long SKIPJACK_CFB16 = 0x00001006L;
    public static final long SKIPJACK_CFB8 = 0x00001007L;
    public static final long SKIPJACK_WRAP = 0x00001008L;
    public static final long SKIPJACK_PRIVATE_WRAP = 0x00001009L;
    public static final long SKIPJACK_RELAYX = 0x0000100AL;

    public static final long KEA_KEY_PAIR_GEN = 0x00001010L;
    public static final long KEA_KEY_DERIVE = 0x00001011L;
    public static final long KEA_DERIVE = 0x00001012L;

    public static final long FORTEZZA_TIMESTAMP = 0x00001020L;

    public static final long BATON_KEY_GEN = 0x00001030L;
    public static final long BATON_ECB128 = 0x00001031L;
    public static final long BATON_ECB96 = 0x00001032L;
    public static final long BATON_CBC128 = 0x00001033L;
    public static final long BATON_COUNTER = 0x00001034L;
    public static final long BATON_SHUFFLE = 0x00001035L;
    public static final long BATON_WRAP = 0x00001036L;

    public static final long ECDSA_KEY_PAIR_GEN = 0x00001040L;
    public static final long EC_KEY_PAIR_GEN = 0x00001040L;
    public static final long ECDSA = 0x00001041L;
    public static final long ECDSA_SHA1 = 0x00001042L;
    public static final long ECDSA_SHA224 = 0x00001043L;
    public static final long ECDSA_SHA256 = 0x00001044L;
    public static final long ECDSA_SHA384 = 0x00001045L;
    public static final long ECDSA_SHA512 = 0x00001046L;

    public static final long ECDH1_DERIVE = 0x00001050L;
    public static final long ECDH1_COFACTOR_DERIVE = 0x00001051L;
    public static final long ECMQV_DERIVE = 0x00001052L;

    public static final long ECDH_AES_KEY_WRAP = 0x00001053L;
    public static final long RSA_AES_KEY_WRAP = 0x00001054L;

    public static final long JUNIPER_KEY_GEN = 0x00001060L;
    public static final long JUNIPER_ECB128 = 0x00001061L;
    public static final long JUNIPER_CBC128 = 0x00001062L;
    public static final long JUNIPER_COUNTER = 0x00001063L;
    public static final long JUNIPER_SHUFFLE = 0x00001064L;
    public static final long JUNIPER_WRAP = 0x00001065L;
    public static final long FASTHASH = 0x00001070L;

    public static final long AES_KEY_GEN = 0x00001080L;
    public static final long AES_ECB = 0x00001081L;
    public static final long AES_CBC = 0x00001082L;
    public static final long AES_MAC = 0x00001083L;
    public static final long AES_MAC_GENERAL = 0x00001084L;
    public static final long AES_CBC_PAD = 0x00001085L;
    public static final long AES_CTR = 0x00001086L;
    public static final long AES_GCM = 0x00001087L;
    public static final long AES_CCM = 0x00001088L;
    public static final long AES_CTS = 0x00001089L;
    public static final long AES_CMAC = 0x0000108AL;
    public static final long AES_CMAC_GENERAL = 0x0000108BL;
    public static final long AES_XCBC_MAC = 0x0000108CL;
    public static final long AES_XCBC_MAC_96 = 0x0000108DL;
    public static final long AES_GMAC = 0x0000108EL;

    public static final long BLOWFISH_KEY_GEN = 0x00001090L;
    public static final long BLOWFISH_CBC = 0x00001091L;
    public static final long TWOFISH_KEY_GEN = 0x00001092L;
    public static final long TWOFISH_CBC = 0x00001093L;
    public static final long BLOWFISH_CBC_PAD = 0x00001094L;
    public static final long TWOFISH_CBC_PAD = 0x00001095L;

    public static final long DES_ECB_ENCRYPT_DATA = 0x00001100L;
    public static final long DES_CBC_ENCRYPT_DATA = 0x00001101L;
    public static final long DES3_ECB_ENCRYPT_DATA = 0x00001102L;
    public static final long DES3_CBC_ENCRYPT_DATA = 0x00001103L;
    public static final long AES_ECB_ENCRYPT_DATA = 0x00001104L;
    public static final long AES_CBC_ENCRYPT_DATA = 0x00001105L;

    public static final long GOSTR3410_KEY_PAIR_GEN = 0x00001200L;
    public static final long GOSTR3410 = 0x00001201L;
    public static final long GOSTR3410_WITH_GOSTR3411 = 0x00001202L;
    public static final long GOSTR3410_KEY_WRAP = 0x00001203L;
    public static final long GOSTR3410_DERIVE = 0x00001204L;
    public static final long GOSTR3411 = 0x00001210L;
    public static final long GOSTR3411_HMAC = 0x00001211L;
    public static final long GOST28147_KEY_GEN = 0x00001220L;
    public static final long GOST28147_ECB = 0x00001221L;
    public static final long GOST28147 = 0x00001222L;
    public static final long GOST28147_MAC = 0x00001223L;
    public static final long GOST28147_KEY_WRAP = 0x00001224L;

    public static final long DSA_PARAMETER_GEN = 0x00002000L;
    public static final long DH_PKCS_PARAMETER_GEN = 0x00002001L;
    public static final long X9_42_DH_PARAMETER_GEN = 0x00002002L;
    public static final long DSA_PROBABLISTIC_PARAMETER_GEN = 0x00002003L;
    public static final long DSA_SHAWE_TAYLOR_PARAMETER_GEN = 0x00002004L;

    public static final long AES_OFB = 0x00002104L;
    public static final long AES_CFB64 = 0x00002105L;
    public static final long AES_CFB8 = 0x00002106L;
    public static final long AES_CFB128 = 0x00002107L;
    public static final long AES_CFB1 = 0x00002108L;
    public static final long AES_KEY_WRAP = 0x00002109L;
    public static final long AES_KEY_WRAP_PAD = 0x0000210AL;

    public static final long RSA_PKCS_TPM_1_1 = 0x00004001L;
    public static final long RSA_PKCS_OAEP_TPM_1_1 = 0x00004002L;

    public static final long VENDOR_DEFINED = 0x80000000L;

    private static final Map<Long, String> MECHANISM_NAMES = new HashMap<>();

    static {
        // RSA mechanisms
        MECHANISM_NAMES.put(RSA_PKCS_KEY_PAIR_GEN, "RSA_PKCS_KEY_PAIR_GEN");
        MECHANISM_NAMES.put(RSA_PKCS, "RSA_PKCS");
        MECHANISM_NAMES.put(RSA_9796, "RSA_9796");
        MECHANISM_NAMES.put(RSA_X_509, "RSA_X_509");
        MECHANISM_NAMES.put(MD2_RSA_PKCS, "MD2_RSA_PKCS");
        MECHANISM_NAMES.put(MD5_RSA_PKCS, "MD5_RSA_PKCS");
        MECHANISM_NAMES.put(SHA1_RSA_PKCS, "SHA1_RSA_PKCS");
        MECHANISM_NAMES.put(RIPEMD128_RSA_PKCS, "RIPEMD128_RSA_PKCS");
        MECHANISM_NAMES.put(RIPEMD160_RSA_PKCS, "RIPEMD160_RSA_PKCS");
        MECHANISM_NAMES.put(RSA_PKCS_OAEP, "RSA_PKCS_OAEP");
        MECHANISM_NAMES.put(RSA_X9_31_KEY_PAIR_GEN, "RSA_X9_31_KEY_PAIR_GEN");
        MECHANISM_NAMES.put(RSA_X9_31, "RSA_X9_31");
        MECHANISM_NAMES.put(SHA1_RSA_X9_31, "SHA1_RSA_X9_31");
        MECHANISM_NAMES.put(RSA_PKCS_PSS, "RSA_PKCS_PSS");
        MECHANISM_NAMES.put(SHA1_RSA_PKCS_PSS, "SHA1_RSA_PKCS_PSS");
        MECHANISM_NAMES.put(SHA256_RSA_PKCS, "SHA256_RSA_PKCS");
        MECHANISM_NAMES.put(SHA384_RSA_PKCS, "SHA384_RSA_PKCS");
        MECHANISM_NAMES.put(SHA512_RSA_PKCS, "SHA512_RSA_PKCS");
        MECHANISM_NAMES.put(SHA256_RSA_PKCS_PSS, "SHA256_RSA_PKCS_PSS");
        MECHANISM_NAMES.put(SHA384_RSA_PKCS_PSS, "SHA384_RSA_PKCS_PSS");
        MECHANISM_NAMES.put(SHA512_RSA_PKCS_PSS, "SHA512_RSA_PKCS_PSS");
        MECHANISM_NAMES.put(SHA224_RSA_PKCS, "SHA224_RSA_PKCS");
        MECHANISM_NAMES.put(SHA224_RSA_PKCS_PSS, "SHA224_RSA_PKCS_PSS");
        MECHANISM_NAMES.put(RSA_AES_KEY_WRAP, "RSA_AES_KEY_WRAP");
        MECHANISM_NAMES.put(RSA_PKCS_TPM_1_1, "RSA_PKCS_TPM_1_1");
        MECHANISM_NAMES.put(RSA_PKCS_OAEP_TPM_1_1, "RSA_PKCS_OAEP_TPM_1_1");

        // DSA mechanisms
        MECHANISM_NAMES.put(DSA_KEY_PAIR_GEN, "DSA_KEY_PAIR_GEN");
        MECHANISM_NAMES.put(DSA, "DSA");
        MECHANISM_NAMES.put(DSA_SHA1, "DSA_SHA1");
        MECHANISM_NAMES.put(DSA_SHA224, "DSA_SHA224");
        MECHANISM_NAMES.put(DSA_SHA256, "DSA_SHA256");
        MECHANISM_NAMES.put(DSA_SHA384, "DSA_SHA384");
        MECHANISM_NAMES.put(DSA_SHA512, "DSA_SHA512");
        MECHANISM_NAMES.put(DSA_PARAMETER_GEN, "DSA_PARAMETER_GEN");
        MECHANISM_NAMES.put(DSA_PROBABLISTIC_PARAMETER_GEN, "DSA_PROBABLISTIC_PARAMETER_GEN");
        MECHANISM_NAMES.put(DSA_SHAWE_TAYLOR_PARAMETER_GEN, "DSA_SHAWE_TAYLOR_PARAMETER_GEN");

        // DH mechanisms
        MECHANISM_NAMES.put(DH_PKCS_KEY_PAIR_GEN, "DH_PKCS_KEY_PAIR_GEN");
        MECHANISM_NAMES.put(DH_PKCS_DERIVE, "DH_PKCS_DERIVE");
        MECHANISM_NAMES.put(DH_PKCS_PARAMETER_GEN, "DH_PKCS_PARAMETER_GEN");
        MECHANISM_NAMES.put(X9_42_DH_KEY_PAIR_GEN, "X9_42_DH_KEY_PAIR_GEN");
        MECHANISM_NAMES.put(X9_42_DH_DERIVE, "X9_42_DH_DERIVE");
        MECHANISM_NAMES.put(X9_42_DH_HYBRID_DERIVE, "X9_42_DH_HYBRID_DERIVE");
        MECHANISM_NAMES.put(X9_42_MQV_DERIVE, "X9_42_MQV_DERIVE");
        MECHANISM_NAMES.put(X9_42_DH_PARAMETER_GEN, "X9_42_DH_PARAMETER_GEN");

        // Hash mechanisms
        MECHANISM_NAMES.put(MD2, "MD2");
        MECHANISM_NAMES.put(MD2_HMAC, "MD2_HMAC");
        MECHANISM_NAMES.put(MD2_HMAC_GENERAL, "MD2_HMAC_GENERAL");
        MECHANISM_NAMES.put(MD5, "MD5");
        MECHANISM_NAMES.put(MD5_HMAC, "MD5_HMAC");
        MECHANISM_NAMES.put(MD5_HMAC_GENERAL, "MD5_HMAC_GENERAL");
        MECHANISM_NAMES.put(SHA_1, "SHA_1");
        MECHANISM_NAMES.put(SHA_1_HMAC, "SHA_1_HMAC");
        MECHANISM_NAMES.put(SHA_1_HMAC_GENERAL, "SHA_1_HMAC_GENERAL");
        MECHANISM_NAMES.put(SHA256, "SHA256");
        MECHANISM_NAMES.put(SHA256_HMAC, "SHA256_HMAC");
        MECHANISM_NAMES.put(SHA256_HMAC_GENERAL, "SHA256_HMAC_GENERAL");
        MECHANISM_NAMES.put(SHA224, "SHA224");
        MECHANISM_NAMES.put(SHA224_HMAC, "SHA224_HMAC");
        MECHANISM_NAMES.put(SHA224_HMAC_GENERAL, "SHA224_HMAC_GENERAL");
        MECHANISM_NAMES.put(SHA384, "SHA384");
        MECHANISM_NAMES.put(SHA384_HMAC, "SHA384_HMAC");
        MECHANISM_NAMES.put(SHA384_HMAC_GENERAL, "SHA384_HMAC_GENERAL");
        MECHANISM_NAMES.put(SHA512, "SHA512");
        MECHANISM_NAMES.put(SHA512_HMAC, "SHA512_HMAC");
        MECHANISM_NAMES.put(SHA512_HMAC_GENERAL, "SHA512_HMAC_GENERAL");
        MECHANISM_NAMES.put(SHA512_224, "SHA512_224");
        MECHANISM_NAMES.put(SHA512_224_HMAC, "SHA512_224_HMAC");
        MECHANISM_NAMES.put(SHA512_224_HMAC_GENERAL, "SHA512_224_HMAC_GENERAL");
        MECHANISM_NAMES.put(SHA512_224_KEY_DERIVATION, "SHA512_224_KEY_DERIVATION");
        MECHANISM_NAMES.put(SHA512_256, "SHA512_256");
        MECHANISM_NAMES.put(SHA512_256_HMAC, "SHA512_256_HMAC");
        MECHANISM_NAMES.put(SHA512_256_HMAC_GENERAL, "SHA512_256_HMAC_GENERAL");
        MECHANISM_NAMES.put(SHA512_256_KEY_DERIVATION, "SHA512_256_KEY_DERIVATION");
        MECHANISM_NAMES.put(RIPEMD128, "RIPEMD128");
        MECHANISM_NAMES.put(RIPEMD128_HMAC, "RIPEMD128_HMAC");
        MECHANISM_NAMES.put(RIPEMD128_HMAC_GENERAL, "RIPEMD128_HMAC_GENERAL");
        MECHANISM_NAMES.put(RIPEMD160, "RIPEMD160");
        MECHANISM_NAMES.put(RIPEMD160_HMAC, "RIPEMD160_HMAC");
        MECHANISM_NAMES.put(RIPEMD160_HMAC_GENERAL, "RIPEMD160_HMAC_GENERAL");

        // Key derivation
        MECHANISM_NAMES.put(MD5_KEY_DERIVATION, "MD5_KEY_DERIVATION");
        MECHANISM_NAMES.put(MD2_KEY_DERIVATION, "MD2_KEY_DERIVATION");
        MECHANISM_NAMES.put(SHA1_KEY_DERIVATION, "SHA1_KEY_DERIVATION");
        MECHANISM_NAMES.put(SHA256_KEY_DERIVATION, "SHA256_KEY_DERIVATION");
        MECHANISM_NAMES.put(SHA384_KEY_DERIVATION, "SHA384_KEY_DERIVATION");
        MECHANISM_NAMES.put(SHA512_KEY_DERIVATION, "SHA512_KEY_DERIVATION");
        MECHANISM_NAMES.put(SHA224_KEY_DERIVATION, "SHA224_KEY_DERIVATION");

        // EC mechanisms
        MECHANISM_NAMES.put(EC_KEY_PAIR_GEN, "EC_KEY_PAIR_GEN");
        MECHANISM_NAMES.put(ECDSA, "ECDSA");
        MECHANISM_NAMES.put(ECDSA_SHA1, "ECDSA_SHA1");
        MECHANISM_NAMES.put(ECDSA_SHA224, "ECDSA_SHA224");
        MECHANISM_NAMES.put(ECDSA_SHA256, "ECDSA_SHA256");
        MECHANISM_NAMES.put(ECDSA_SHA384, "ECDSA_SHA384");
        MECHANISM_NAMES.put(ECDSA_SHA512, "ECDSA_SHA512");
        MECHANISM_NAMES.put(ECDH1_DERIVE, "ECDH1_DERIVE");
        MECHANISM_NAMES.put(ECDH1_COFACTOR_DERIVE, "ECDH1_COFACTOR_DERIVE");
        MECHANISM_NAMES.put(ECMQV_DERIVE, "ECMQV_DERIVE");
        MECHANISM_NAMES.put(ECDH_AES_KEY_WRAP, "ECDH_AES_KEY_WRAP");

        // AES mechanisms
        MECHANISM_NAMES.put(AES_KEY_GEN, "AES_KEY_GEN");
        MECHANISM_NAMES.put(AES_ECB, "AES_ECB");
        MECHANISM_NAMES.put(AES_CBC, "AES_CBC");
        MECHANISM_NAMES.put(AES_MAC, "AES_MAC");
        MECHANISM_NAMES.put(AES_MAC_GENERAL, "AES_MAC_GENERAL");
        MECHANISM_NAMES.put(AES_CBC_PAD, "AES_CBC_PAD");
        MECHANISM_NAMES.put(AES_CTR, "AES_CTR");
        MECHANISM_NAMES.put(AES_GCM, "AES_GCM");
        MECHANISM_NAMES.put(AES_CCM, "AES_CCM");
        MECHANISM_NAMES.put(AES_CTS, "AES_CTS");
        MECHANISM_NAMES.put(AES_CMAC, "AES_CMAC");
        MECHANISM_NAMES.put(AES_CMAC_GENERAL, "AES_CMAC_GENERAL");
        MECHANISM_NAMES.put(AES_XCBC_MAC, "AES_XCBC_MAC");
        MECHANISM_NAMES.put(AES_XCBC_MAC_96, "AES_XCBC_MAC_96");
        MECHANISM_NAMES.put(AES_GMAC, "AES_GMAC");
        MECHANISM_NAMES.put(AES_OFB, "AES_OFB");
        MECHANISM_NAMES.put(AES_CFB64, "AES_CFB64");
        MECHANISM_NAMES.put(AES_CFB8, "AES_CFB8");
        MECHANISM_NAMES.put(AES_CFB128, "AES_CFB128");
        MECHANISM_NAMES.put(AES_CFB1, "AES_CFB1");
        MECHANISM_NAMES.put(AES_KEY_WRAP, "AES_KEY_WRAP");
        MECHANISM_NAMES.put(AES_KEY_WRAP_PAD, "AES_KEY_WRAP_PAD");
        MECHANISM_NAMES.put(AES_ECB_ENCRYPT_DATA, "AES_ECB_ENCRYPT_DATA");
        MECHANISM_NAMES.put(AES_CBC_ENCRYPT_DATA, "AES_CBC_ENCRYPT_DATA");

        // DES mechanisms
        MECHANISM_NAMES.put(DES_KEY_GEN, "DES_KEY_GEN");
        MECHANISM_NAMES.put(DES_ECB, "DES_ECB");
        MECHANISM_NAMES.put(DES_CBC, "DES_CBC");
        MECHANISM_NAMES.put(DES_MAC, "DES_MAC");
        MECHANISM_NAMES.put(DES_MAC_GENERAL, "DES_MAC_GENERAL");
        MECHANISM_NAMES.put(DES_CBC_PAD, "DES_CBC_PAD");
        MECHANISM_NAMES.put(DES_OFB64, "DES_OFB64");
        MECHANISM_NAMES.put(DES_OFB8, "DES_OFB8");
        MECHANISM_NAMES.put(DES_CFB64, "DES_CFB64");
        MECHANISM_NAMES.put(DES_CFB8, "DES_CFB8");
        MECHANISM_NAMES.put(DES_ECB_ENCRYPT_DATA, "DES_ECB_ENCRYPT_DATA");
        MECHANISM_NAMES.put(DES_CBC_ENCRYPT_DATA, "DES_CBC_ENCRYPT_DATA");

        // DES3 mechanisms
        MECHANISM_NAMES.put(DES2_KEY_GEN, "DES2_KEY_GEN");
        MECHANISM_NAMES.put(DES3_KEY_GEN, "DES3_KEY_GEN");
        MECHANISM_NAMES.put(DES3_ECB, "DES3_ECB");
        MECHANISM_NAMES.put(DES3_CBC, "DES3_CBC");
        MECHANISM_NAMES.put(DES3_MAC, "DES3_MAC");
        MECHANISM_NAMES.put(DES3_MAC_GENERAL, "DES3_MAC_GENERAL");
        MECHANISM_NAMES.put(DES3_CBC_PAD, "DES3_CBC_PAD");
        MECHANISM_NAMES.put(DES3_CMAC_GENERAL, "DES3_CMAC_GENERAL");
        MECHANISM_NAMES.put(DES3_CMAC, "DES3_CMAC");
        MECHANISM_NAMES.put(DES3_ECB_ENCRYPT_DATA, "DES3_ECB_ENCRYPT_DATA");
        MECHANISM_NAMES.put(DES3_CBC_ENCRYPT_DATA, "DES3_CBC_ENCRYPT_DATA");

        // RC2 mechanisms
        MECHANISM_NAMES.put(RC2_KEY_GEN, "RC2_KEY_GEN");
        MECHANISM_NAMES.put(RC2_ECB, "RC2_ECB");
        MECHANISM_NAMES.put(RC2_CBC, "RC2_CBC");
        MECHANISM_NAMES.put(RC2_MAC, "RC2_MAC");
        MECHANISM_NAMES.put(RC2_MAC_GENERAL, "RC2_MAC_GENERAL");
        MECHANISM_NAMES.put(RC2_CBC_PAD, "RC2_CBC_PAD");

        // RC4 mechanisms
        MECHANISM_NAMES.put(RC4_KEY_GEN, "RC4_KEY_GEN");
        MECHANISM_NAMES.put(RC4, "RC4");

        // RC5 mechanisms
        MECHANISM_NAMES.put(RC5_KEY_GEN, "RC5_KEY_GEN");
        MECHANISM_NAMES.put(RC5_ECB, "RC5_ECB");
        MECHANISM_NAMES.put(RC5_CBC, "RC5_CBC");
        MECHANISM_NAMES.put(RC5_MAC, "RC5_MAC");
        MECHANISM_NAMES.put(RC5_MAC_GENERAL, "RC5_MAC_GENERAL");
        MECHANISM_NAMES.put(RC5_CBC_PAD, "RC5_CBC_PAD");

        // CDMF mechanisms
        MECHANISM_NAMES.put(CDMF_KEY_GEN, "CDMF_KEY_GEN");
        MECHANISM_NAMES.put(CDMF_ECB, "CDMF_ECB");
        MECHANISM_NAMES.put(CDMF_CBC, "CDMF_CBC");
        MECHANISM_NAMES.put(CDMF_MAC, "CDMF_MAC");
        MECHANISM_NAMES.put(CDMF_MAC_GENERAL, "CDMF_MAC_GENERAL");
        MECHANISM_NAMES.put(CDMF_CBC_PAD, "CDMF_CBC_PAD");

        // CAST mechanisms
        MECHANISM_NAMES.put(CAST_KEY_GEN, "CAST_KEY_GEN");
        MECHANISM_NAMES.put(CAST_ECB, "CAST_ECB");
        MECHANISM_NAMES.put(CAST_CBC, "CAST_CBC");
        MECHANISM_NAMES.put(CAST_MAC, "CAST_MAC");
        MECHANISM_NAMES.put(CAST_MAC_GENERAL, "CAST_MAC_GENERAL");
        MECHANISM_NAMES.put(CAST_CBC_PAD, "CAST_CBC_PAD");
        MECHANISM_NAMES.put(CAST3_KEY_GEN, "CAST3_KEY_GEN");
        MECHANISM_NAMES.put(CAST3_ECB, "CAST3_ECB");
        MECHANISM_NAMES.put(CAST3_CBC, "CAST3_CBC");
        MECHANISM_NAMES.put(CAST3_MAC, "CAST3_MAC");
        MECHANISM_NAMES.put(CAST3_MAC_GENERAL, "CAST3_MAC_GENERAL");
        MECHANISM_NAMES.put(CAST3_CBC_PAD, "CAST3_CBC_PAD");
        MECHANISM_NAMES.put(CAST128_KEY_GEN, "CAST128_KEY_GEN");
        MECHANISM_NAMES.put(CAST128_ECB, "CAST128_ECB");
        MECHANISM_NAMES.put(CAST128_CBC, "CAST128_CBC");
        MECHANISM_NAMES.put(CAST128_MAC, "CAST128_MAC");
        MECHANISM_NAMES.put(CAST128_MAC_GENERAL, "CAST128_MAC_GENERAL");
        MECHANISM_NAMES.put(CAST128_CBC_PAD, "CAST128_CBC_PAD");

        // IDEA mechanisms
        MECHANISM_NAMES.put(IDEA_KEY_GEN, "IDEA_KEY_GEN");
        MECHANISM_NAMES.put(IDEA_ECB, "IDEA_ECB");
        MECHANISM_NAMES.put(IDEA_CBC, "IDEA_CBC");
        MECHANISM_NAMES.put(IDEA_MAC, "IDEA_MAC");
        MECHANISM_NAMES.put(IDEA_MAC_GENERAL, "IDEA_MAC_GENERAL");
        MECHANISM_NAMES.put(IDEA_CBC_PAD, "IDEA_CBC_PAD");

        // Blowfish/Twofish mechanisms
        MECHANISM_NAMES.put(BLOWFISH_KEY_GEN, "BLOWFISH_KEY_GEN");
        MECHANISM_NAMES.put(BLOWFISH_CBC, "BLOWFISH_CBC");
        MECHANISM_NAMES.put(BLOWFISH_CBC_PAD, "BLOWFISH_CBC_PAD");
        MECHANISM_NAMES.put(TWOFISH_KEY_GEN, "TWOFISH_KEY_GEN");
        MECHANISM_NAMES.put(TWOFISH_CBC, "TWOFISH_CBC");
        MECHANISM_NAMES.put(TWOFISH_CBC_PAD, "TWOFISH_CBC_PAD");

        // Camellia mechanisms
        MECHANISM_NAMES.put(CAMELLIA_KEY_GEN, "CAMELLIA_KEY_GEN");
        MECHANISM_NAMES.put(CAMELLIA_ECB, "CAMELLIA_ECB");
        MECHANISM_NAMES.put(CAMELLIA_CBC, "CAMELLIA_CBC");
        MECHANISM_NAMES.put(CAMELLIA_MAC, "CAMELLIA_MAC");
        MECHANISM_NAMES.put(CAMELLIA_MAC_GENERAL, "CAMELLIA_MAC_GENERAL");
        MECHANISM_NAMES.put(CAMELLIA_CBC_PAD, "CAMELLIA_CBC_PAD");
        MECHANISM_NAMES.put(CAMELLIA_ECB_ENCRYPT_DATA, "CAMELLIA_ECB_ENCRYPT_DATA");
        MECHANISM_NAMES.put(CAMELLIA_CBC_ENCRYPT_DATA, "CAMELLIA_CBC_ENCRYPT_DATA");
        MECHANISM_NAMES.put(CAMELLIA_CTR, "CAMELLIA_CTR");

        // ARIA mechanisms
        MECHANISM_NAMES.put(ARIA_KEY_GEN, "ARIA_KEY_GEN");
        MECHANISM_NAMES.put(ARIA_ECB, "ARIA_ECB");
        MECHANISM_NAMES.put(ARIA_CBC, "ARIA_CBC");
        MECHANISM_NAMES.put(ARIA_MAC, "ARIA_MAC");
        MECHANISM_NAMES.put(ARIA_MAC_GENERAL, "ARIA_MAC_GENERAL");
        MECHANISM_NAMES.put(ARIA_CBC_PAD, "ARIA_CBC_PAD");
        MECHANISM_NAMES.put(ARIA_ECB_ENCRYPT_DATA, "ARIA_ECB_ENCRYPT_DATA");
        MECHANISM_NAMES.put(ARIA_CBC_ENCRYPT_DATA, "ARIA_CBC_ENCRYPT_DATA");

        // SEED mechanisms
        MECHANISM_NAMES.put(SEED_KEY_GEN, "SEED_KEY_GEN");
        MECHANISM_NAMES.put(SEED_ECB, "SEED_ECB");
        MECHANISM_NAMES.put(SEED_CBC, "SEED_CBC");
        MECHANISM_NAMES.put(SEED_MAC, "SEED_MAC");
        MECHANISM_NAMES.put(SEED_MAC_GENERAL, "SEED_MAC_GENERAL");
        MECHANISM_NAMES.put(SEED_CBC_PAD, "SEED_CBC_PAD");
        MECHANISM_NAMES.put(SEED_ECB_ENCRYPT_DATA, "SEED_ECB_ENCRYPT_DATA");
        MECHANISM_NAMES.put(SEED_CBC_ENCRYPT_DATA, "SEED_CBC_ENCRYPT_DATA");

        // GOST mechanisms
        MECHANISM_NAMES.put(GOSTR3410_KEY_PAIR_GEN, "GOSTR3410_KEY_PAIR_GEN");
        MECHANISM_NAMES.put(GOSTR3410, "GOSTR3410");
        MECHANISM_NAMES.put(GOSTR3410_WITH_GOSTR3411, "GOSTR3410_WITH_GOSTR3411");
        MECHANISM_NAMES.put(GOSTR3410_KEY_WRAP, "GOSTR3410_KEY_WRAP");
        MECHANISM_NAMES.put(GOSTR3410_DERIVE, "GOSTR3410_DERIVE");
        MECHANISM_NAMES.put(GOSTR3411, "GOSTR3411");
        MECHANISM_NAMES.put(GOSTR3411_HMAC, "GOSTR3411_HMAC");
        MECHANISM_NAMES.put(GOST28147_KEY_GEN, "GOST28147_KEY_GEN");
        MECHANISM_NAMES.put(GOST28147_ECB, "GOST28147_ECB");
        MECHANISM_NAMES.put(GOST28147, "GOST28147");
        MECHANISM_NAMES.put(GOST28147_MAC, "GOST28147_MAC");
        MECHANISM_NAMES.put(GOST28147_KEY_WRAP, "GOST28147_KEY_WRAP");

        // Generic/key management mechanisms
        MECHANISM_NAMES.put(GENERIC_SECRET_KEY_GEN, "GENERIC_SECRET_KEY_GEN");
        MECHANISM_NAMES.put(CONCATENATE_BASE_AND_KEY, "CONCATENATE_BASE_AND_KEY");
        MECHANISM_NAMES.put(CONCATENATE_BASE_AND_DATA, "CONCATENATE_BASE_AND_DATA");
        MECHANISM_NAMES.put(CONCATENATE_DATA_AND_BASE, "CONCATENATE_DATA_AND_BASE");
        MECHANISM_NAMES.put(XOR_BASE_AND_DATA, "XOR_BASE_AND_DATA");
        MECHANISM_NAMES.put(EXTRACT_KEY_FROM_KEY, "EXTRACT_KEY_FROM_KEY");
        MECHANISM_NAMES.put(KEY_WRAP_LYNKS, "KEY_WRAP_LYNKS");
        MECHANISM_NAMES.put(KEY_WRAP_SET_OAEP, "KEY_WRAP_SET_OAEP");

        // SSL/TLS mechanisms
        MECHANISM_NAMES.put(SSL3_PRE_MASTER_KEY_GEN, "SSL3_PRE_MASTER_KEY_GEN");
        MECHANISM_NAMES.put(SSL3_MASTER_KEY_DERIVE, "SSL3_MASTER_KEY_DERIVE");
        MECHANISM_NAMES.put(SSL3_KEY_AND_MAC_DERIVE, "SSL3_KEY_AND_MAC_DERIVE");
        MECHANISM_NAMES.put(SSL3_MASTER_KEY_DERIVE_DH, "SSL3_MASTER_KEY_DERIVE_DH");
        MECHANISM_NAMES.put(SSL3_MD5_MAC, "SSL3_MD5_MAC");
        MECHANISM_NAMES.put(SSL3_SHA1_MAC, "SSL3_SHA1_MAC");
        MECHANISM_NAMES.put(TLS_PRE_MASTER_KEY_GEN, "TLS_PRE_MASTER_KEY_GEN");
        MECHANISM_NAMES.put(TLS_MASTER_KEY_DERIVE, "TLS_MASTER_KEY_DERIVE");
        MECHANISM_NAMES.put(TLS_KEY_AND_MAC_DERIVE, "TLS_KEY_AND_MAC_DERIVE");
        MECHANISM_NAMES.put(TLS_MASTER_KEY_DERIVE_DH, "TLS_MASTER_KEY_DERIVE_DH");
        MECHANISM_NAMES.put(TLS_PRF, "TLS_PRF");
        MECHANISM_NAMES.put(TLS10_MAC_SERVER, "TLS10_MAC_SERVER");
        MECHANISM_NAMES.put(TLS10_MAC_CLIENT, "TLS10_MAC_CLIENT");
        MECHANISM_NAMES.put(TLS12_MAC, "TLS12_MAC");
        MECHANISM_NAMES.put(TLS12_KDF, "TLS12_KDF");
        MECHANISM_NAMES.put(TLS12_MASTER_KEY_DERIVE, "TLS12_MASTER_KEY_DERIVE");
        MECHANISM_NAMES.put(TLS12_KEY_AND_MAC_DERIVE, "TLS12_KEY_AND_MAC_DERIVE");
        MECHANISM_NAMES.put(TLS12_MASTER_KEY_DERIVE_DH, "TLS12_MASTER_KEY_DERIVE_DH");
        MECHANISM_NAMES.put(TLS12_KEY_SAFE_DERIVE, "TLS12_KEY_SAFE_DERIVE");
        MECHANISM_NAMES.put(TLS_MAC, "TLS_MAC");
        MECHANISM_NAMES.put(TLS_KDF, "TLS_KDF");

        // WTLS mechanisms
        MECHANISM_NAMES.put(WTLS_PRE_MASTER_KEY_GEN, "WTLS_PRE_MASTER_KEY_GEN");
        MECHANISM_NAMES.put(WTLS_MASTER_KEY_DERIVE, "WTLS_MASTER_KEY_DERIVE");
        MECHANISM_NAMES.put(WTLS_MASTER_KEY_DERIVE_DH_ECC, "WTLS_MASTER_KEY_DERIVE_DH_ECC");
        MECHANISM_NAMES.put(WTLS_PRF, "WTLS_PRF");
        MECHANISM_NAMES.put(WTLS_SERVER_KEY_AND_MAC_DERIVE, "WTLS_SERVER_KEY_AND_MAC_DERIVE");
        MECHANISM_NAMES.put(WTLS_CLIENT_KEY_AND_MAC_DERIVE, "WTLS_CLIENT_KEY_AND_MAC_DERIVE");

        // PBE mechanisms
        MECHANISM_NAMES.put(PBE_MD2_DES_CBC, "PBE_MD2_DES_CBC");
        MECHANISM_NAMES.put(PBE_MD5_DES_CBC, "PBE_MD5_DES_CBC");
        MECHANISM_NAMES.put(PBE_MD5_CAST_CBC, "PBE_MD5_CAST_CBC");
        MECHANISM_NAMES.put(PBE_MD5_CAST3_CBC, "PBE_MD5_CAST3_CBC");
        MECHANISM_NAMES.put(PBE_MD5_CAST128_CBC, "PBE_MD5_CAST128_CBC");
        MECHANISM_NAMES.put(PBE_SHA1_CAST128_CBC, "PBE_SHA1_CAST128_CBC");
        MECHANISM_NAMES.put(PBE_SHA1_RC4_128, "PBE_SHA1_RC4_128");
        MECHANISM_NAMES.put(PBE_SHA1_RC4_40, "PBE_SHA1_RC4_40");
        MECHANISM_NAMES.put(PBE_SHA1_DES3_EDE_CBC, "PBE_SHA1_DES3_EDE_CBC");
        MECHANISM_NAMES.put(PBE_SHA1_DES2_EDE_CBC, "PBE_SHA1_DES2_EDE_CBC");
        MECHANISM_NAMES.put(PBE_SHA1_RC2_128_CBC, "PBE_SHA1_RC2_128_CBC");
        MECHANISM_NAMES.put(PBE_SHA1_RC2_40_CBC, "PBE_SHA1_RC2_40_CBC");
        MECHANISM_NAMES.put(PKCS5_PBKD2, "PKCS5_PBKD2");
        MECHANISM_NAMES.put(PBA_SHA1_WITH_SHA1_HMAC, "PBA_SHA1_WITH_SHA1_HMAC");

        // Other mechanisms
        MECHANISM_NAMES.put(SECURID_KEY_GEN, "SECURID_KEY_GEN");
        MECHANISM_NAMES.put(SECURID, "SECURID");
        MECHANISM_NAMES.put(HOTP_KEY_GEN, "HOTP_KEY_GEN");
        MECHANISM_NAMES.put(HOTP, "HOTP");
        MECHANISM_NAMES.put(ACTI, "ACTI");
        MECHANISM_NAMES.put(ACTI_KEY_GEN, "ACTI_KEY_GEN");
        MECHANISM_NAMES.put(CMS_SIG, "CMS_SIG");
        MECHANISM_NAMES.put(KIP_DERIVE, "KIP_DERIVE");
        MECHANISM_NAMES.put(KIP_WRAP, "KIP_WRAP");
        MECHANISM_NAMES.put(KIP_MAC, "KIP_MAC");

        // Skipjack mechanisms
        MECHANISM_NAMES.put(SKIPJACK_KEY_GEN, "SKIPJACK_KEY_GEN");
        MECHANISM_NAMES.put(SKIPJACK_ECB64, "SKIPJACK_ECB64");
        MECHANISM_NAMES.put(SKIPJACK_CBC64, "SKIPJACK_CBC64");
        MECHANISM_NAMES.put(SKIPJACK_OFB64, "SKIPJACK_OFB64");
        MECHANISM_NAMES.put(SKIPJACK_CFB64, "SKIPJACK_CFB64");
        MECHANISM_NAMES.put(SKIPJACK_CFB32, "SKIPJACK_CFB32");
        MECHANISM_NAMES.put(SKIPJACK_CFB16, "SKIPJACK_CFB16");
        MECHANISM_NAMES.put(SKIPJACK_CFB8, "SKIPJACK_CFB8");
        MECHANISM_NAMES.put(SKIPJACK_WRAP, "SKIPJACK_WRAP");
        MECHANISM_NAMES.put(SKIPJACK_PRIVATE_WRAP, "SKIPJACK_PRIVATE_WRAP");
        MECHANISM_NAMES.put(SKIPJACK_RELAYX, "SKIPJACK_RELAYX");

        // KEA mechanisms
        MECHANISM_NAMES.put(KEA_KEY_PAIR_GEN, "KEA_KEY_PAIR_GEN");
        MECHANISM_NAMES.put(KEA_KEY_DERIVE, "KEA_KEY_DERIVE");
        MECHANISM_NAMES.put(KEA_DERIVE, "KEA_DERIVE");
        MECHANISM_NAMES.put(FORTEZZA_TIMESTAMP, "FORTEZZA_TIMESTAMP");

        // Baton mechanisms
        MECHANISM_NAMES.put(BATON_KEY_GEN, "BATON_KEY_GEN");
        MECHANISM_NAMES.put(BATON_ECB128, "BATON_ECB128");
        MECHANISM_NAMES.put(BATON_ECB96, "BATON_ECB96");
        MECHANISM_NAMES.put(BATON_CBC128, "BATON_CBC128");
        MECHANISM_NAMES.put(BATON_COUNTER, "BATON_COUNTER");
        MECHANISM_NAMES.put(BATON_SHUFFLE, "BATON_SHUFFLE");
        MECHANISM_NAMES.put(BATON_WRAP, "BATON_WRAP");

        // Juniper mechanisms
        MECHANISM_NAMES.put(JUNIPER_KEY_GEN, "JUNIPER_KEY_GEN");
        MECHANISM_NAMES.put(JUNIPER_ECB128, "JUNIPER_ECB128");
        MECHANISM_NAMES.put(JUNIPER_CBC128, "JUNIPER_CBC128");
        MECHANISM_NAMES.put(JUNIPER_COUNTER, "JUNIPER_COUNTER");
        MECHANISM_NAMES.put(JUNIPER_SHUFFLE, "JUNIPER_SHUFFLE");
        MECHANISM_NAMES.put(JUNIPER_WRAP, "JUNIPER_WRAP");
        MECHANISM_NAMES.put(FASTHASH, "FASTHASH");

        // Vendor defined
        MECHANISM_NAMES.put(VENDOR_DEFINED, "VENDOR_DEFINED");
    }

    /**
     * Returns the name of a mechanism type, or a hex string if unknown.
     */
    public static String getName(long mechanismType) {
        String name = MECHANISM_NAMES.get(mechanismType);
        if (name != null) {
            return name;
        }
        if ((mechanismType & VENDOR_DEFINED) != 0) {
            return String.format("VENDOR_DEFINED(0x%08X)", mechanismType);
        }
        return String.format("UNKNOWN(0x%08X)", mechanismType);
    }
}
