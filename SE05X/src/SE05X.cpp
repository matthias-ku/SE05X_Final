/*
  SE05X.cpp
  Copyright (c) 2023 Arduino SA.  All right reserved.

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include "SE05X.h"

/**
 * 26 bytes see ecc_der_header_nist256
 */
#define SE05X_EC_KEY_DER_HEADER_LENGTH   26

/**
 * 1 byte for key compression format 0x02 / 0x03 / 0x04
 */
#define SE05X_EC_KEY_FORMAT_LENGTH        1

/**
 * 64 bytes X Y uncompressed points
 */
#define SE05X_EC_KEY_RAW_LENGTH          64

/**
 * 91 bytes total key length in DER format
 */
#define SE05X_EC_KEY_DER_LENGTH          SE05X_EC_KEY_DER_HEADER_LENGTH + \
                                         SE05X_EC_KEY_FORMAT_LENGTH     + \
                                         SE05X_EC_KEY_RAW_LENGTH

/**
 * 32 bytes R values + 32 bytes S values
 */
#define SE05X_EC_SIGNATURE_RAW_LENGTH    64

/**
 * 8 bytes worst case 30 45 02 21 00 | 32 bytes R values | 02 21 00 | 32 bytes S values
 */
#define SE05X_EC_SIGNATURE_MAX_HEADER_LENGTH 8

/**
 * 6 bytes best case 30 45 02 21 | 32 bytes R values | 02 21 | 32 bytes S values
 */
#define SE05X_EC_SIGNATURE_MIN_HEADER_LENGTH 6

/**
 * 72 bytes worst case
 */
#define SE05X_EC_SIGNATURE_MAX_DER_LENGTH    SE05X_EC_SIGNATURE_MAX_HEADER_LENGTH + \
                                             SE05X_EC_SIGNATURE_RAW_LENGTH

/**
 * 70 bytes best case
 */
#define SE05X_EC_SIGNATURE_MIN_DER_LENGTH    SE05X_EC_SIGNATURE_MIN_HEADER_LENGTH + \
                                             SE05X_EC_SIGNATURE_RAW_LENGTH

#define SE05X_SHA256_LENGTH              32

#define SE05X_OEAP_SHA_256_OVERHEAD ((SE05X_SHA256_LENGTH * 2) + 2)

#define SE05X_MIN_SIGNATURE_LENGTH       128    //Min length for RSA Signatures

#define SE05X_MAX_SIGNATURE_LENGTH       512    //Max length for RSA Signatures

#define SE05X_TEMP_OBJECT                9999

#define SE05X_MAX_CHUNK_SIZE             100

#define SE05X_RSA_PUBLIC_EXPONENT_SIZE   4

static const byte ecc_der_header_nist256[SE05X_EC_KEY_DER_HEADER_LENGTH] =
{
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00
};

/* RSA Header */
const uint8_t grsa512PubHeader[] = {0x30, 0x5C, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
    0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x4B, 0x00, 0x30, 0x48, 0x02};

const uint8_t grsa1kPubHeader[] = {0x30, 0x81, 0x9F, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
   0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0x8D, 0x00, 0x30, 0x81, 0x89, 0x02};

const uint8_t grsa1152PubHeader[] = {0x30, 0x81, 0xAF, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
     0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0x9D, 0x00, 0x30, 0x81, 0x99, 0x02};

const uint8_t grsa2kPubHeader[]
= {0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01,
0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0F, 0x00, 0x30, 0x82, 0x01, 0x0A, 0x02};

const uint8_t grsa3kPubHeader[]
= {0x30, 0x82, 0x01, 0xA2, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01,
0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x8F, 0x00, 0x30, 0x82, 0x01, 0x8A, 0x02};

const uint8_t grsa4kPubHeader[]
= {0x30, 0x82, 0x02, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01,
0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0F, 0x00, 0x30, 0x82, 0x02, 0x0A, 0x02};

/* RSA Helper Macros to make code little more readable */
#define SE05X_RSA_NO_p /* Skip */ NULL, 0
#define SE05X_RSA_NO_q /* Skip */ NULL, 0
#define SE05X_RSA_NO_dp /* Skip */ NULL, 0
#define SE05X_RSA_NO_dq /* Skip */ NULL, 0
#define SE05X_RSA_NO_qInv /* Skip */ NULL, 0
#define SE05X_RSA_NO_pubExp /* Skip */ NULL, 0
#define SE05X_RSA_NO_priv /* Skip */ NULL, 0
#define SE05X_RSA_NO_pubMod /* Skip */ NULL, 0


SE05XClass::SE05XClass() { }
SE05XClass::~SE05XClass() { }

int SE05XClass::begin()
{
    smStatus_t status;

    pinMode(SE050_ENA_PIN, OUTPUT);
    digitalWrite(SE050_ENA_PIN, HIGH);

    _se05x_session = {0,0,{0,},0,0,0,0,0,0,0,0};

    status = Se05x_API_SessionOpen(&_se05x_session);
    if(status != SM_OK) {
        return 0;
    }

    return 1;
}

void SE05XClass::end()
{
    Se05x_API_SessionClose(&_se05x_session);
}

int SE05XClass::serialNumber(byte sn[])
{
    return serialNumber(sn, SE05X_SN_LENGTH);
}

int SE05XClass::serialNumber(byte sn[], size_t length)
{
    size_t uidLen = length;
    const int kSE05x_AppletResID_UNIQUE_ID = 0x7FFF0206;
    smStatus_t status;

    status = Se05x_API_ReadObject(&_se05x_session, kSE05x_AppletResID_UNIQUE_ID, 0, length, sn, &uidLen);
    if (status != SM_OK || length != uidLen) {
        SMLOG_E("Error in Se05x_API_ReadObject \n");
        return 0;
    }
    return 1;
}

String SE05XClass::serialNumber()
{
    String result = (char*)NULL;
    byte UID[SE05X_SN_LENGTH];

    serialNumber(UID, sizeof(UID));

    result.reserve(SE05X_SN_LENGTH * 2);

    for (size_t i = 0; i < SE05X_SN_LENGTH; i++) {
        byte b = UID[i];

        if (b < 16) {
          result += "0";
        }
        result += String(b, HEX);
    }

    result.toUpperCase();

    return result;
}

long SE05XClass::random(long max)
{
    return random(0, max);
}

long SE05XClass::random(long min, long max)
{
    if (min >= max)
    {
        return min;
    }

    long diff = max - min;

    long r;
    random((byte*)&r, sizeof(r));

    if (r < 0) {
        r = -r;
    }

    r = (r % diff);

    return (r + min);
}

int SE05XClass::random(byte data[], size_t length)
{
    smStatus_t status;
    uint16_t   offset = 0;
    uint16_t   left = length;

    while (left > 0) {
        uint16_t chunk     = (left > SE05X_MAX_CHUNK_SIZE) ? SE05X_MAX_CHUNK_SIZE : left;
        size_t max_buffer  = chunk;

        status = Se05x_API_GetRandom(&_se05x_session, chunk, (data + offset), &max_buffer);
        if (status != SM_OK) {
            SMLOG_E("Error in Se05x_API_GetRandom \n");
            return 0;
        }
        left   = left - chunk;
        offset = offset + chunk;
    }

    return 1;
}

int SE05XClass::generatePrivateKey(int keyID, byte keyBuf[], size_t keyBufMaxLen, size_t* keyLen)
{
    if (keyBufMaxLen < SE05X_EC_KEY_DER_LENGTH ) {
        SMLOG_E("Error in generatePrivateKey buffer length \n");
        return 0;
    }

    *keyLen = SE05X_EC_KEY_DER_LENGTH;

    /* Copy header byte from 0 to 25 */
    memcpy(keyBuf, ecc_der_header_nist256, sizeof(ecc_der_header_nist256));

    /* Add format byte */
    keyBuf[SE05X_EC_KEY_DER_HEADER_LENGTH] = 0x04;

    /* Add X Y points */
    return generatePrivateKey(keyID, &keyBuf[SE05X_EC_KEY_DER_HEADER_LENGTH + SE05X_EC_KEY_FORMAT_LENGTH]);
}

int SE05XClass::generatePrivateKey(int keyID, byte publicKey[])
{
    smStatus_t      status;
    SE05x_ECCurve_t curveID = kSE05x_ECCurve_NIST_P256;
    SE05x_Result_t  result;

    /* SE050 fills a buffer with 1 byte key format + 64 bytes of X Y points */
    uint8_t         keyBuf[SE05X_EC_KEY_FORMAT_LENGTH + SE05X_EC_KEY_RAW_LENGTH];
    size_t          keylen = sizeof(keyBuf);

    status = Se05x_API_CheckObjectExists(&_se05x_session, keyID, &result);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_CheckObjectExists \n");
        return 0;
    }

    if (result == kSE05x_Result_SUCCESS) {
        SMLOG_I("Object already exists \n");
        curveID = kSE05x_ECCurve_NA;
    }

    SMLOG_I("Generate ec key \n");
    status = Se05x_API_WriteECKey(&_se05x_session, NULL, 0, keyID, curveID, NULL, 0, NULL, 0, kSE05x_INS_NA, kSE05x_KeyPart_Pair);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_WriteECKey \n");
        return 0;
    }

    status = Se05x_API_ReadObject(&_se05x_session, keyID, 0, 0, keyBuf, &keylen);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_ReadObject \n");
        return 0;
    }

    /* To User: copy only 64 bytes of X Y points */
    memcpy(publicKey, &keyBuf[SE05X_EC_KEY_FORMAT_LENGTH], SE05X_EC_KEY_RAW_LENGTH);


    return 1;
}

int SE05XClass::generatePrivateRSAKey(int keyID, byte keyBuf[], size_t keyBufMaxLen, size_t* keyLen, uint16_t keyBitLength)
{
    int index = 0;
    uint8_t modulus[520] = {0};
    uint8_t exponent[4]  = {0};
    size_t  modlen       = sizeof(modulus);
    size_t  pubExplen    = sizeof(exponent);

    ENSURE_OR_RETURN_ON_ERROR(keyBuf != NULL, 0);

    /* Copy header */
    if (keyBitLength == kSE05x_RSABitLength_512)
    {
        ENSURE_OR_RETURN_ON_ERROR((sizeof(grsa512PubHeader) + (keyBitLength / 8) + SE05X_RSA_PUBLIC_EXPONENT_SIZE + 3U + 3U) <= keyBufMaxLen, 0);
        memcpy(keyBuf, grsa512PubHeader, sizeof(grsa512PubHeader));
        index += sizeof(grsa512PubHeader);
        *keyLen = sizeof(grsa512PubHeader) + (keyBitLength / 8) + SE05X_RSA_PUBLIC_EXPONENT_SIZE + 3U + 3U;
    }
    else if (keyBitLength == kSE05x_RSABitLength_1024)
    {
        ENSURE_OR_RETURN_ON_ERROR((sizeof(grsa1kPubHeader) + (keyBitLength / 8) + SE05X_RSA_PUBLIC_EXPONENT_SIZE + 3U + 3U) <= keyBufMaxLen, 0);
        memcpy(keyBuf, grsa1kPubHeader, sizeof(grsa1kPubHeader));
        index += sizeof(grsa1kPubHeader);
        *keyLen = sizeof(grsa1kPubHeader) + (keyBitLength / 8) + SE05X_RSA_PUBLIC_EXPONENT_SIZE + 3U + 3U;
    }
    else if (keyBitLength == kSE05x_RSABitLength_1152)
    {
        ENSURE_OR_RETURN_ON_ERROR((sizeof(grsa1152PubHeader) + (keyBitLength / 8) + SE05X_RSA_PUBLIC_EXPONENT_SIZE + 3U + 3U) <= keyBufMaxLen, 0);
        memcpy(keyBuf, grsa1152PubHeader, sizeof(grsa1152PubHeader));
        index += sizeof(grsa1152PubHeader);
        *keyLen = sizeof(grsa1152PubHeader) + (keyBitLength / 8) + SE05X_RSA_PUBLIC_EXPONENT_SIZE + 3U + 3U;
    }
    else if (keyBitLength == kSE05x_RSABitLength_2048)
    {
        ENSURE_OR_RETURN_ON_ERROR((sizeof(grsa2kPubHeader) + (keyBitLength / 8) + SE05X_RSA_PUBLIC_EXPONENT_SIZE + 3U + 3U) <= keyBufMaxLen, 0);
        memcpy(keyBuf, grsa2kPubHeader, sizeof(grsa2kPubHeader));
        index += sizeof(grsa2kPubHeader);
        *keyLen = sizeof(grsa2kPubHeader) + (keyBitLength / 8) + SE05X_RSA_PUBLIC_EXPONENT_SIZE + 3U + 3U;
    }
    else if (keyBitLength == kSE05x_RSABitLength_3072)
    {
        ENSURE_OR_RETURN_ON_ERROR((sizeof(grsa3kPubHeader) + (keyBitLength / 8) + SE05X_RSA_PUBLIC_EXPONENT_SIZE + 3U + 3U) <= keyBufMaxLen, 0);
        memcpy(keyBuf, grsa3kPubHeader, sizeof(grsa3kPubHeader));
        index += sizeof(grsa3kPubHeader);
        *keyLen = sizeof(grsa3kPubHeader) + (keyBitLength / 8) + SE05X_RSA_PUBLIC_EXPONENT_SIZE + 3U + 3U;
    }
    else if (keyBitLength == kSE05x_RSABitLength_4096)
    {
        ENSURE_OR_RETURN_ON_ERROR((sizeof(grsa4kPubHeader) + (keyBitLength / 8) + SE05X_RSA_PUBLIC_EXPONENT_SIZE + 3U + 3U) <= keyBufMaxLen, 0);
        memcpy(keyBuf, grsa4kPubHeader, sizeof(grsa4kPubHeader));
        index += sizeof(grsa4kPubHeader);
        *keyLen = sizeof(grsa4kPubHeader) + (keyBitLength / 8) + SE05X_RSA_PUBLIC_EXPONENT_SIZE + 3U + 3U;
    }
    else
    {
        SMLOG_E("Error in generatePrivateRSAKey keyBitLength \n");
        return 0;
    }

    /* Add mod and exponent */
    if (generatePrivateRSAKey(keyID, modulus, &modlen, exponent, &pubExplen, keyBitLength) != 1)
    {
        return 0;
    }

    size_t intModLEn = modlen + 1;  // RSA Key has null byte before moduls start

    // add length for modulus
    if(intModLEn < 0x7f)
    {
        ENSURE_OR_RETURN_ON_ERROR(index + 1 <= *keyLen, 0);
        keyBuf[index++] = (uint8_t) intModLEn;
    }
    else if (intModLEn < 0xFF)
    {
        ENSURE_OR_RETURN_ON_ERROR(index + 2 <= *keyLen, 0);
        keyBuf[index++] = 0x81;
        keyBuf[index++] = (uint8_t) intModLEn;
    }
    else
    {
        ENSURE_OR_RETURN_ON_ERROR(index + 3 <= *keyLen, 0);
        ENSURE_OR_RETURN_ON_ERROR((intModLEn >> 8) <= UINT8_MAX, 0);
        keyBuf[index++] = 0x82;
        keyBuf[index++] = (uint8_t) (intModLEn >> 8);
        keyBuf[index++] = (uint8_t) intModLEn & 0xFF;
    }

    //add null byte and modulus
    ENSURE_OR_RETURN_ON_ERROR(index + 1 + modlen <= *keyLen, 0);
    keyBuf[index++] = 0x00;  // Null byte
    memcpy(keyBuf + index, modulus, modlen);
    index += modlen;

    /*Copy the public Exponent*/
    ENSURE_OR_RETURN_ON_ERROR(index + 1 + 1 + pubExplen <= *keyLen, 0);
    keyBuf[index++] = 0x02;                     // tag
    keyBuf[index++] = (uint8_t) pubExplen;      // length
    memcpy(keyBuf + index, exponent, pubExplen);  // value
    index += pubExplen;
    *keyLen = index;

    return 1;
}

int SE05XClass::generatePrivateRSAKey(
    int keyID, byte modulus[], size_t* modLen, byte exponent[], size_t* expLen, uint16_t keyBitLength)
{
    smStatus_t     status;
    SE05x_Result_t result;

    ENSURE_OR_RETURN_ON_ERROR(((keyBitLength / 8)) <= *modLen, 0);
    ENSURE_OR_RETURN_ON_ERROR((SE05X_RSA_PUBLIC_EXPONENT_SIZE) <= *modLen, 0);

    status = Se05x_API_CheckObjectExists(&_se05x_session, keyID, &result);
    if (status != SM_OK)
    {
        SMLOG_E("Error in Se05x_API_CheckObjectExists \n");
        return 0;
    }

    if (result == kSE05x_Result_SUCCESS)
    {
        SMLOG_I("Object already exists \n");
    }else{
        keyBitLength = (status == 1) ? 0 : keyBitLength;

        ENSURE_OR_RETURN_ON_ERROR(keyBitLength <= UINT16_MAX, 0);

        SMLOG_I("Generate RSA key \n");
        status = Se05x_API_WriteRSAKey(&_se05x_session, NULL, keyID, (uint16_t) keyBitLength, SE05X_RSA_NO_p,
                                       SE05X_RSA_NO_q, SE05X_RSA_NO_dp, SE05X_RSA_NO_dq, SE05X_RSA_NO_qInv,
                                       SE05X_RSA_NO_pubExp, SE05X_RSA_NO_priv, SE05X_RSA_NO_pubMod, kSE05x_INS_NA,
                                       kSE05x_KeyPart_Pair, kSE05x_RSAKeyFormat_RAW);
        if (status != SM_OK)
        {
            SMLOG_E("Error in Se05x_API_WriteRSAKey \n");
            return 0;
        }
    }

    status = Se05x_API_ReadRSA(&_se05x_session, keyID, 0, 0, kSE05x_RSAPubKeyComp_MOD, modulus, modLen);
    if (status != SM_OK)
    {
        SMLOG_E("Error in Se05x_API_ReadRSA kSE05x_RSAPubKeyComp_MOD \n");
        return 0;
    }

    status = Se05x_API_ReadRSA(&_se05x_session, keyID, 0, 0, kSE05x_RSAPubKeyComp_PUB_EXP, exponent, expLen);
    if (status != SM_OK)
    {
        SMLOG_E("Error in Se05x_API_ReadRSA kSE05x_RSAPubKeyComp_PUB_EXP \n");
        return 0;
    }
    return 1;
}

int SE05XClass::writeRSAKey(int                  keyID,
                            SE05x_RSABitLength_t keyBitLength,
                            const uint8_t*       p,
                            size_t               pLen,
                            const uint8_t*       q,
                            size_t               qLen,
                            const uint8_t*       dp,
                            size_t               dpLen,
                            const uint8_t*       dq,
                            size_t               dqLen,
                            const uint8_t*       qInv,
                            size_t               qInvLen,
                            const uint8_t*       pubExp,
                            size_t               pubExpLen,
                            const uint8_t*       priv,
                            size_t               privLen,
                            const uint8_t*       pubMod,
                            size_t               pubModLen,
                            SE05x_RSAKeyFormat_t rsa_format,
                            bool                 transient,
                            SE05x_KeyPart_t      keyType,
                            pSe05xPolicy_t       policy)
{
    smStatus_t     status;
    SE05x_Result_t result;
    SE05x_INS_t    transient_type = kSE05x_INS_NA;  // Se05x_API_WriteRSAKey always sets INS_WRITE, kSE05x_INS_TRANSIENT is a additional flag

    ENSURE_OR_RETURN_ON_ERROR(
        (keyType == kSE05x_KeyPart_Public || keyType == kSE05x_KeyPart_Private || keyType == kSE05x_KeyPart_Pair), 0);
    ENSURE_OR_RETURN_ON_ERROR((keyBitLength == kSE05x_RSABitLength_512 || keyBitLength == kSE05x_RSABitLength_1024
                               || keyBitLength == kSE05x_RSABitLength_1152 || keyBitLength == kSE05x_RSABitLength_2048
                               || keyBitLength == kSE05x_RSABitLength_3072 || keyBitLength == kSE05x_RSABitLength_4096),
                              0);


    status = Se05x_API_CheckObjectExists(&_se05x_session, keyID, &result);
    if (status != SM_OK)
    {
        SMLOG_E("Error in Se05x_API_CheckObjectExists \n");
        return 0;
    }

    if (result == kSE05x_Result_SUCCESS)
    {
        SMLOG_I("Object already exists \n");
        return 0;
    }

    if (transient)
    {
        transient_type = kSE05x_INS_TRANSIENT;
    }
    else
    {
        transient_type = kSE05x_INS_NA;
    }

    SMLOG_I("Generate RSA key \n");
    // every key part must be written seperately
    if (rsa_format == kSE05x_RSAKeyFormat_RAW)
    {
        // check if all reqired values exist
        ENSURE_OR_RETURN_ON_ERROR(pubMod != NULL, 0);
        ENSURE_OR_RETURN_ON_ERROR(pubModLen != 0, 0);

        if (keyType == kSE05x_KeyPart_Public || keyType == kSE05x_KeyPart_Pair)
        {
            ENSURE_OR_RETURN_ON_ERROR(pubExp != NULL, 0);
            ENSURE_OR_RETURN_ON_ERROR(pubExpLen != 0, 0);
        }

        if (keyType == kSE05x_KeyPart_Private || keyType == kSE05x_KeyPart_Pair)
        {
            ENSURE_OR_RETURN_ON_ERROR(priv != NULL, 0);
            ENSURE_OR_RETURN_ON_ERROR(privLen != 0, 0);
        }

        // mod is used in private, public and keypair
        status = Se05x_API_WriteRSAKey(&_se05x_session, policy, keyID, (uint16_t) keyBitLength, SE05X_RSA_NO_p,
                                       SE05X_RSA_NO_q, SE05X_RSA_NO_dp, SE05X_RSA_NO_dq, SE05X_RSA_NO_qInv,
                                       SE05X_RSA_NO_pubExp, SE05X_RSA_NO_priv, pubMod, pubModLen, transient_type,
                                       keyType, rsa_format);
        if (status != SM_OK)
        {
            SMLOG_E("Error in Se05x_API_WriteRSAKey \n");
            return 0;
        }

        // write public exponent
        if (keyType == kSE05x_KeyPart_Public || keyType == kSE05x_KeyPart_Pair)
        {
            // public exponent
            status = Se05x_API_WriteRSAKey(&_se05x_session, policy, keyID, (uint16_t) 0, SE05X_RSA_NO_p,
                                           SE05X_RSA_NO_q, SE05X_RSA_NO_dp, SE05X_RSA_NO_dq, SE05X_RSA_NO_qInv, pubExp,
                                           pubExpLen, SE05X_RSA_NO_priv, SE05X_RSA_NO_pubMod, transient_type,
                                           kSE05x_KeyPart_NA, rsa_format);
            if (status != SM_OK)
            {
                SMLOG_E("Error in Se05x_API_WriteRSAKey \n");
                return 0;
            }
        }

        if (keyType == kSE05x_KeyPart_Private || keyType == kSE05x_KeyPart_Pair)
        {
            // private exponent
            status = Se05x_API_WriteRSAKey(&_se05x_session, policy, keyID, (uint16_t) 0, SE05X_RSA_NO_p,
                                           SE05X_RSA_NO_q, SE05X_RSA_NO_dp, SE05X_RSA_NO_dq, SE05X_RSA_NO_qInv,
                                           SE05X_RSA_NO_pubExp, priv, privLen, SE05X_RSA_NO_pubMod, transient_type,
                                           kSE05x_KeyPart_NA, rsa_format);
            if (status != SM_OK)
            {
                SMLOG_E("Error in Se05x_API_WriteRSAKey \n");
                return 0;
            }
        }
    }
    else if (rsa_format == kSE05x_RSAKeyFormat_CRT)
    {
        if (keyType == kSE05x_KeyPart_Public)
        {
            // mod is used in public and keypair
            ENSURE_OR_RETURN_ON_ERROR(pubMod != NULL, 0);
            ENSURE_OR_RETURN_ON_ERROR(pubModLen != 0, 0);

            ENSURE_OR_RETURN_ON_ERROR(pubExp != NULL, 0);
            ENSURE_OR_RETURN_ON_ERROR(pubExpLen != 0, 0);

            status = Se05x_API_WriteRSAKey(&_se05x_session, policy, keyID, (uint16_t) keyBitLength, SE05X_RSA_NO_p,
                                           SE05X_RSA_NO_q, SE05X_RSA_NO_dp, SE05X_RSA_NO_dq, SE05X_RSA_NO_qInv,
                                           SE05X_RSA_NO_pubExp, SE05X_RSA_NO_priv, pubMod, pubModLen, transient_type,
                                           keyType, rsa_format);
            if (status != SM_OK)
            {
                SMLOG_E("Error in Se05x_API_WriteRSAKey \n");
                return 0;
            }

            // public exponent
            status = Se05x_API_WriteRSAKey(&_se05x_session, policy, keyID, (uint16_t) keyBitLength, SE05X_RSA_NO_p,
                                           SE05X_RSA_NO_q, SE05X_RSA_NO_dp, SE05X_RSA_NO_dq, SE05X_RSA_NO_qInv, pubExp,
                                           pubExpLen, SE05X_RSA_NO_priv, SE05X_RSA_NO_pubMod, transient_type,
                                           kSE05x_KeyPart_NA, rsa_format);
            if (status != SM_OK)
            {
                SMLOG_E("Error in Se05x_API_WriteRSAKey \n");
                return 0;
            }
        }
        else if (keyType == kSE05x_KeyPart_Private)
        {
            ENSURE_OR_RETURN_ON_ERROR(p != NULL, 0);
            ENSURE_OR_RETURN_ON_ERROR(pLen != 0, 0);

            ENSURE_OR_RETURN_ON_ERROR(q != NULL, 0);
            ENSURE_OR_RETURN_ON_ERROR(qLen != 0, 0);

            ENSURE_OR_RETURN_ON_ERROR(dp != NULL, 0);
            ENSURE_OR_RETURN_ON_ERROR(dpLen != 0, 0);

            ENSURE_OR_RETURN_ON_ERROR(dq != NULL, 0);
            ENSURE_OR_RETURN_ON_ERROR(dqLen != 0, 0);

            ENSURE_OR_RETURN_ON_ERROR(qInv != NULL, 0);
            ENSURE_OR_RETURN_ON_ERROR(qInvLen != 0, 0);

            status = Se05x_API_WriteRSAKey(&_se05x_session, policy, keyID, (uint16_t) keyBitLength, p, pLen,
                                           SE05X_RSA_NO_q, SE05X_RSA_NO_dp, SE05X_RSA_NO_dq, SE05X_RSA_NO_qInv,
                                           SE05X_RSA_NO_pubExp, SE05X_RSA_NO_priv, SE05X_RSA_NO_pubMod, transient_type,
                                           keyType, rsa_format);
            if (status != SM_OK)
            {
                SMLOG_E("Error in Se05x_API_WriteRSAKey \n");
                return 0;
            }

            status = Se05x_API_WriteRSAKey(&_se05x_session, policy, keyID, (uint16_t) keyBitLength, SE05X_RSA_NO_p, q,
                                           qLen, SE05X_RSA_NO_dp, SE05X_RSA_NO_dq, SE05X_RSA_NO_qInv,
                                           SE05X_RSA_NO_pubExp, SE05X_RSA_NO_priv, SE05X_RSA_NO_pubMod, transient_type,
                                           kSE05x_KeyPart_NA, rsa_format);
            if (status != SM_OK)
            {
                SMLOG_E("Error in Se05x_API_WriteRSAKey \n");
                return 0;
            }

            status = Se05x_API_WriteRSAKey(&_se05x_session, policy, keyID, (uint16_t) keyBitLength, SE05X_RSA_NO_p,
                                           SE05X_RSA_NO_q, dp, dpLen, SE05X_RSA_NO_dq, SE05X_RSA_NO_qInv,
                                           SE05X_RSA_NO_pubExp, SE05X_RSA_NO_priv, SE05X_RSA_NO_pubMod, transient_type,
                                           kSE05x_KeyPart_NA, rsa_format);
            if (status != SM_OK)
            {
                SMLOG_E("Error in Se05x_API_WriteRSAKey \n");
                return 0;
            }

            status = Se05x_API_WriteRSAKey(&_se05x_session, policy, keyID, (uint16_t) keyBitLength, SE05X_RSA_NO_p,
                                           SE05X_RSA_NO_q, SE05X_RSA_NO_dp, dq, dqLen, SE05X_RSA_NO_qInv,
                                           SE05X_RSA_NO_pubExp, SE05X_RSA_NO_priv, SE05X_RSA_NO_pubMod, transient_type,
                                           kSE05x_KeyPart_NA, rsa_format);
            if (status != SM_OK)
            {
                SMLOG_E("Error in Se05x_API_WriteRSAKey \n");
                return 0;
            }

            status = Se05x_API_WriteRSAKey(&_se05x_session, policy, keyID, (uint16_t) keyBitLength, SE05X_RSA_NO_p,
                                           SE05X_RSA_NO_q, SE05X_RSA_NO_dp, SE05X_RSA_NO_dq, qInv, qInvLen,
                                           SE05X_RSA_NO_pubExp, SE05X_RSA_NO_priv, SE05X_RSA_NO_pubMod, transient_type,
                                           kSE05x_KeyPart_NA, rsa_format);
            if (status != SM_OK)
            {
                SMLOG_E("Error in Se05x_API_WriteRSAKey \n");
                return 0;
            }
        }
        else if (keyType == kSE05x_KeyPart_Pair)
        {
            ENSURE_OR_RETURN_ON_ERROR(p != NULL, 0);
            ENSURE_OR_RETURN_ON_ERROR(pLen != 0, 0);

            ENSURE_OR_RETURN_ON_ERROR(q != NULL, 0);
            ENSURE_OR_RETURN_ON_ERROR(qLen != 0, 0);

            ENSURE_OR_RETURN_ON_ERROR(dp != NULL, 0);
            ENSURE_OR_RETURN_ON_ERROR(dpLen != 0, 0);

            ENSURE_OR_RETURN_ON_ERROR(dq != NULL, 0);
            ENSURE_OR_RETURN_ON_ERROR(dqLen != 0, 0);

            ENSURE_OR_RETURN_ON_ERROR(qInv != NULL, 0);
            ENSURE_OR_RETURN_ON_ERROR(qInvLen != 0, 0);

            ENSURE_OR_RETURN_ON_ERROR(pubMod != NULL, 0);
            ENSURE_OR_RETURN_ON_ERROR(pubModLen != 0, 0);

            ENSURE_OR_RETURN_ON_ERROR(pubExp != NULL, 0);
            ENSURE_OR_RETURN_ON_ERROR(pubExpLen != 0, 0);

            status = Se05x_API_WriteRSAKey(&_se05x_session, policy, keyID, (uint16_t) keyBitLength, p, pLen,
                                           SE05X_RSA_NO_q, SE05X_RSA_NO_dp, SE05X_RSA_NO_dq, SE05X_RSA_NO_qInv,
                                           SE05X_RSA_NO_pubExp, SE05X_RSA_NO_priv, SE05X_RSA_NO_pubMod, transient_type,
                                           keyType, rsa_format);
            if (status != SM_OK)
            {
                SMLOG_E("Error in Se05x_API_WriteRSAKey \n");
                return 0;
            }

            status = Se05x_API_WriteRSAKey(&_se05x_session, policy, keyID, (uint16_t) keyBitLength, SE05X_RSA_NO_p, q,
                                           qLen, SE05X_RSA_NO_dp, SE05X_RSA_NO_dq, SE05X_RSA_NO_qInv,
                                           SE05X_RSA_NO_pubExp, SE05X_RSA_NO_priv, SE05X_RSA_NO_pubMod, transient_type,
                                           kSE05x_KeyPart_NA, rsa_format);
            if (status != SM_OK)
            {
                SMLOG_E("Error in Se05x_API_WriteRSAKey \n");
                return 0;
            }

            status = Se05x_API_WriteRSAKey(&_se05x_session, policy, keyID, (uint16_t) keyBitLength, SE05X_RSA_NO_p,
                                           SE05X_RSA_NO_q, dp, dpLen, SE05X_RSA_NO_dq, SE05X_RSA_NO_qInv,
                                           SE05X_RSA_NO_pubExp, SE05X_RSA_NO_priv, SE05X_RSA_NO_pubMod, transient_type,
                                           kSE05x_KeyPart_NA, rsa_format);
            if (status != SM_OK)
            {
                SMLOG_E("Error in Se05x_API_WriteRSAKey \n");
                return 0;
            }

            status = Se05x_API_WriteRSAKey(&_se05x_session, policy, keyID, (uint16_t) keyBitLength, SE05X_RSA_NO_p,
                                           SE05X_RSA_NO_q, SE05X_RSA_NO_dp, dq, dqLen, SE05X_RSA_NO_qInv,
                                           SE05X_RSA_NO_pubExp, SE05X_RSA_NO_priv, SE05X_RSA_NO_pubMod, transient_type,
                                           kSE05x_KeyPart_NA, rsa_format);
            if (status != SM_OK)
            {
                SMLOG_E("Error in Se05x_API_WriteRSAKey \n");
                return 0;
            }

            status = Se05x_API_WriteRSAKey(&_se05x_session, policy, keyID, (uint16_t) keyBitLength, SE05X_RSA_NO_p,
                                           SE05X_RSA_NO_q, SE05X_RSA_NO_dp, SE05X_RSA_NO_dq, qInv, qInvLen,
                                           SE05X_RSA_NO_pubExp, SE05X_RSA_NO_priv, SE05X_RSA_NO_pubMod, transient_type,
                                           kSE05x_KeyPart_NA, rsa_format);
            if (status != SM_OK)
            {
                SMLOG_E("Error in Se05x_API_WriteRSAKey \n");
                return 0;
            }

            // mod is used in public and keypair
            status = Se05x_API_WriteRSAKey(&_se05x_session, policy, keyID, (uint16_t) keyBitLength, SE05X_RSA_NO_p,
                                           SE05X_RSA_NO_q, SE05X_RSA_NO_dp, SE05X_RSA_NO_dq, SE05X_RSA_NO_qInv,
                                           SE05X_RSA_NO_pubExp, SE05X_RSA_NO_priv, pubMod, pubModLen, transient_type,
                                           kSE05x_KeyPart_NA, rsa_format);
            if (status != SM_OK)
            {
                SMLOG_E("Error in Se05x_API_WriteRSAKey \n");
                return 0;
            }

            status = Se05x_API_WriteRSAKey(&_se05x_session, policy, keyID, (uint16_t) keyBitLength, SE05X_RSA_NO_p,
                                           SE05X_RSA_NO_q, SE05X_RSA_NO_dp, SE05X_RSA_NO_dq, SE05X_RSA_NO_qInv, pubExp,
                                           pubExpLen, SE05X_RSA_NO_priv, SE05X_RSA_NO_pubMod, transient_type,
                                           kSE05x_KeyPart_NA, rsa_format);
            if (status != SM_OK)
            {
                SMLOG_E("Error in Se05x_API_WriteRSAKey \n");
                return 0;
            }
        }
    }

    uint8_t modulus[520] = {0};
    uint8_t exponent[4]  = {0};
    size_t  modlen       = sizeof(modulus);
    size_t  pubExplen    = sizeof(exponent);
    status = Se05x_API_ReadRSA(&_se05x_session, keyID, 0, 0, kSE05x_RSAPubKeyComp_MOD, modulus, &modlen);
    if (status != SM_OK)
    {
        SMLOG_E("Error in Se05x_API_ReadRSA kSE05x_RSAPubKeyComp_MOD \n");
        return 0;
    }

    status = Se05x_API_ReadRSA(&_se05x_session, keyID, 0, 0, kSE05x_RSAPubKeyComp_PUB_EXP, exponent, &pubExplen);
    if (status != SM_OK)
    {
        SMLOG_E("Error in Se05x_API_ReadRSA kSE05x_RSAPubKeyComp_PUB_EXP \n");
        return 0;
    }
    if (memcmp(modulus, pubMod, pubModLen) != 0 && memcmp(exponent, pubExp, pubExplen) != 0)
        return 0;
        
    return 1;
}

int SE05XClass::generatePublicKey(int keyID, byte keyBuf[], size_t keyBufMaxLen, size_t* keyLen)
{
    if (keyBufMaxLen < SE05X_EC_KEY_DER_LENGTH ) {
        SMLOG_E("Error in generatePublicKey buffer too short \n");
        return 0;
    }

    *keyLen = SE05X_EC_KEY_DER_LENGTH;

    /* Copy header byte from 0 to 25 */
    memcpy(keyBuf, ecc_der_header_nist256, SE05X_EC_KEY_DER_HEADER_LENGTH);

    /* Add format byte */
    keyBuf[SE05X_EC_KEY_DER_HEADER_LENGTH] = 0x04;

    /* Add X Y points */
    return generatePublicKey(keyID, &keyBuf[SE05X_EC_KEY_DER_HEADER_LENGTH + SE05X_EC_KEY_FORMAT_LENGTH]);
}

int SE05XClass::generatePublicKey(int keyID, byte publicKey[])
{
    smStatus_t      status;
    SE05x_Result_t  result;

    /* SE050 fills a buffer with 1 byte key format + 64 bytes of X Y points */
    uint8_t         keyBuf[SE05X_EC_KEY_FORMAT_LENGTH + SE05X_EC_KEY_RAW_LENGTH];
    size_t          keyLen = sizeof(keyBuf);

    status = Se05x_API_CheckObjectExists(&_se05x_session, keyID, &result);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_CheckObjectExists \n");
        return 0;
    }

    status = Se05x_API_ReadObject(&_se05x_session, keyID, 0, 0, keyBuf, &keyLen);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_ReadObject \n");
        return 0;
    }

    /* To User: copy only 64 bytes of X Y points */
    memcpy(publicKey, &keyBuf[SE05X_EC_KEY_FORMAT_LENGTH], SE05X_EC_KEY_RAW_LENGTH);

    return 1;
}

int SE05XClass::importPublicKey(int keyID, const byte publicKey[], size_t keyLen)
{
    smStatus_t      status;
    SE05x_ECCurve_t curveID = kSE05x_ECCurve_NIST_P256;
    SE05x_Result_t  result;

    /* SE050 fills a buffer with 1 byte key format + 64 bytes of X Y points */
    uint8_t         keyBuf[SE05X_EC_KEY_FORMAT_LENGTH + SE05X_EC_KEY_RAW_LENGTH];

    if (keyLen < SE05X_EC_KEY_DER_LENGTH) {
        SMLOG_E("Error in importPublicKey invalid key length \n");
        return 0;
    }

    if (memcmp(ecc_der_header_nist256, publicKey, SE05X_EC_KEY_DER_HEADER_LENGTH)) {
        SMLOG_E("Error in importPublicKey invalid key format \n");
        return 0;
    }

    status = Se05x_API_CheckObjectExists(&_se05x_session, keyID, &result);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_CheckObjectExists \n");
        return 0;
    }

    if (result == kSE05x_Result_SUCCESS) {
        SMLOG_I("Object already exists \n");
        curveID = kSE05x_ECCurve_NA;
    }

    /* To SE050: copy 65 bytes Key format + 64 bytes of X Y points */
    memcpy(keyBuf, &publicKey[SE05X_EC_KEY_DER_HEADER_LENGTH], sizeof(keyBuf));

    SMLOG_I("Import ec key \n");
    status = Se05x_API_WriteECKey(&_se05x_session, NULL, 0, keyID, curveID, NULL, 0, keyBuf, sizeof(keyBuf), kSE05x_INS_WRITE, kSE05x_KeyPart_Public);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_WriteECKey \n");
        return 0;
    }

    return 1;
}

int SE05XClass::beginSHA256()
{
    smStatus_t      status;
    SE05x_CryptoModeSubType_t subtype;

    subtype.digest = kSE05x_DigestMode_SHA256;

    status = Se05x_API_CreateCryptoObject(&_se05x_session, kSE05x_CryptoObject_DIGEST_SHA256, kSE05x_CryptoContext_DIGEST, subtype);
    if (status != SM_OK) {
        SMLOG_W("Se05x_API_CreateCryptoObject failed. Object already exists? \n");
    }

    status = Se05x_API_DigestInit(&_se05x_session, kSE05x_CryptoObject_DIGEST_SHA256);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_DigestInit \n");
        return 0;
    }

    return 1;
}

int SE05XClass::updateSHA256(const byte in[], size_t inLen)
{
    smStatus_t      status;

    status = Se05x_API_DigestUpdate(&_se05x_session, kSE05x_CryptoObject_DIGEST_SHA256, in, inLen);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_DigestUpdate \n");
        return 0;
    }

    return 1;
}

int SE05XClass::endSHA256(byte out[], size_t* outLen)
{
    smStatus_t      status;

    if (*outLen < SE05X_SHA256_LENGTH) {
        SMLOG_E("Error in endSHA256 \n");
        *outLen = 0;
        return 0;
    }

    status = Se05x_API_DigestFinal(&_se05x_session, kSE05x_CryptoObject_DIGEST_SHA256, NULL, 0, out, outLen);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_DigestFinal \n");
        *outLen = 0;
        return 0;
    }

    status = Se05x_API_DeleteCryptoObject(&_se05x_session, kSE05x_CryptoObject_DIGEST_SHA256);

    return 1;
}

int SE05XClass::SHA256(const byte in[], size_t inLen, byte out[], size_t outMaxLen, size_t* outLen)
{
    smStatus_t      status;

    *outLen = outMaxLen;
    status = Se05x_API_DigestOneShot(&_se05x_session,  kSE05x_DigestMode_SHA256, in, inLen, out, outLen);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_DigestOneShot \n");
        *outLen = 0;
        return 0;
    }

    return 1;
}

int SE05XClass::Sign(int keyID, const byte hash[], size_t hashLen, byte sig[], size_t sigMaxLen, size_t* sigLen)
{
    smStatus_t      status;
    SE05x_Result_t  result;

    if (hashLen != SE05X_SHA256_LENGTH) {
        SMLOG_E("Error in Sign invalid input SHA256 buffer \n");
        *sigLen = 0;
        return 0;
    }

    if (sigMaxLen < SE05X_EC_SIGNATURE_MAX_DER_LENGTH) {
        SMLOG_E("Error in Sign signature buffer too small \n");
        *sigLen = 0;
        return 0;
    }

    status = Se05x_API_CheckObjectExists(&_se05x_session, keyID, &result);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_CheckObjectExists \n");
        *sigLen = 0;
        return 0;
    }

    if (result != kSE05x_Result_SUCCESS) {
        SMLOG_E("Object not exists \n");
        *sigLen = 0;
        return 0;
    }

    *sigLen = sigMaxLen;
    status = Se05x_API_ECDSASign(&_se05x_session, keyID, kSE05x_ECSignatureAlgo_SHA_256, hash, hashLen, sig, sigLen);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_ECDSASign \n");
        return 0;
    }
    return 1;
}

int SE05XClass::ecSign(int slot, const byte message[], byte signature[])
{
    byte signatureDer[SE05X_EC_SIGNATURE_MAX_DER_LENGTH];
    size_t signatureDerLen;
    size_t size = SE05X_EC_SIGNATURE_RAW_LENGTH;

    if (!Sign(slot, message, SE05X_SHA256_LENGTH, signatureDer, sizeof(signatureDer), &signatureDerLen)) {
        SMLOG_E("Error in ecSign \n");
        return 0;
    }

    /* Get r s values from DER buffer */
    if (!getECSignatureRsValuesFromDER(signatureDer, signatureDerLen, signature, &size)) {
        SMLOG_E("Error in ecSign cannot get R S values\n");
        return 0;
    }

    return 1;
}

int SE05XClass::Verify(int keyID, const byte hash[], size_t hashLen, const byte sig[], size_t sigLen)
{
    smStatus_t      status;
    SE05x_Result_t  result;

    if (hashLen != SE05X_SHA256_LENGTH) {
        SMLOG_E("Error in Verify invalid input SHA256 buffer \n");
        return 0;
    }

    if ((sigLen < SE05X_EC_SIGNATURE_MIN_DER_LENGTH) || (sigLen > SE05X_EC_SIGNATURE_MAX_DER_LENGTH)) {
        SMLOG_E("Error in Verify invalid signature \n");
        return 0;
    }

    status = Se05x_API_CheckObjectExists(&_se05x_session, keyID, &result);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_CheckObjectExists \n");
        return 0;
    }

    if (result != kSE05x_Result_SUCCESS) {
        SMLOG_E("Object not exists \n");
        return 0;
    }

    status = Se05x_API_ECDSAVerify(&_se05x_session, keyID, kSE05x_ECSignatureAlgo_SHA_256, hash, hashLen, sig, sigLen, &result);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_ECDSASign \n");
        return 0;
    }

    if (result != kSE05x_Result_SUCCESS) {
        SMLOG_E("Verify failure \n");
        return 0;
    }
    return 1;
}

int SE05XClass::ecdsaVerify(const byte message[], const byte signature[], const byte pubkey[])
{
    byte pubKeyDER[SE05X_EC_KEY_DER_LENGTH];
    size_t pubKeyDERLen = sizeof(pubKeyDER);
    byte signatureDER[SE05X_EC_SIGNATURE_MAX_DER_LENGTH];
    size_t signatureDERLen = sizeof(signatureDER);

    if (!setECKeyXyVauesInDER(pubkey, SE05X_EC_KEY_RAW_LENGTH, pubKeyDER, &pubKeyDERLen)) {
        SMLOG_E("ecdsaVerify failure creating key DER\n");
        return 0;
    }

    if (!importPublicKey(SE05X_TEMP_OBJECT, pubKeyDER, pubKeyDERLen)) {
        SMLOG_E("ecdsaVerify failure importing temp key\n");
        return 0;
    }

    if (!setECSignatureRsValuesInDER(signature, SE05X_EC_SIGNATURE_RAW_LENGTH, signatureDER, &signatureDERLen)) {
        SMLOG_E("ecdsaVerify failure creating signature DER\n");
        return 0;
    }

    if (!Verify(SE05X_TEMP_OBJECT, message, SE05X_SHA256_LENGTH, signatureDER, SE05X_EC_SIGNATURE_MAX_DER_LENGTH)) {
        SMLOG_E("ecdsaVerify failure\n");
        return 0;
    }

    if (!deleteBinaryObject(SE05X_TEMP_OBJECT)) {
        SMLOG_E("ecdsaVerify failure deleting temporary object\n");
        return 0;
    }

    return 1;
}

int SE05XClass::readBinaryObject(int objectId, byte data[], size_t dataMaxLen, size_t* length)
{
    smStatus_t      status;
    SE05x_Result_t  result;
    uint16_t        offset = 0;
    uint16_t        size;

    status = Se05x_API_CheckObjectExists(&_se05x_session, objectId, &result);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_CheckObjectExists \n");
        *length = 0;
        return 0;
    }

    if (result != kSE05x_Result_SUCCESS) {
        SMLOG_E("Object not exists \n");
        *length = 0;
        return 0;
    }

    status = Se05x_API_ReadSize(&_se05x_session, objectId, &size);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_CheckObjectExists \n");
        *length = 0;
        return 0;
    }

    if (dataMaxLen < size) {
        SMLOG_E("Error in readBinaryObject buffer too small \n");
        *length = 0;
        return 0;
    }

    uint16_t left = size;
    while (left > 0) {
        uint16_t chunk     = (left > SE05X_MAX_CHUNK_SIZE) ? SE05X_MAX_CHUNK_SIZE : left;
        size_t max_buffer  = chunk;

        status = Se05x_API_ReadObject(&_se05x_session, objectId, offset, chunk, (data + offset), &max_buffer);
        if (status != SM_OK) {
            SMLOG_E("Error in Se05x_API_ReadObject \n");
            *length = 0;
            return 0;
        }
        left   = left - chunk;
        offset = offset + chunk;
    }

    *length = size;
    return 1;
}

int SE05XClass::readSlot(int slot, byte data[], int length)
{
    size_t  size;
    return readBinaryObject(slot, data, length, &size);
}

int SE05XClass::AES_ECB_encrypt(int objectId, const byte data[], size_t data_length, byte output[], size_t *output_len)
{
    smStatus_t status;
    status = Se05x_API_CipherOneShot(&_se05x_session, objectId, kSE05x_CipherMode_AES_ECB_NOPAD, data, data_length, 0, 0, output, output_len, kSE05x_Cipher_Oper_OneShot_Encrypt);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_CipherOneShot \n");
        return 0;
    }
    return 1;
}

int SE05XClass::AES_ECB_decrypt(int objectId, const byte data[], size_t data_length, byte output[], size_t *output_len)
{
    smStatus_t status;
    status = Se05x_API_CipherOneShot(&_se05x_session, objectId, kSE05x_CipherMode_AES_ECB_NOPAD, data, data_length, 0, 0, output, output_len, kSE05x_Cipher_Oper_OneShot_Decrypt);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_CipherOneShot \n");
        return 0;
    }
    return 1;
}

int SE05XClass::writeAESKey(int objectId, const byte data[], size_t length)
{
    smStatus_t      status;
    SE05x_Result_t  result;

    status = Se05x_API_CheckObjectExists(&_se05x_session, objectId, &result);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_CheckObjectExists \n");
        return 0;
    }

    if (result == kSE05x_Result_SUCCESS) {
        SMLOG_E("Object exists \n");
        return 0;
    }

    status = Se05x_API_WriteSymmKey(&_se05x_session, NULL, 3, objectId, SE05x_KeyID_KEK_NONE, data, length, kSE05x_INS_NA, kSE05x_SymmKeyType_AES);

    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_WriteSymmKey \n");
        return 0;
    }
    return 1;
}

int SE05XClass::writeHMACKey(int objectId, const byte data[], size_t length)
{
    smStatus_t      status;
    SE05x_Result_t  result;

    status = Se05x_API_CheckObjectExists(&_se05x_session, objectId, &result);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_CheckObjectExists \n");
        return 0;
    }

    if (result == kSE05x_Result_SUCCESS) {
        SMLOG_E("Object exists \n");
    }

    status = Se05x_API_WriteSymmKey(&_se05x_session, NULL, 0, objectId, SE05x_KeyID_KEK_NONE, data, length, kSE05x_INS_NA, kSE05x_SymmKeyType_HMAC);

    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_WriteSymmKey \n");
        return 0;
    }
    return 1;
}

int SE05XClass::HMAC_Generate(int objectId, uint8_t mac_operation, const byte data[], size_t data_length, byte output[], size_t *output_len)
{
    smStatus_t status;
    status = Se05x_API_MACOneShot_G(&_se05x_session, objectId, mac_operation, data, data_length, output, output_len);

    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_CipherOneShot \n");
        return status;
    }
    return 1;
}

int SE05XClass::writeBinaryObject(int objectId, const byte data[], size_t length)
{
    smStatus_t      status;
    SE05x_Result_t  result;
    uint8_t         exists = 0;
    uint16_t        offset = 0;
    uint16_t        size;

    status = Se05x_API_CheckObjectExists(&_se05x_session, objectId, &result);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_CheckObjectExists \n");
        return 0;
    }

    if (result == kSE05x_Result_SUCCESS) {
        SMLOG_E("Object exists \n");
        exists = 1;
    }

    uint16_t left = length;

    while (left > 0) {
        uint16_t chunk = (left > SE05X_MAX_CHUNK_SIZE) ? SE05X_MAX_CHUNK_SIZE : left;
        left           = left - chunk;
        size           = exists ? 0 : length;

        status = Se05x_API_WriteBinary(&_se05x_session, NULL, objectId, offset, size, (data + offset), chunk);
        if (status != SM_OK) {
            SMLOG_E("Error in Se05x_API_WriteBinary \n");
            return 0;
        }
        exists = 1;
        offset = offset + chunk;
    }

    return 1;
}

int SE05XClass::writeSlot(int slot, const byte data[], int length)
{
    if (existsBinaryObject(slot)) {
        if (!deleteBinaryObject(slot)) {
            return 0;
        }
    }
    return writeBinaryObject(slot, data, length);
}

int SE05XClass::existsBinaryObject(int objectId)
{
    smStatus_t      status;
    SE05x_Result_t  result;

    status = Se05x_API_CheckObjectExists(&_se05x_session, objectId, &result);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_CheckObjectExists \n");
        return 0;
    }

    if (result != kSE05x_Result_SUCCESS) {
        SMLOG_E("Object not exists \n");
        return 0;
    }

    return 1;
}

int SE05XClass::deleteBinaryObject(int objectId)
{
    smStatus_t      status;

    status = Se05x_API_DeleteSecureObject(&_se05x_session, objectId);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_DeleteSecureObject \n");
        return 0;
    }

    return 1;
}

int SE05XClass::deleteAllObjects(void)
{
    smStatus_t      status;

    status = Se05x_API_DeleteAll_Iterative(&_se05x_session);
    if (status != SM_OK) {
        SMLOG_E("Error in Se05x_API_CheckObjectExists \n");
        return 0;
    }

    return 1;
}

int SE05XClass::getECKeyXyValuesFromDER(byte* derKey, size_t derLen, byte* rawKey, size_t* rawLen)
{
    if(*rawLen < SE05X_EC_KEY_RAW_LENGTH) {
        SMLOG_E("Error in getECKeyXyValuesFromDER \n");
        *rawLen = 0;
        return 0;
    }

    /* XY values are stored in the last 64 bytes of DER buffer */
    *rawLen = SE05X_EC_KEY_RAW_LENGTH;
    memcpy(rawKey, &derKey[derLen - SE05X_EC_KEY_RAW_LENGTH], SE05X_EC_KEY_RAW_LENGTH);

    return 1;
}

int SE05XClass::setECKeyXyVauesInDER(const byte* rawKey, size_t rawLen, byte* derKey, size_t* derLen)
{
    if(rawLen != SE05X_EC_KEY_RAW_LENGTH) {
        SMLOG_E("Error in setECKeyXyVauesInDER invalid raw key\n");
        *derLen = 0;
        return 0;
    }

    if(*derLen < SE05X_EC_KEY_DER_LENGTH) {
        SMLOG_E("Error in setECKeyXyVauesInDER buffer too small\n");
        *derLen = 0;
        return 0;
    }

    /* Copy header byte from 0 to 25 */
    memcpy(&derKey[0], &ecc_der_header_nist256[0], SE05X_EC_KEY_DER_HEADER_LENGTH);
    /* Add format byte */
    derKey[SE05X_EC_KEY_DER_HEADER_LENGTH] = 0x04;
    /* Add X Y points */
    memcpy(&derKey[SE05X_EC_KEY_DER_HEADER_LENGTH + SE05X_EC_KEY_FORMAT_LENGTH], &rawKey[0], SE05X_EC_KEY_RAW_LENGTH);

    *derLen = SE05X_EC_KEY_DER_LENGTH;
    return 1;
}

int SE05XClass::getECSignatureRsValuesFromDER(byte* derSignature, size_t derLen, byte* rawSignature, size_t *rawLen)
{
    byte rLen;
    byte sLen;

    if ((derLen < SE05X_EC_SIGNATURE_MIN_DER_LENGTH) || (derLen > SE05X_EC_SIGNATURE_MAX_DER_LENGTH)) {
        SMLOG_E("Error in getECSignatureRsValuesFromDER invalid signature\n");
        *rawLen = 0;
        return 0;
    }

    if (*rawLen < SE05X_EC_SIGNATURE_RAW_LENGTH) {
        SMLOG_E("Error in getECSignatureRsValuesFromDER buffer too small\n");
        *rawLen = 0;
        return 0;
    }

    rLen = derSignature[3];
    sLen = derSignature[3 + rLen + 2];

    byte * out = rawSignature;

    if(rLen == (SE05X_EC_SIGNATURE_RAW_LENGTH / 2))
    {
        memcpy(out, &derSignature[4], (SE05X_EC_SIGNATURE_RAW_LENGTH / 2));
    }
    else if ((rLen == ((SE05X_EC_SIGNATURE_RAW_LENGTH / 2) + 1)) && (derSignature[4] == 0))
    {
        memcpy(out, &derSignature[5], (SE05X_EC_SIGNATURE_RAW_LENGTH / 2));
    }

    out += (SE05X_EC_SIGNATURE_RAW_LENGTH / 2);

    if(sLen == (SE05X_EC_SIGNATURE_RAW_LENGTH / 2))
    {
        memcpy(out, &derSignature[3 + rLen + 3], (SE05X_EC_SIGNATURE_RAW_LENGTH / 2));
    }
    else if ((sLen == ((SE05X_EC_SIGNATURE_RAW_LENGTH / 2) + 1)) && (derSignature[3 + rLen + 3] == 0))
    {
        memcpy(out, &derSignature[3 + rLen + 4], (SE05X_EC_SIGNATURE_RAW_LENGTH / 2));
    }

    return 1;
}

int SE05XClass::setECSignatureRsValuesInDER(const byte* rawSignature, size_t rawLen, byte* signature, size_t* derLen)
{
    /**
     * Always consider worst case with padding
     *
     * | 0x30 0x46 0x02 0x21 0x00 | R values 32 bytes | 0x02 0x21 0x00 | S values 32 bytes |
     *
     */
    const int halfSigLen = SE05X_EC_SIGNATURE_RAW_LENGTH / 2;

    if (rawLen != SE05X_EC_SIGNATURE_RAW_LENGTH) {
        SMLOG_E("Error in setECSignatureRsValuesInDER invalid signature\n");
        *derLen = 0;
        return 0;
    }

    if (*derLen < SE05X_EC_SIGNATURE_MAX_DER_LENGTH) {
        SMLOG_E("Error in setECSignatureRsValuesInDER buffer too small\n");
        *derLen = 0;
        return 0;
    }

    signature[0] = 0x30;
    signature[1] = 0x46; /* 3 + 32 + 3 + 32*/
    signature[2] = 0x02;
    signature[3] = 0x21;
    signature[4] = 0x00;
    memcpy(&signature[5], &rawSignature[0], halfSigLen);
    signature[37] = 0x02;
    signature[38] = 0x21;
    signature[39] = 0x00;
    memcpy(&signature[40], &rawSignature[halfSigLen], halfSigLen);

    return 1;
}

SE05XClass SE05X;
