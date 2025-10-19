/*
  SE05X.h
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

#ifndef _SE05X_H_
#define _SE05X_H_

#include <Arduino.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "lib/apdu/se05x_APDU_apis.h"
#include "lib/platform/arduino/sm_port.h"

#ifdef __cplusplus
}
#endif

#define SE05X_SN_LENGTH 18

class SE05XClass
{
public:
    SE05XClass();
    virtual ~SE05XClass();

    int begin();
    void end();

    int serialNumber(byte sn[]);
    int serialNumber(byte sn[], size_t length);
#if defined (ARDUINO)
    String serialNumber();
#endif

    long random(long max);
    long random(long min, long max);
    int random(byte data[], size_t length);

    /** generatePrivateKey
     *
     * Create a new ECCurve_NIST_P256 keypair. Only public key will be available
     * inside KeyBuf with DER format.
     *
     * | P256 Header (26 bytes)| 0x04 (1 byte)| Public key X Y values (64 bytes) |
     *
     * @param[in] KeyID Se050 objectID where to store the private key
     * @param[out] keyBuf Buffer containing the public key in DER format
     * @param[in] keyBufMaxLen Buffer size in bytes
     * @param[in,out] keyLen Public key size in bytes
     *
     * @return 0 on Failure 1 on Success
     */
    int generatePrivateKey(int keyID, byte keyBuf[], size_t keyBufMaxLen, size_t* keyLen);
    
    /** generatePrivateRSAKey
     *
     * Create a new RSA keypair. Only public key will be available
     * inside KeyBuf with DER format.
     *
     * |Header (23-29 bytes)| lenght of mod, up to 3 bytes | 0x00 (1 byte) | Public key mod value (up to 512 bytes) |
     * length public exp 2 bytes | 0x00 (1 byte) | public exp 3-4 bytes |
     *
     * @param[in] KeyID Se050 objectID where to store the private key
     * @param[out] keyBuf Buffer containing the public key in DER format
     * @param[in] keyBufMaxLen Buffer size in bytes
     * @param[in,out] keyLen Public key size in bytes
     *
     * @return 0 on Failure 1 on Success
     */
    int generatePrivateRSAKey(int keyID, byte keyBuf[], size_t keyBufMaxLen, size_t* keyLen, uint16_t keyBitLength);

    /** generatePublicKey
     *
     * Reads ECCurve_NIST_P256 public key from KeyID. Public key will be available
     * inside KeyBuf with DER format.
     *
     * | P256 Header (26 bytes)| 0x04 (1 byte)| Public key X Y values (64 bytes) |
     *
     * @param[in] KeyID Se050 objectID where is stored the public key or keypair
     * @param[out] keyBuf Buffer containing the public key in DER format
     * @param[in] keyBufMaxLen Buffer size in bytes
     * @param[in,out] keyLen Public key size in bytes
     *
     * @return 0 on Failure 1 on Success
     */
    int generatePublicKey(int keyID, byte keyBuf[], size_t keyBufMaxLen, size_t* keyLen);

        /** writeRSAKey
     *
     * writeRSAKey can be public, private and keypair, depending on keyType
     * CRT and RAW rsa_format are supported (if a value is missing the method retruns with 0)
     * When policy is set to NULL, default policy is used
     *
     * @param[in]  size            The size
     * @param[in]  p               The part p
     * @param[in]  pLen            The p length
     * @param[in]  q               The quarter
     * @param[in]  qLen            The quarter length
     * @param[in]  dp              The part dp
     * @param[in]  dpLen           The dp length
     * @param[in]  dq              The part dq
     * @param[in]  dqLen           The dq length
     * @param[in]  qInv            The quarter inv
     * @param[in]  qInvLen         The quarter inv length
     * @param[in]  pubExp          The pub exponent
     * @param[in]  pubExpLen       The pub exponent length
     * @param[in]  priv            The priv
     * @param[in]  privLen         The priv length
     * @param[in]  pubMod          The pub modifier
     * @param[in]  pubModLen       The pub modifier length
     * @param[in]  transient
     * @param[in]  key_part        The key part   (public/private/keypair)
     * @param[in]  rsa_format      The rsa format (raw/crt)
     * @param[in] KeyID Se050 objectID where is stored the public key or keypair
     * @param[in] keyBitLength Public key size in nit
     * @param[in] pSe05xPolicy_t       policy
     *
     * @return 0 on Failure 1 on Success
     */
    int writeRSAKey(int                  keyID,
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
        pSe05xPolicy_t       policy);

    /** importPublicKey
     *
     * Imports ECCurve_NIST_P256 public key into KeyID. Public key must be provided
     * inside publicKey with DER format.
     *
     * | P256 Header (26 bytes)| 0x04 (1 byte)| Public key X Y values (64 bytes) |
     *
     * @param[in] KeyID Se050 objectID where to store the private key
     * @param[in] keyBuf Buffer containing the public key in DER format
     * @param[in] keyLen Public key size in bytes
     *
     * @return 0 on Failure 1 on Success
     */
    int importPublicKey(int keyID, const byte publicKey[], size_t keyLen);

    /** beginSHA1
     *
     * Initialize digest context to start a new SHA1 computation.
     *
     *
     * @return 0 on Failure 1 on Success
     */
    int beginSHA1();

    /** updateSHA1
     *
     * Updates SHA1 adding new data to the previous iterations
     *
     * @param[in] in Input data buffer
     * @param[in] inLen Input data length
     *
     * @return 0 on Failure 1 on Success
     */
    int updateSHA1(const byte in[], size_t inLen);

    /** endSHA1
     *
     * Get SHA1 data and cleanup digest context
     *
     * @param[out] out Output data buffer
     * @param[in,out] outLen Size of output data buffer, SHA1 length
     *
     * @return 0 on Failure 1 on Success
     */
    int endSHA1(byte out[], size_t* outLen);

    /** beginSHA224
     *
     * Initialize digest context to start a new SHA224 computation.
     *
     *
     * @return 0 on Failure 1 on Success
     */
    int beginSHA224();

    /** updateSHA224
     *
     * Updates SHA224 adding new data to the previous iterations
     *
     * @param[in] in Input data buffer
     * @param[in] inLen Input data length
     *
     * @return 0 on Failure 1 on Success
     */
    int updateSHA224(const byte in[], size_t inLen);

    /** endSHA224
     *
     * Get SHA224 data and cleanup digest context
     *
     * @param[out] out Output data buffer
     * @param[in,out] outLen Size of output data buffer, SHA224 length
     *
     * @return 0 on Failure 1 on Success
     */
    int endSHA224(byte out[], size_t* outLen);

    /** beginSHA256
     *
     * Initialize digest context to start a new SHA256 computation.
     *
     *
     * @return 0 on Failure 1 on Success
     */
    int beginSHA256();

    /** updateSHA256
     *
     * Updates SHA256 adding new data to the previous iterations
     *
     * @param[in] in Input data buffer
     * @param[in] inLen Input data length
     *
     * @return 0 on Failure 1 on Success
     */
    int updateSHA256(const byte in[], size_t inLen);

    /** endSHA256
     *
     * Get SHA256 data and cleanup digest context
     *
     * @param[out] out Output data buffer
     * @param[in,out] outLen Size of output data buffer, SHA256 length
     *
     * @return 0 on Failure 1 on Success
     */
    int endSHA256(byte out[], size_t* outLen);

    /** SHA256
     *
     * One-shot SHA256
     *
     * @param[in] in Input data buffer
     * @param[in] inLen Input data length
     * @param[out] out Output buffer
     * @param[in] outMaxLen Output buffer size
     * @param[out] outLen SHA256 length
     *
     * @return 0 on Failure 1 on Success
     */
    int SHA256(const byte in[], size_t inLen, byte out[], size_t outMaxLen, size_t* outLen);

    /** beginSHA384
     *
     * Initialize digest context to start a new SHA384 computation.
     *
     *
     * @return 0 on Failure 1 on Success
     */
    int beginSHA384();

    /** updateSHA384
     *
     * Updates SHA384 adding new data to the previous iterations
     *
     * @param[in] in Input data buffer
     * @param[in] inLen Input data length
     *
     * @return 0 on Failure 1 on Success
     */
    int updateSHA384(const byte in[], size_t inLen);

    /** endSHA384
     *
     * Get SHA384 data and cleanup digest context
     *
     * @param[out] out Output data buffer
     * @param[in,out] outLen Size of output data buffer, SHA384 length
     *
     * @return 0 on Failure 1 on Success
     */
    int endSHA384(byte out[], size_t* outLen);

    /** beginSHA512
     *
     * Initialize digest context to start a new SHA512 computation.
     *
     *
     * @return 0 on Failure 1 on Success
     */
    int beginSHA512();

    /** updateSHA512
     *
     * Updates SHA512 adding new data to the previous iterations
     *
     * @param[in] in Input data buffer
     * @param[in] inLen Input data length
     *
     * @return 0 on Failure 1 on Success
     */
    int updateSHA512(const byte in[], size_t inLen);

    /** endSHA512
     *
     * Get SHA512 data and cleanup digest context
     *
     * @param[out] out Output data buffer
     * @param[in,out] outLen Size of output data buffer, SHA512 length
     *
     * @return 0 on Failure 1 on Success
     */
    int endSHA512(byte out[], size_t* outLen);

    /** Sign
     *
     * Computes ECDSA signature using key stored in KeyID SE050 object.
     * Output buffer is filled with the signature in DER format:
     *
     * | 0x30 | payloadsize 1 byte | 0x02 | R length 1 byte | padding 0x00 (if length 0x21) | R values 32 bytes
     *                             | 0x02 | S length 1 byte | padding 0x00 (if length 0x21) | S values 32 bytes
     *
     * SHA256 -> private Key -> Signature
     *
     * @param[in] keyID SE050 object ID containing the key
     * @param[in] hash Input SHA256 used to compute the signature
     * @param[in] hashLen SHA256 length
     * @param[out] sig Output buffer containint the signature
     * @param[in] maxSigLen Output buffer size
     * @param[out] sigLen signature length
     *
     * @return 0 on Failure 1 on Success
     */
    int Sign(int keyID, const byte hash[], size_t hashLen, byte sig[], size_t maxSigLen, size_t* sigLen);

    /** Sign
     *
     * Computes RSA signature using key stored in KeyID SE050 object.
     * Output buffer is filled with the signature in DER format
     *
     * SHA256 -> private Key -> Signature
     *
     * @param[in] keyID SE050 object ID containing the key
     * @param[in] encodedHash Input RSASSA-PKCS1-v1_5 or RSASSA-PSS encoded hash used to compute the signature
     * @param[in] encodedHashLen RSASSA-PKCS1-v1_5 or RSASSA-PSS length
     * @param[out] sig Output buffer containing the signature
     * @param[in] maxSigLen Output buffer size
     * @param[out] sigLen signature length
     *
     * @return 0 on Failure 1 on Success
     */
    int SignRSA(int keyID, const byte encodedHash[], size_t encodedHashLen, byte sig[], size_t maxSigLen, size_t* sigLen);
    /** Verify
     *
     * Verify ECDSA signature using key stored in KeyID SE050 object.
     *
     *                               Input SHA256
     *                                             ? Match ?
     * Signature -> public Key -> Original SHA256
     *
     * @param[in] keyID SE050 object ID containing the key
     * @param[in] hash Input SHA256 used to compute the signature
     * @param[in] hashLen SHA256 length
     * @param[in] sig Input buffer containint the signature
     * @param[in] sigLen signature length
     *
     * @return 0 on Failure (Not match) 1 on Success (Match)
     */
    int Verify(int keyID, const byte hash[], size_t hashLen, const byte sig[],size_t sigLen);

    /** Verify
     *
     * Verify RSASSA_PKCS1 signature using key stored in KeyID SE050 object.
     *
     *                               Input pkcs1_v15_encoded hash
     *                                             ? Match ?
     * Signature -> public Key -> pkcs1_v15_encoded hash
     *
     * @param[in] keyID SE050 object ID containing the key
     * @param[in] encodedHash Input pkcs1_v15_encoded hash used to compute the signature (the method pkcs1_v15_encode can be used to generate the encoded hash)
     * @param[in] encodedHashLen pkcs1_v15_encoded hash length
     * @param[in] sig Input buffer containint the signature
     * @param[in] sigLen signature length
     *
     * @return 0 on Failure (Not match) 1 on Success (Match)
     */
    int VerifyRSASSA_PKCS1(int keyID, const byte encodedHash[], size_t encodedHashLen, const byte sig[], size_t sigLen);

    /** readBinaryObject
     *
     * Reads binary data from SE050 object.
     *
     * @param[in] ObjectId SE050 object ID containing data
     * @param[out] data Output data buffer
     * @param[in] dataMaxLen Output data buffer size
     * @param[out] sig Binary object size
     *
     * @return 0 on Failure 1 on Success
     */
    int readBinaryObject(int ObjectId, byte data[], size_t dataMaxLen, size_t* length);

    /** AES_ECB_encrypt
     *
     * Enrypts something with AES ECB
     *
     * @param[in] ObjectId SE050 object ID
     * @param[in] data Input data buffer
     * @param[in] length Input data buffer size (should be a multiple of 16 bytes)
     * @param[out] output Output data buffer
     * @param[out] output_length Output data buffer size (same as input)
     *
     * @return 0 on Failure 1 on Success
     */
    int AES_ECB_encrypt(int objectId, const byte data[], size_t data_length, byte output[], size_t *output_len);

    /** AES_ECB_decrypt
     *
     * Enrypts something with AES ECB
     *
     * @param[in] ObjectId SE050 object ID
     * @param[in] data Input data buffer
     * @param[in] length Input data buffer size (should be a multiple of 16 bytes)
     * @param[out] output Output data buffer
     * @param[out] output_length Output data buffer size (same as input)
     *
     * @return 0 on Failure 1 on Success
     */
    int AES_ECB_decrypt(int objectId, const byte data[], size_t data_length, byte output[], size_t *output_len);

    /** writeAESKey
     *
     * Writes symmetric key into SE050 object.
     *
     * @param[in] ObjectId SE050 object ID
     * @param[in] data Input data buffer
     * @param[in] length Input data buffer size
     *
     * @return 0 on Failure 1 on Success
     */
    int writeAESKey(int ObjectId, const byte data[], size_t length);

    /** writeHMACKey
     *
     * Writes symmetric key into SE050 object.
     *
     * @param[in] ObjectId SE050 object ID for the hmac key
     * @param[in] data Input data buffer
     * @param[in] length Input data buffer size
     *
     * @return 0 on Failure 1 on Success
     */
    int writeHMACKey(int ObjectId, const byte data[], size_t length);

    /** HMAC_Generate
     *
     * Computes the HMAC digest with SE050 chip
     *
     * @param[in] objectId SE050 object ID for the hmac key
     * @param[in] mac_operation Type of Hash function for HMAC
     * @param[in] data Input data buffer
     * @param[in] length Input data buffer size
     * @param[out] output Output data buffer
     * @param[out] output_length Output data buffer size (should be 32 bytes for SHA256)
     *
     * @return 0 on Failure 1 on Success
     */
    int HMAC_Generate(int objectId, uint8_t mac_operation, const byte data[], size_t data_length, byte output[], size_t *output_len);


    /** writeBinaryObject
     *
     * Writes binary data into SE050 object.
     *
     * @param[in] ObjectId SE050 object ID
     * @param[in] data Input data buffer
     * @param[in] length Input data buffer size
     *
     * @return 0 on Failure 1 on Success
     */
    int writeBinaryObject(int ObjectId, const byte data[], size_t length);

    /** existsBinaryObject
     *
     * Checks if Object exist
     *
     * @param[in] ObjectId SE050 object ID
     *
     * @return 0 on Failure (Not exist) 1 on Success (Exists)
     */
    int existsBinaryObject(int objectId);

    /** deleteBinaryObject
     *
     * Deletes SE050 object
     *
     * @param[in] ObjectId SE050 object ID
     *
     * @return 0 on Failure 1 on Success
     */
    int deleteBinaryObject(int objectId);

    /** deleteBinaryObject
     *
     * Deletes all SE050 user objects
     *
     * @param[in] ObjectId SE050 object ID
     *
     * @return 0 on Failure 1 on Success
     */
    int deleteAllObjects();

    /* ECCX08 legacy API*/

    /** generatePrivateKey
     *
     * Create a new ECCurve_NIST_P256 keypair. Only public key X Y values will be available
     * inside publicKey buffer.
     *
     * | Public key X Y values (64 bytes) |
     *
     * @param[in] slot Se050 objectID where to store the private key
     * @param[out] publicKey Buffer containing the public key X Y values
     *
     * @return 0 on Failure 1 on Success
     */
    int generatePrivateKey(int slot, byte publicKey[]);
    
    /** generatePrivateRSAKey
     *
     * Create a new RSA keypair. Only public exponent and modulus values will be available
     * inside the provided buffers.
     *
     * @param[in] slot Se050 objectID where to store the private key
     * @param[out] exponent Buffer containing the public exponent
     * @param[out] modulus Buffer containing the modulus
     *
     * @return 0 on Failure 1 on Success
     */
    int generatePrivateRSAKey(int keyID, byte modulus[], size_t* modLen, byte exponent[], size_t* expLen, uint16_t keyBitLength);

    /** generatePublicKey
     *
     * Reads ECCurve_NIST_P256 public key from KeyID. Public key X Y values will be available
     * inside publicKey buffer.
     *
     * | Public key X Y values (64 bytes) |
     *
     * @param[in] slot Se050 objectID where is stored the public key or keypair
     * @param[out] pubkey Buffer containing the public key X Y values
     *
     * @return 0 on Failure 1 on Success
     */
    int generatePublicKey(int slot, byte publicKey[]);

    /** ecdsaVerify
     *
     * Verify ECDSA signature using public key.
     *
     *                               Input SHA256
     *                                             ? Match ?
     * Signature -> public Key -> Original SHA256
     *
     * @param[in] message Input SHA256 used to compute the signature 32 bytes
     * @param[in] sig Input buffer containint the signature R S values 64bytes
     * @param[in] pubkey Public key X Y values 64bytes
     *
     * @return 0 on Failure (Not match) 1 on Success (Match)
     */
    int ecdsaVerify(const byte message[], const byte signature[], const byte pubkey[]);

    /** ecSign
     *
     * Computes ECDSA signature using key stored in KeyID SE050 object.
     * Output buffer is filled with the signature R S values:
     *
     * | R values 32 bytes | S values 32 bytes |
     *
     * SHA256 -> private Key -> Signature
     *
     * @param[in] slot SE050 object ID containing the key
     * @param[in] message Input SHA256 used to compute the signature 32 bytes
     * @param[out] signature Output buffer containint the signature 64 bytes
     *
     * @return 0 on Failure 1 on Success
     */
    int ecSign(int slot, const byte message[], byte signature[]);

    /** readSlot
     *
     * Reads binary data from SE050 object.
     *
     * @param[in] ObjecslottId SE050 object ID containing data
     * @param[out] data Output data buffer
     * @param[in] length Number of bytes to read
     *
     * @return 0 on Failure 1 on Success
     */
    int readSlot(int slot, byte data[], int length);

    /** writeSlot
     *
     * Writes binary data into SE050 object.
     *
     * @param[in] ObjectId SE050 object ID
     * @param[in] data Input data buffer
     * @param[in] length Number of bytes to write
     *
     * @return 0 on Failure 1 on Success
     */
    int writeSlot(int slot, const byte data[], int length);

    /** pkcs1_v15_encode
     *
     * The hash to the buffer in the RSASSA-PKCS1-v1_5 format.
     *
     * @param[in] ObjectId SE050 object ID
     * @param[in] data Input data buffer
     * @param[in] length Number of bytes to write
     *
     * @return 0 on Failure 1 on Success
     */
    int pkcs1_v15_encode(uint8_t* hash, size_t hashlen, uint8_t* out, size_t* outLen, SE05x_RSASignatureAlgo_t rsaSignAlgo, SE05x_RSABitLength_t keyLength);
    
    /** RSAEncryptOAEP
     *
     * Enrypts message with RSA using OAEP padding
     * hash digest size = 20 bytes (SHA1 as specified in AN12413 4.3.14)
     *
     * @param[in] keyID SE050 key ID
     * @param[in] message Input data buffer
     * @param[in] messageLen Input data buffer size: must be less than ((RSA modulus - 2) - (2 * (hash digest size); (256 - 2) - (2*20) = 214 bytes for 2048bit keys
     * @param[out] cipher Output data buffer: must be greater or equal as RSA modulus
     * @param[out] cipherLen Output data buffer size (depending on the key size)
     * @param[in] cipherMaxLen Output data buffer size 
     *
     * @return 0 on Failure 1 on Success
     */
    int RSAEncryptOAEP(int keyID, const byte message[], size_t messageLen, byte cipher[], size_t* cipherLen, size_t cipherMaxLen);
    /** RSAEncryptRAW
     *
     * Enrypts message with RSA using no dedicated padding
     *
     * @param[in] keyID SE050 key ID
     * @param[in] message Input data buffer
     * @param[in] messageLen Input data buffer size: must be less than RSA modulus
     * @param[out] cipher Output data buffer: must be greater or equal as RSA modulus
     * @param[out] cipherLen Output data buffer size (depending on the key size)
     * @param[in] cipherMaxLen Output data buffer size
     *
     * @return 0 on Failure 1 on Success
     */
    int RSAEncryptRAW(int keyID, const byte message[], size_t messageLen, byte cipher[], size_t* cipherLen, size_t cipherMaxLen);
    /** RSADecryptOAEP
     *
     * Enrypts cipher with RSA using OAEP padding
     *
     * @param[in] keyID SE050 key ID
     * @param[out] message Output data buffer
     * @param[out] messageLen length of the message output
     * @param[in] cipher Input data buffer
     * @param[in] cipherLen Input data buffer size
     * @param[in] messageMaxLen Output data buffer size
     *
     * @return 0 on Failure 1 on Success
     */
    int RSADecryptOAEP(int keyID, byte message[], size_t* messageLen, size_t messageMaxLen, const byte cipher[], size_t cipherLen);
    /** RSADecryptRAW
     *
     * Enrypts cipher with RSA no padding
     *
     * @param[in] keyID SE050 key ID
     * @param[out] message Output data buffer
     * @param[out] messageLen length of the message output
     * @param[in] cipher Input data buffer
     * @param[in] cipherLen Input data buffer size
     * @param[in] messageMaxLen Output data buffer size
     *
     * @return 0 on Failure 1 on Success
     */
    int RSADecryptRAW(int keyID, byte message[], size_t* messageLen, size_t messageMaxLen, const byte cipher[], size_t cipherLen);
    int emsa_pss_encode(uint8_t*                 hash,
        size_t                   hashlen,
        uint8_t*                 out,
        size_t*                  outLen,
        SE05x_RSASignatureAlgo_t rsaSignAlgo,
        SE05x_RSABitLength_t     keyLength,
        uint8_t*                 externalSalt,
        size_t                   externalSaltLen);
    int emsa_pss_encode(uint8_t*                 hash,
        size_t                   hashlen,
        uint8_t*                 out,
        size_t*                  outLen,
        SE05x_RSASignatureAlgo_t rsaSignAlgo,
        SE05x_RSABitLength_t     keyLength);
    /** mgf1
     *
     * Generates mgf1 mask
     *
     * @param[in] mgfSeed pointer to the seed data buffer
     * @param[in] seedLen length of the seed data buffer
     * @param[out] mask Output data buffer of the mask (the buffer size must be greater or equal to maskLen)
     * @param[out] maskLen length of the mask output
     * @param[in] hLen hLen must be the output size in bytes of a accepted hashing algo (SHA1=20,SHA224=28,SHA256=32,SHA384=48,SHA512=64) 
     *
     * @return 0 on Failure 1 on Success
     */
    int mgf1(uint8_t* mgfSeed, size_t seedLen, uint8_t* mask, uint64_t* maskLen, size_t hLen);

    inline int locked() { return 1; }
    inline int lock() { return 1; }
    inline int writeConfiguration(const byte data[]) { (void)data; return 1; }
    inline Se05xSession_t* getSession() { return &_se05x_session; }

private:
    static int getECKeyXyValuesFromDER(byte* derKey, size_t derLen, byte* rawKey, size_t* rawLen);
    static int setECKeyXyVauesInDER(const byte* rawKey, size_t rawLen, byte* derKey, size_t* derLen);
    static int getECSignatureRsValuesFromDER(byte* derSignature, size_t derLen, byte* rawSignature, size_t* rawLen);
    static int setECSignatureRsValuesInDER(const byte* rawSignature, size_t rawLen, byte* signature, size_t* derLen);
    int I2OSP(uint8_t*  out,
        uint64_t        xLen,
        uint64_t        x);

    Se05xSession_t _se05x_session;
};

extern SE05XClass SE05X;

#endif
