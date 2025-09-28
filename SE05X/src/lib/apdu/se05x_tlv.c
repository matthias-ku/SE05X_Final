/** @file se05x_tlv.c
 *  @brief TLV utils functions.
 *
 * Copyright 2021,2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include "se05x_tlv.h"
#include "smCom.h"
#ifdef ARDUINO
#include "../platform/arduino/sm_port.h"
#else
#include "sm_port.h"
#endif
#include "se05x_types.h"
#include <limits.h>

/* ********************** Function Prototypes ********************** */
#ifdef WITH_PLATFORM_SCP03
smStatus_t Se05x_API_SCP03_TransmitData(pSe05xSession_t session_ctx,
    const tlvHeader_t *hdr,
    uint8_t *cmdBuf,
    size_t cmdBufLen,
    uint8_t *rspBuf,
    size_t *pRspBufLen,
    uint8_t hasle);
#endif

/* ********************** Function ********************** */

int tlvSet_U8(uint8_t **buf, size_t *bufLen, SE05x_TAG_t tag, uint8_t value)
{
    uint8_t *pBuf            = NULL;
    const size_t size_of_tlv = 1 + 1 + 1;

    ENSURE_OR_RETURN_ON_ERROR(buf != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(bufLen != NULL, 1);

    pBuf = *buf;
    ENSURE_OR_RETURN_ON_ERROR(pBuf != NULL, 1);

    if ((*bufLen) > (MAX_APDU_BUFFER - size_of_tlv)) {
        return 1;
    }
    *pBuf++ = (uint8_t)tag;
    *pBuf++ = 1;
    *pBuf++ = value;
    *buf    = pBuf;
    *bufLen += size_of_tlv;
    return 0;
}

int tlvSet_U16(uint8_t **buf, size_t *bufLen, SE05x_TAG_t tag, uint16_t value)
{
    const size_t size_of_tlv = 1 + 1 + 2;
    uint8_t *pBuf            = NULL;

    ENSURE_OR_RETURN_ON_ERROR(buf != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(bufLen != NULL, 1);

    pBuf = *buf;
    ENSURE_OR_RETURN_ON_ERROR(pBuf != NULL, 1);

    if ((*bufLen) > (MAX_APDU_BUFFER - size_of_tlv)) {
        return 1;
    }
    *pBuf++ = (uint8_t)tag;
    *pBuf++ = 2;
    *pBuf++ = (uint8_t)((value >> 1 * 8) & 0xFF);
    *pBuf++ = (uint8_t)((value >> 0 * 8) & 0xFF);
    *buf    = pBuf;
    *bufLen += size_of_tlv;
    return 0;
}

int tlvSet_U32(uint8_t **buf, size_t *bufLen, SE05x_TAG_t tag, uint32_t value)
{
    const size_t size_of_tlv = 1 + 1 + 4;
    uint8_t *pBuf            = NULL;

    ENSURE_OR_RETURN_ON_ERROR(buf != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(bufLen != NULL, 1);

    pBuf = *buf;
    ENSURE_OR_RETURN_ON_ERROR(pBuf != NULL, 1);

    if ((*bufLen) > (MAX_APDU_BUFFER - size_of_tlv)) {
        return 1;
    }
    *pBuf++ = (uint8_t)tag;
    *pBuf++ = 4;
    *pBuf++ = (uint8_t)((value >> 3 * 8) & 0xFF);
    *pBuf++ = (uint8_t)((value >> 2 * 8) & 0xFF);
    *pBuf++ = (uint8_t)((value >> 1 * 8) & 0xFF);
    *pBuf++ = (uint8_t)((value >> 0 * 8) & 0xFF);
    *buf    = pBuf;
    *bufLen += size_of_tlv;
    return 0;
}

int tlvSet_u8buf(uint8_t **buf, size_t *bufLen, SE05x_TAG_t tag, const uint8_t *cmd, size_t cmdLen)
{
    uint8_t *pBuf = NULL;

    ENSURE_OR_RETURN_ON_ERROR(buf != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(bufLen != NULL, 1);

    pBuf = *buf;
    ENSURE_OR_RETURN_ON_ERROR(pBuf != NULL, 1);

    /* if < 0x7F
    *    len = 1 byte
    * elif if < 0xFF
    *    '0x81' + len == 2 Bytes
    * elif if < 0xFFFF
    *    '0x82' + len_msb + len_lsb == 3 Bytes
    */
    const size_t size_of_length = (cmdLen <= 0x7f ? 1 : (cmdLen <= 0xFf ? 2 : 3));
    const size_t size_of_tlv    = 1 + size_of_length + cmdLen;

    if ((UINT_MAX - size_of_tlv) < (*bufLen)) {
        return 1;
    }

    if (((*bufLen) + size_of_tlv) > MAX_APDU_BUFFER) {
        SMLOG_E("Not enough buffer \n");
        return 1;
    }
    *pBuf++ = (uint8_t)tag;

    if (cmdLen <= 0x7Fu) {
        *pBuf++ = (uint8_t)cmdLen;
    }
    else if (cmdLen <= 0xFFu) {
        *pBuf++ = (uint8_t)(0x80 /* Extended */ | 0x01 /* Additional Length */);
        *pBuf++ = (uint8_t)((cmdLen >> 0 * 8) & 0xFF);
    }
    else if (cmdLen <= 0xFFFFu) {
        *pBuf++ = (uint8_t)(0x80 /* Extended */ | 0x02 /* Additional Length */);
        *pBuf++ = (uint8_t)((cmdLen >> 1 * 8) & 0xFF);
        *pBuf++ = (uint8_t)((cmdLen >> 0 * 8) & 0xFF);
    }
    else {
        return 1;
    }
    if ((cmdLen > 0) && (cmd != NULL)) {
        while (cmdLen-- > 0) {
            *pBuf++ = *cmd++;
        }
    }

    *bufLen += size_of_tlv;
    *buf = pBuf;

    return 0;
}

int tlvSet_u8bufOptional(uint8_t **buf, size_t *bufLen, SE05x_TAG_t tag, const uint8_t *cmd, size_t cmdLen)
{
    if (cmdLen == 0) {
        return 0;
    }
    else {
        return tlvSet_u8buf(buf, bufLen, tag, cmd, cmdLen);
    }
}

int tlvSet_u8bufOptional_ByteShift(uint8_t **buf, size_t *bufLen, SE05x_TAG_t tag, const uint8_t *cmd, size_t cmdLen)
{
    int ret = 1;
    if (cmdLen == 0) {
        ret = 0;
    } else if (0 == (cmdLen & 1)) {
        /* LSB is 0 */
        ret = tlvSet_u8buf(buf, bufLen, tag, cmd, cmdLen);
    } else {
        uint8_t localBuff[MAX_APDU_BUFFER];
        ENSURE_OR_GO_CLEANUP((cmdLen + 1) < sizeof(localBuff));
        ENSURE_OR_GO_CLEANUP(cmd != NULL);
        localBuff[0] = '\0';
        memcpy(localBuff + 1, cmd, cmdLen);
        ret = tlvSet_u8buf(buf, bufLen, tag, localBuff, cmdLen + 1);
    }

cleanup:
    return ret;
}

int tlvSet_U16Optional(uint8_t **buf, size_t *bufLen, SE05x_TAG_t tag, uint16_t value)
{
    if (value == 0) {
        return 0;
    }
    else {
        return tlvSet_U16(buf, bufLen, tag, value);
    }
}

int tlvSet_Se05xPolicy(const char *description, uint8_t **buf, size_t *bufLen, SE05x_TAG_t tag, Se05xPolicy_t *policy)
{
    int tlvRet = 0;
    (void)description;
    if ((policy != NULL) && (policy->value != NULL)) {
        tlvRet = tlvSet_u8buf(buf, bufLen, tag, policy->value, policy->value_len);
        return tlvRet;
    }
    return tlvRet;
}

int tlvSet_MaxAttemps(uint8_t **buf, size_t *bufLen, SE05x_TAG_t tag, uint16_t maxAttemps)
{
    int retVal = 0;
    if (maxAttemps != 0) {
        retVal = tlvSet_U16(buf, bufLen, tag, maxAttemps);
    }
    return retVal;
}

int tlvSet_ECCurve(uint8_t **buf, size_t *bufLen, SE05x_TAG_t tag, SE05x_ECCurve_t value)
{
    int retVal = 0;
    if (value != kSE05x_ECCurve_NA) {
        retVal = tlvSet_U8(buf, bufLen, tag, (uint8_t)value);
    }
    return retVal;
}

int tlvSet_KeyID(uint8_t **buf, size_t *bufLen, SE05x_TAG_t tag, uint32_t keyID)
{
    int retVal = 0;
    if (keyID != 0) {
        retVal = tlvSet_U32(buf, bufLen, tag, keyID);
    }
    return retVal;
}

int tlvSet_header(uint8_t **buf, size_t *bufLen, tlvHeader_t *hdr)
{
    uint8_t *pBuf = NULL;

    ENSURE_OR_RETURN_ON_ERROR(buf != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(bufLen != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(hdr != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(((UINT_MAX - 5) >= *bufLen), 1);

    pBuf = *buf;

    memcpy(pBuf, hdr, 4);
    *buf = pBuf + (4 + 1);
    *bufLen += (4 + 1);
    return 0;
}

int tlvGet_U8(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, SE05x_TAG_t tag, uint8_t *pRsp)
{
    int retVal      = 1;
    uint8_t *pBuf   = buf + (*pBufIndex);
    uint8_t got_tag = *pBuf++;
    size_t rspLen;

    if ((*pBufIndex) > bufLen) {
        goto cleanup;
    }

    if (got_tag != tag) {
        goto cleanup;
    }
    rspLen = *pBuf++;
    if (rspLen > 1) {
        goto cleanup;
    }
    *pRsp = *pBuf;
    *pBufIndex += (1 + 1 + (rspLen));
    retVal = 0;
cleanup:
    return retVal;
}

int tlvGet_u8buf(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, SE05x_TAG_t tag, uint8_t *rsp, size_t *pRspLen)
{
    int retVal      = 1;
    uint8_t *pBuf   = buf + (*pBufIndex);
    uint8_t got_tag = *pBuf++;
    size_t extendedLen;
    size_t rspLen;
    //size_t len;

    if (rsp == NULL) {
        goto cleanup;
    }

    if (pRspLen == NULL) {
        goto cleanup;
    }

    if ((*pBufIndex) > bufLen) {
        goto cleanup;
    }

    if (got_tag != tag) {
        goto cleanup;
    }
    rspLen = *pBuf++;

    if (rspLen <= 0x7FU) {
        extendedLen = rspLen;
        *pBufIndex += (1 + 1);
    }
    else if (rspLen == 0x81) {
        extendedLen = *pBuf++;
        *pBufIndex += (1 + 1 + 1);
    }
    else if (rspLen == 0x82) {
        extendedLen = *pBuf++;
        extendedLen = (extendedLen << 8) | *pBuf++;
        *pBufIndex += (1 + 1 + 2);
    }
    else {
        goto cleanup;
    }

    if (extendedLen > *pRspLen) {
        goto cleanup;
    }
    if (extendedLen > bufLen) {
        goto cleanup;
    }

    *pRspLen = extendedLen;
    *pBufIndex += extendedLen;
    while (extendedLen-- > 0) {
        *rsp++ = *pBuf++;
    }
    retVal = 0;
cleanup:
    if (retVal != 0) {
        if (pRspLen != NULL) {
            *pRspLen = 0;
        }
    }
    return retVal;
}

int tlvGet_Result(uint8_t *buf, size_t *pBufIndex, size_t bufLen, SE05x_TAG_t tag, SE05x_Result_t *presult)
{
    uint8_t uType   = 0;
    size_t uTypeLen = 1;
    int retVal      = tlvGet_u8buf(buf, pBufIndex, bufLen, tag, &uType, &uTypeLen);
    *presult        = (SE05x_Result_t)uType;
    return retVal;
}

int tlvGet_U16(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, SE05x_TAG_t tag, uint16_t *pRsp)
{
    int retVal    = 1;
    uint8_t *pBuf = buf + (*pBufIndex);
    uint8_t got_tag;
    size_t rspLen;

    if (bufLen < 4) {
        goto cleanup;
    }
    if ((*pBufIndex) > bufLen - 4) {
        goto cleanup;
    }

    got_tag = *pBuf++;
    if (got_tag != tag) {
        goto cleanup;
    }
    rspLen = *pBuf++;
    if (rspLen > 2) {
        goto cleanup;
    }
    *pRsp = (*pBuf++) << 8;
    *pRsp |= *pBuf++;
    *pBufIndex += (1 + 1 + (rspLen));
    retVal = 0;
cleanup:
    return retVal;
}

smStatus_t DoAPDUTx(
    pSe05xSession_t session_ctx, const tlvHeader_t *hdr, uint8_t *cmdBuf, size_t cmdBufLen, uint8_t hasle)
{
    smStatus_t apduStatus = SM_NOT_OK;
    size_t rxBufLen       = sizeof(session_ctx->apdu_buffer) / 2;
    uint8_t *rspBuf       = &session_ctx->apdu_buffer[ADPU_BUFFER_RX_OFFSET];

    ENSURE_OR_GO_EXIT(hdr != NULL);
    if (cmdBufLen > 0) {
        ENSURE_OR_GO_EXIT(cmdBuf != NULL);
    }

#ifdef WITH_PLATFORM_SCP03
    apduStatus = Se05x_API_SCP03_TransmitData(session_ctx, hdr, cmdBuf, cmdBufLen, rspBuf, &rxBufLen, hasle);
#else

    if ((hasle && cmdBufLen > 0) || cmdBufLen > 0xFF) { // Extended length APDU

        // Format: CLA INS P1 P2 00 Lc(2 bytes) [Data]
        if (cmdBufLen > 0xFFFF) {
            return apduStatus;
        }

        // 7 additional bytes Extended tx case CLA INS P1 P2 00 Lc(2 bytes)
        if (cmdBufLen > (MAX_APDU_BUFFER - 7)) {
            return apduStatus;
        }

        // add header
        memmove((cmdBuf + 7), cmdBuf, cmdBufLen);
        memcpy(cmdBuf, hdr, 4);

        cmdBuf[4] = 0x00;
        cmdBuf[5] = (uint8_t)(cmdBufLen >> 8) & 0xFF; // Lc high byte
        cmdBuf[6] = (uint8_t)cmdBufLen & 0xFF; // Lc low byte
        cmdBufLen += 7; // Header(4) + Lc(3)
        //this is a TX only method so LE isn't required
    } else if (cmdBufLen > 0) {
        // if cmdBufLen is larger than cmdBufLen we need a extedned case
        if (cmdBufLen > 0xFF) {
            return apduStatus;
        }

        if (cmdBufLen > (MAX_APDU_BUFFER - 5)) {
            return apduStatus;
        }

        // add header + Lc
        memmove((cmdBuf + 5), cmdBuf, cmdBufLen);
        memcpy(cmdBuf, hdr, 4);
        cmdBuf[4] = cmdBufLen & 0xFF; // Lc
        cmdBufLen += 5; // Header(4) + Lc(1)
    } else {
        // No command data (Case 1)
        // Format: CLA INS P1 P2
        memcpy(cmdBuf, hdr, 4);
        cmdBufLen = 4;
    }

    apduStatus = smComT1oI2C_TransceiveRaw(session_ctx->conn_context, cmdBuf, cmdBufLen, rspBuf, &rxBufLen);
    if (rxBufLen >= 2) {
        apduStatus = rspBuf[(rxBufLen)-2] << 8 | rspBuf[(rxBufLen)-1];
    }
#endif //#ifdef WITH_PLATFORM_SCP03

exit:
    return apduStatus;
}

smStatus_t DoAPDUTxRx(pSe05xSession_t session_ctx,
    const tlvHeader_t *hdr,
    uint8_t *cmdBuf,
    size_t cmdBufLen,
    uint8_t *rspBuf,
    size_t *pRspBufLen,
    uint8_t hasle)
{
    smStatus_t apduStatus = SM_NOT_OK;

    ENSURE_OR_GO_EXIT(hdr != NULL);
    if (cmdBufLen > 0) {
        ENSURE_OR_GO_EXIT(cmdBuf != NULL);
    }
    ENSURE_OR_GO_EXIT(pRspBufLen != NULL);
    ENSURE_OR_GO_EXIT(rspBuf != NULL);

#ifdef WITH_PLATFORM_SCP03
    apduStatus = Se05x_API_SCP03_TransmitData(session_ctx, hdr, cmdBuf, cmdBufLen, rspBuf, pRspBufLen, hasle);
#else
    if (hasle && cmdBufLen > 0) { // Extended length APDU
        
        // Format: CLA INS P1 P2 00 Lc(2 bytes) [Data] Le(2 bytes)
        if (cmdBufLen > 0xFFFF) {
            return apduStatus;
        }

        if (cmdBufLen > (MAX_APDU_BUFFER - 9)) {
            return apduStatus;
        }

        // add header
        memmove((cmdBuf + 7), cmdBuf, cmdBufLen);
        memcpy(cmdBuf, hdr, 4);

        cmdBuf[4] = 0x00;
        cmdBuf[5] = (uint8_t)(cmdBufLen >> 8) & 0xFF; // Lc high byte
        cmdBuf[6] = (uint8_t)cmdBufLen & 0xFF; // Lc low byte
        // Set Le: 0x0000 for maximum response length  AN12413 4.1.2 Le field must in any case be smaller than 0x8000
        cmdBuf[7 + cmdBufLen] = (uint8_t)(MAX_APDU_BUFFER >> 8) & 0xFF; // Le high byte
        cmdBuf[8 + cmdBufLen] = (uint8_t)(MAX_APDU_BUFFER)&0xFF; // Le low byte
        cmdBufLen += 9; // Header(4) + Lc(3) + Le(2)
    } else if (cmdBufLen > 0) {

        if (cmdBufLen > 0xFF) {
            return apduStatus;
        }

        if (cmdBufLen > (MAX_APDU_BUFFER - 5)) {
            return apduStatus;
        }

        // add header + Lc
        memmove((cmdBuf + 5), cmdBuf, cmdBufLen);
        memcpy(cmdBuf, hdr, 4);
        cmdBuf[4] = cmdBufLen & 0xFF; // Lc
        cmdBufLen += 5; // Header(4) + Lc(1)
    } else {
        if(!hasle){
            // No command data (Case 1)
            // Format: CLA INS P1 P2
            memcpy(cmdBuf, hdr, 4);
            cmdBufLen = 4;
        }else if(hasle && cmdBufLen == 0){
            // No command data (Case 2E)
            // Format: CLA INS P1 P2 00 (LE 2 Byte)
            memcpy(cmdBuf, hdr, 4);
            cmdBuf[4] = 0x00;
            cmdBuf[5] = (uint8_t)(MAX_APDU_BUFFER >> 8) & 0xFF; // Le high byte
            cmdBuf[6] = (uint8_t)(MAX_APDU_BUFFER)&0xFF; // Le low byte
            cmdBufLen = 7;
        }
    }

    apduStatus = smComT1oI2C_TransceiveRaw(session_ctx->conn_context, cmdBuf, cmdBufLen, rspBuf, pRspBufLen);
    if (*pRspBufLen >= 2) {
        apduStatus = rspBuf[(*pRspBufLen) - 2] << 8 | rspBuf[(*pRspBufLen) - 1];
    }
#endif //#ifdef WITH_PLATFORM_SCP03

exit:
    return apduStatus;
}
