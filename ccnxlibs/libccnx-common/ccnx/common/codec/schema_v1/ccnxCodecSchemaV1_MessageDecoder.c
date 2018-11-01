/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>

#include <LongBow/runtime.h>

#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_Object.h>
#include <parc/algol/parc_Buffer.h>

#include <ccnx/common/codec/schema_v1/ccnxCodecSchemaV1_Types.h>
#include <ccnx/common/codec/schema_v1/ccnxCodecSchemaV1_MessageDecoder.h>

#include <ccnx/common/codec/ccnxCodec_TlvUtilities.h>
#include <ccnx/common/ccnx_PayloadType.h>
#include <ccnx/common/ccnx_InterestReturn.h>

static bool
_translateWirePayloadTypeToCCNxPayloadType(CCNxCodecSchemaV1Types_PayloadType wireFormatType, CCNxPayloadType *payloadTypePtr)
{
//by wschoi
printf("######################_translateWirePayloadTypeToCCNxPayloadType\n\n");
    bool success = true;
    switch (wireFormatType) {
        case CCNxCodecSchemaV1Types_PayloadType_Data:
            *payloadTypePtr = CCNxPayloadType_DATA;
            break;

        case CCNxCodecSchemaV1Types_PayloadType_Key:
            *payloadTypePtr = CCNxPayloadType_KEY;
            break;

        case CCNxCodecSchemaV1Types_PayloadType_Link:
            *payloadTypePtr = CCNxPayloadType_LINK;
            break;

        default:
            // unknown type
            success = false;
    }
    return success;
}

/**
 * Translates the wire format value for the PayloadType to CCNxPayloadType
 */
static bool
_decodePayloadType(CCNxCodecTlvDecoder *decoder, CCNxTlvDictionary *packetDictionary, uint16_t length)
{
//by wschoi
printf("######################_decodePayloadType\n\n");

    CCNxPayloadType payloadType;

    uint64_t wireFormatVarInt;
    bool success = ccnxCodecTlvDecoder_GetVarInt(decoder, length, &wireFormatVarInt);
    if (success) {
        CCNxCodecSchemaV1Types_PayloadType wireFormatType = (CCNxCodecSchemaV1Types_PayloadType) wireFormatVarInt;

        success = _translateWirePayloadTypeToCCNxPayloadType(wireFormatType, &payloadType);
    }

    if (success) {
        success = ccnxTlvDictionary_PutInteger(packetDictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_PAYLOADTYPE, payloadType);
    }
//by wschoi
	//printf("##############_decodePayloadType    success   %d\n\n",success);
    return success;
}

static bool
_decodeType(CCNxCodecTlvDecoder *decoder, CCNxTlvDictionary *packetDictionary, uint16_t type, uint16_t length)
{
//by wschoi
	//printf("######################_decodeType\n\n");

    bool success = false;
    switch (type) {
        case CCNxCodecSchemaV1Types_CCNxMessage_Name:
            success = ccnxCodecTlvUtilities_PutAsName(decoder, packetDictionary, type, length, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME);
            break;

        case CCNxCodecSchemaV1Types_CCNxMessage_Payload:
            success = ccnxCodecTlvUtilities_PutAsBuffer(decoder, packetDictionary, type, length, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_PAYLOAD);
            break;
//by wschoi
//LOOKUP

        case CCNxCodecSchemaV1Types_CCNxMessage_T_GETNAME:
            success = ccnxCodecTlvUtilities_PutAsBuffer(decoder, packetDictionary, type, length, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_GETNAME);
            break;

        case CCNxCodecSchemaV1Types_CCNxMessage_T_PAYLOAD_GETNAME:
            success = ccnxCodecTlvUtilities_PutAsBuffer(decoder, packetDictionary, type, length, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_PAYLOAD_GETNAME);
            break;

        case CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_KEY:
            success = ccnxCodecTlvUtilities_PutAsBuffer(decoder, packetDictionary, type, length, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME_KEY);
            break;

			
//REGISTRATION
//registration
        case CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_REGISTRATION_KeyName:
            success = ccnxCodecTlvUtilities_PutAsBuffer(decoder, packetDictionary, type, length, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME_REG_KEY);
            break;

        case CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_REGISTRATION_ValueName:
            success = ccnxCodecTlvUtilities_PutAsBuffer(decoder, packetDictionary, type, length, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME_REG_VALUE);
            break;

        case CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_REGISTRATION_ACK:
            success = ccnxCodecTlvUtilities_PutAsBuffer(decoder, packetDictionary, type, length, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME_REG_ACK);
            break;


//ADD
        case CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_ADD_KeyName:
            success = ccnxCodecTlvUtilities_PutAsBuffer(decoder, packetDictionary, type, length, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME_ADD_KEY);
            break;

        case CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_ADD_ValueName:
            success = ccnxCodecTlvUtilities_PutAsBuffer(decoder, packetDictionary, type, length, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME_ADD_VALUE);
            break;

        case CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_ADD_ACK:
            success = ccnxCodecTlvUtilities_PutAsBuffer(decoder, packetDictionary, type, length, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME_ADD_ACK);
            break;

			
//DEL
        case CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_DEL_KeyName:
            success = ccnxCodecTlvUtilities_PutAsBuffer(decoder, packetDictionary, type, length, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME_DEL_KEY);
            break;

        case CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_DEL_ValueName:
            success = ccnxCodecTlvUtilities_PutAsBuffer(decoder, packetDictionary, type, length, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME_DEL_VALUE);
            break;

        case CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_DEL_ACK:
            success = ccnxCodecTlvUtilities_PutAsBuffer(decoder, packetDictionary, type, length, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME_DEL_ACK);
            break;


//DEREG
        case CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_DEREG_KeyName:
            success = ccnxCodecTlvUtilities_PutAsBuffer(decoder, packetDictionary, type, length, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME_DEREG_KEY);
            break;

        case CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_DEREG_ValueName:
            success = ccnxCodecTlvUtilities_PutAsBuffer(decoder, packetDictionary, type, length, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME_DEREG_VALUE);
            break;

        case CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_DEREG_ACK:
            success = ccnxCodecTlvUtilities_PutAsBuffer(decoder, packetDictionary, type, length, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME_DEREG_ACK);
            break;

#if 0
//refresh
        case CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_REFRESH_KeyName:
            success = ccnxCodecTlvUtilities_PutAsBuffer(decoder, packetDictionary, type, length, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME_REFRESH_KEY);
            break;

        case CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_REFRESH_ValueName:
            success = ccnxCodecTlvUtilities_PutAsBuffer(decoder, packetDictionary, type, length, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME_REFRESH_VALUE);
            break;

        case CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_REFRESH_ACK:
            success = ccnxCodecTlvUtilities_PutAsBuffer(decoder, packetDictionary, type, length, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME_REFRESH_ACK);
            break;

#endif


        case CCNxCodecSchemaV1Types_CCNxMessage_KeyIdRestriction:
            success = ccnxCodecTlvUtilities_PutAsHash(decoder, packetDictionary, type, length, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_KEYID_RESTRICTION);
            break;

        case CCNxCodecSchemaV1Types_CCNxMessage_ContentObjectHashRestriction:
            success = ccnxCodecTlvUtilities_PutAsHash(decoder, packetDictionary, type, length, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_OBJHASH_RESTRICTION);
            break;

        case CCNxCodecSchemaV1Types_CCNxMessage_PayloadType:
            success = _decodePayloadType(decoder, packetDictionary, length);
            break;

        case CCNxCodecSchemaV1Types_CCNxMessage_ExpiryTime:
            success = ccnxCodecTlvUtilities_PutAsInteger(decoder, packetDictionary, type, length, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_EXPIRY_TIME);
            break;

        case CCNxCodecSchemaV1Types_CCNxMessage_EndChunkNumber:
            success = ccnxCodecTlvUtilities_PutAsInteger(decoder, packetDictionary, type, length, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_ENDSEGMENT);
            break;

        default:
            // if we do not know the TLV type, put it in this container's unknown list
            success = ccnxCodecTlvUtilities_PutAsListBuffer(decoder, packetDictionary, type, length, CCNxCodecSchemaV1TlvDictionary_Lists_MESSAGE_LIST);
            break;
    }

    if (!success) {
        CCNxCodecError *error = ccnxCodecError_Create(TLV_ERR_DECODE, __func__, __LINE__, ccnxCodecTlvDecoder_Position(decoder));
        ccnxCodecTlvDecoder_SetError(decoder, error);
        ccnxCodecError_Release(&error);
    }

    return success;
}

/*
 * We are given a decoder that points to the first TLV of a list of TLVs.  We keep walking the
 * list until we come to the end of the decoder.
 */
bool
ccnxCodecSchemaV1MessageDecoder_Decode(CCNxCodecTlvDecoder *decoder, CCNxTlvDictionary *packetDictionary)
{
//by wschoi
//printf("######################ccnxCodecSchemaV1MessageDecoder_Decode\n\n");
    return ccnxCodecTlvUtilities_DecodeContainer(decoder, packetDictionary, _decodeType);
}
