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

#include <parc/security/parc_SigningAlgorithm.h>

#include <ccnx/common/internal/ccnx_ContentObjectFacadeV1.h>
#include <ccnx/common/internal/ccnx_ValidationFacadeV1.h>
#include <ccnx/common/internal/ccnx_ChunkingFacadeV1.h>
#include <ccnx/common/codec/schema_v1/ccnxCodecSchemaV1_TlvDictionary.h>

#include <ccnx/common/codec/ccnxCodec_TlvEncoder.h>

//by wschoi
//#define LOG_CHECK

static void
_assertInvariants(const CCNxTlvDictionary *contentObjectDictionary)
{
    assertNotNull(contentObjectDictionary, "Dictionary is null");
    assertTrue(ccnxTlvDictionary_IsContentObject(contentObjectDictionary), "Dictionary is not a content object");
    assertTrue(ccnxTlvDictionary_GetSchemaVersion(contentObjectDictionary) == CCNxTlvDictionary_SchemaVersion_V1,
               "Dictionary is wrong schema version, got %d expected %d",
               ccnxTlvDictionary_GetSchemaVersion(contentObjectDictionary), CCNxTlvDictionary_SchemaVersion_V1);
}

// =========================
// Creation

//by wschoi
//LOOKUP
static CCNxTlvDictionary *
_ccnxContentObjectFacadeV1_CreateWithNameAndPayload_lookup(const CCNxName *name,              // required
                                                    const CCNxPayloadType payloadType, // required
                                                    const PARCBuffer *payload)         // may be null
{
    assertNotNull(name, "Parameter name must be non-null");

//by wschoi
    CCNxTlvDictionary *dictionary = ccnxCodecSchemaV1TlvDictionary_CreateContentObject();

    if (dictionary) {
        ccnxTlvDictionary_PutName(dictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME, name);

        if (payloadType != CCNxPayloadType_DATA) {
            ccnxTlvDictionary_PutInteger(dictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_PAYLOADTYPE, payloadType);
        }
//by wschoi
        if (payload) {
            ccnxTlvDictionary_PutBuffer(dictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_PAYLOAD_GETNAME, payload);
        }
    } else {
        trapOutOfMemory("Could not allocate ContentObject");
    }
    uint16_t type=0x0112;
    ccnxTlvDictionary_SetLookupType(dictionary, type);
    return dictionary;
}

//REGISTRATION
//reg
static CCNxTlvDictionary *
_ccnxContentObjectFacadeV1_CreateWithNameAndPayload_reg_ack(const CCNxName *name,              // required
                                                    const CCNxPayloadType payloadType, // required
                                                    const PARCBuffer *payload)         // may be null
{
#ifdef LOG_CHECK
			printf("_ccnxContentObjectFacadeV1_CreateWithNameAndPayload_reg_ack(), start\n");
#endif
    assertNotNull(name, "Parameter name must be non-null");

    CCNxTlvDictionary *dictionary = ccnxCodecSchemaV1TlvDictionary_CreateContentObject();

    if (dictionary) {
        ccnxTlvDictionary_PutName(dictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME, name);

        if (payloadType != CCNxPayloadType_DATA) {
            ccnxTlvDictionary_PutInteger(dictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_PAYLOADTYPE, payloadType);
        }
        if (payload) {
#ifdef LOG_CHECK
			printf("_ccnxContentObjectFacadeV1_CreateWithNameAndPayload_reg_ack()\n");
#endif
            ccnxTlvDictionary_PutBuffer(dictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME_REG_ACK, payload);
        }
    } else {
        trapOutOfMemory("Could not allocate ContentObject");
    }

    uint16_t type=0x0116;
    ccnxTlvDictionary_SetLookupType(dictionary, type);
    return dictionary;
}

//add
static CCNxTlvDictionary *
_ccnxContentObjectFacadeV1_CreateWithNameAndPayload_reg_add_ack(const CCNxName *name,              // required
                                                    const CCNxPayloadType payloadType, // required
                                                    const PARCBuffer *payload)         // may be null
{
#ifdef LOG_CHECK
			printf("_ccnxContentObjectFacadeV1_CreateWithNameAndPayload_reg_add_ack(), start\n");
#endif
    assertNotNull(name, "Parameter name must be non-null");

    CCNxTlvDictionary *dictionary = ccnxCodecSchemaV1TlvDictionary_CreateContentObject();

    if (dictionary) {
        ccnxTlvDictionary_PutName(dictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME, name);

        if (payloadType != CCNxPayloadType_DATA) {
            ccnxTlvDictionary_PutInteger(dictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_PAYLOADTYPE, payloadType);
        }
        if (payload) {
#ifdef LOG_CHECK
			printf("_ccnxContentObjectFacadeV1_CreateWithNameAndPayload_reg_add_ack()\n");
#endif
            ccnxTlvDictionary_PutBuffer(dictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME_ADD_ACK, payload);
        }
    } else {
        trapOutOfMemory("Could not allocate ContentObject");
    }

    uint16_t type=0x0119;
    ccnxTlvDictionary_SetLookupType(dictionary, type);
    return dictionary;
}

//del
static CCNxTlvDictionary *
_ccnxContentObjectFacadeV1_CreateWithNameAndPayload_reg_del_ack(const CCNxName *name,              // required
                                                    const CCNxPayloadType payloadType, // required
                                                    const PARCBuffer *payload)         // may be null
{
#ifdef LOG_CHECK
			printf("_ccnxContentObjectFacadeV1_CreateWithNameAndPayload_reg_del_ack(), start\n");
#endif
    assertNotNull(name, "Parameter name must be non-null");

    CCNxTlvDictionary *dictionary = ccnxCodecSchemaV1TlvDictionary_CreateContentObject();

    if (dictionary) {
        ccnxTlvDictionary_PutName(dictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME, name);

        if (payloadType != CCNxPayloadType_DATA) {
            ccnxTlvDictionary_PutInteger(dictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_PAYLOADTYPE, payloadType);
        }
        if (payload) {
#ifdef LOG_CHECK
			printf("_ccnxContentObjectFacadeV1_CreateWithNameAndPayload_reg_del_ack()\n");
#endif
            ccnxTlvDictionary_PutBuffer(dictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME_DEL_ACK, payload);
        }
    } else {
        trapOutOfMemory("Could not allocate ContentObject");
    }

    uint16_t type=0x0122;
    ccnxTlvDictionary_SetLookupType(dictionary, type);
    return dictionary;
}

//dereg
static CCNxTlvDictionary *
_ccnxContentObjectFacadeV1_CreateWithNameAndPayload_reg_dereg_ack(const CCNxName *name,              // required
                                                    const CCNxPayloadType payloadType, // required
                                                    const PARCBuffer *payload)         // may be null
{
#ifdef LOG_CHECK
			printf("_ccnxContentObjectFacadeV1_CreateWithNameAndPayload_reg_dereg_ack(), start\n");
#endif
    assertNotNull(name, "Parameter name must be non-null");

    CCNxTlvDictionary *dictionary = ccnxCodecSchemaV1TlvDictionary_CreateContentObject();

    if (dictionary) {
        ccnxTlvDictionary_PutName(dictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME, name);

        if (payloadType != CCNxPayloadType_DATA) {
            ccnxTlvDictionary_PutInteger(dictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_PAYLOADTYPE, payloadType);
        }
        if (payload) {
#ifdef LOG_CHECK
			printf("_ccnxContentObjectFacadeV1_CreateWithNameAndPayload_reg_dereg_ack()\n");
#endif
            ccnxTlvDictionary_PutBuffer(dictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME_DEREG_ACK, payload);
        }
    } else {
        trapOutOfMemory("Could not allocate ContentObject");
    }

    uint16_t type=0x0125;
    ccnxTlvDictionary_SetLookupType(dictionary, type);
    return dictionary;
}



static CCNxTlvDictionary *
_ccnxContentObjectFacadeV1_CreateWithNameAndPayload(const CCNxName *name,              // required
                                                    const CCNxPayloadType payloadType, // required
                                                    const PARCBuffer *payload)         // may be null
{
    assertNotNull(name, "Parameter name must be non-null");

    CCNxTlvDictionary *dictionary = ccnxCodecSchemaV1TlvDictionary_CreateContentObject();

    if (dictionary) {
        ccnxTlvDictionary_PutName(dictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME, name);

        if (payloadType != CCNxPayloadType_DATA) {
            ccnxTlvDictionary_PutInteger(dictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_PAYLOADTYPE, payloadType);
        }
        if (payload) {
            ccnxTlvDictionary_PutBuffer(dictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_PAYLOAD, payload);
        }
    } else {
        trapOutOfMemory("Could not allocate ContentObject");
    }

    return dictionary;
}




static CCNxTlvDictionary *
_ccnxContentObjectFacadeV1_CreateWithPayload(const CCNxPayloadType payloadType, // required
                                             const PARCBuffer *payload)         // may be null
{
    CCNxTlvDictionary *dictionary = ccnxCodecSchemaV1TlvDictionary_CreateContentObject();

    if (dictionary) {
        if (payloadType != CCNxPayloadType_DATA) {
            ccnxTlvDictionary_PutInteger(dictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_PAYLOADTYPE, payloadType);
        }

        if (payload) {
            ccnxTlvDictionary_PutBuffer(dictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_PAYLOAD, payload);
        }
    } else {
        trapOutOfMemory("Could not allocate ContentObject");
    }

    return dictionary;
}

// =========================
// Getters

static CCNxName *
_ccnxContentObjectFacadeV1_GetName(const CCNxTlvDictionary *contentObjectDictionary)
{
    _assertInvariants(contentObjectDictionary);
    return ccnxTlvDictionary_GetName(contentObjectDictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME);
}

static bool
_ccnxContentObjectFacadeV1_HasExpiryTime(const CCNxTlvDictionary *packetDictionary)
{
    if (ccnxTlvDictionary_IsValueInteger(packetDictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_EXPIRY_TIME)) {
        return true;
    }
    return false;
}

static uint64_t
_ccnxContentObjectFacadeV1_GetExpiryTime(const CCNxTlvDictionary *packetDictionary)
{
    if (ccnxTlvDictionary_IsValueInteger(packetDictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_EXPIRY_TIME)) {
        return ccnxTlvDictionary_GetInteger(packetDictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_EXPIRY_TIME);
    }
    trapUnexpectedState("The dictionary does not contain an Expiry Time");
}

static bool
_ccnxContentObjectFacadeV1_HasPathLabel(const CCNxTlvDictionary *packetDictionary)
{
    if (ccnxTlvDictionary_IsValueInteger(packetDictionary, CCNxCodecSchemaV1TlvDictionary_HeadersFastArray_PathLabel)) {
        return true;
    }
    return false;
}


static uint64_t
_ccnxContentObjectFacadeV1_GetPathLabel(const CCNxTlvDictionary *packetDictionary)
{
    if (ccnxTlvDictionary_IsValueInteger(packetDictionary, CCNxCodecSchemaV1TlvDictionary_HeadersFastArray_PathLabel)) {
        return ccnxTlvDictionary_GetInteger(packetDictionary, CCNxCodecSchemaV1TlvDictionary_HeadersFastArray_PathLabel);
    }
    trapUnexpectedState("The dictionary does not contain a Path Label");
}

static PARCBuffer *
_ccnxContentObjectFacadeV1_GetPayload(const CCNxTlvDictionary *contentObjectDictionary)
{
    _assertInvariants(contentObjectDictionary);
    return ccnxTlvDictionary_GetBuffer(contentObjectDictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_PAYLOAD);
}

//by wschoi
	static PARCBuffer *
_ccnxContentObjectFacadeV1_GetPayload_lookup(const CCNxTlvDictionary *contentObjectDictionary)
{

	printf("#################################_ccnxContentObjectFacadeV1_GetPayload_lookup###############\n\n");
    _assertInvariants(contentObjectDictionary);
    return ccnxTlvDictionary_GetBuffer(contentObjectDictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_PAYLOAD_GETNAME);
}



static CCNxPayloadType
_ccnxContentObjectFacadeV1_GetPayloadType(const CCNxTlvDictionary *contentObjectDictionary)
{
    CCNxPayloadType result = CCNxPayloadType_DATA;

    _assertInvariants(contentObjectDictionary);
    if (ccnxTlvDictionary_IsValueInteger(contentObjectDictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_PAYLOADTYPE)) {
        result = (CCNxPayloadType) ccnxTlvDictionary_GetInteger(contentObjectDictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_PAYLOADTYPE);
    }

    return result;
}

// =========================
// Setters

static bool
_ccnxContentObjectFacadeV1_SetSignature(CCNxTlvDictionary *contentObject, const PARCBuffer *keyId,
                                        const PARCSignature *signature, const CCNxKeyLocator *keyLocator)
{
    bool result = false;

    CCNxTlvDictionary *contentObjectDictionary = (CCNxTlvDictionary *) contentObject;

    if (parcSignature_GetSigningAlgorithm(signature) == PARCSigningAlgorithm_RSA
        && parcSignature_GetHashType(signature) == PARCCryptoHashType_SHA256) {
        ccnxValidationRsaSha256_Set(contentObjectDictionary, keyId, keyLocator);
    } else if (parcSignature_GetSigningAlgorithm(signature) == PARCSigningAlgorithm_HMAC
               && parcSignature_GetHashType(signature) == PARCCryptoHashType_SHA256) {
        ccnxValidationHmacSha256_Set(contentObjectDictionary, keyId);
    } else {
        trapNotImplemented("Have not implemented the signature parameters");
    }

    PARCBuffer *sigbits = parcSignature_GetSignature(signature);

    result = ccnxValidationFacadeV1_SetPayload(contentObjectDictionary, sigbits);

    return result;
}

static PARCBuffer *
_ccnxContentObjectFacadeV1_GetKeyId(const CCNxTlvDictionary *contentObject)
{
    return ccnxValidationFacadeV1_GetKeyId(contentObject);
}

static bool
_ccnxContentObjectFacadeV1_SetExpiryTime(CCNxTlvDictionary *contentObjectDictionary, uint64_t expiryTime)
{
    bool success = ccnxTlvDictionary_PutInteger(contentObjectDictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_EXPIRY_TIME, expiryTime);
    trapUnexpectedStateIf(!success, "Could not set integer in dictionary");
    return success;
}

static bool
_ccnxContentObjectFacadeV1_SetPathLabel(CCNxTlvDictionary *contentObjectDictionary, uint64_t pathLabel)
{
    bool success = ccnxTlvDictionary_PutInteger(contentObjectDictionary, CCNxCodecSchemaV1TlvDictionary_HeadersFastArray_PathLabel, pathLabel);
    trapUnexpectedStateIf(!success, "Could not set integer in dictionary (path label)");
    return success;
}

static bool
_ccnxContentObjectFacadeV1_SetPayload(CCNxTlvDictionary *contentObjectDictionary, CCNxPayloadType payloadType, const PARCBuffer *payload)
{
    bool result = false;

    if (payload != NULL) {
        PARCBuffer *originalPayload = _ccnxContentObjectFacadeV1_GetPayload(contentObjectDictionary);

        result = ccnxTlvDictionary_PutBuffer(contentObjectDictionary,
                                             CCNxCodecSchemaV1TlvDictionary_MessageFastArray_PAYLOAD, payload);

        if (result) {
            if (_ccnxContentObjectFacadeV1_GetPayloadType(contentObjectDictionary) != payloadType) {
                ccnxTlvDictionary_PutInteger(contentObjectDictionary,
                                             CCNxCodecSchemaV1TlvDictionary_MessageFastArray_PAYLOADTYPE, payloadType);
            }

            if (originalPayload != NULL) {
                parcBuffer_Release(&originalPayload);
            }
        }
    }

    return result;
}

// =========================
// Miscellaneous functions

static bool
_ccnxContentObjectFacadeV1_Equals(const CCNxTlvDictionary *objectA, const CCNxTlvDictionary *objectB)
{
    return ccnxTlvDictionary_Equals(objectA, objectB);
}

static char *
_ccnxContentObjectFacadeV1_ToString(const CCNxTlvDictionary *contentObjectDictionary)
{
    trapNotImplemented("_ccnxContentObjectFacadeV1_ToString(): not yet implemented");
}

static void
_ccnxContentObjectFacadeV1_Display(const CCNxTlvDictionary *contentObjectDictionary, size_t indentation)
{
    _assertInvariants(contentObjectDictionary);
    ccnxTlvDictionary_Display(contentObjectDictionary, (unsigned) indentation);
}

/**
 * `CCNxContentObjectFacadeV1_Implementation` is the structure containing the pointers to the
 * V1 schema ContentObject implementation.
 */
CCNxContentObjectInterface CCNxContentObjectFacadeV1_Implementation = {
    .description              = "CCNxContentObjectFacadeV1_Implementation",

    .createWithNameAndPayload = &_ccnxContentObjectFacadeV1_CreateWithNameAndPayload,


    //by wschoi
	//LOOKUP
	.createWithNameAndPayload_lookup = &_ccnxContentObjectFacadeV1_CreateWithNameAndPayload_lookup,

	//REGISTRATION
	//reg
	.createWithNameAndPayload_reg_ack = &_ccnxContentObjectFacadeV1_CreateWithNameAndPayload_reg_ack,

//add
	.createWithNameAndPayload_reg_add_ack = &_ccnxContentObjectFacadeV1_CreateWithNameAndPayload_reg_add_ack,

	//del
	.createWithNameAndPayload_reg_del_ack = &_ccnxContentObjectFacadeV1_CreateWithNameAndPayload_reg_del_ack,

	//dereg
	.createWithNameAndPayload_reg_dereg_ack = &_ccnxContentObjectFacadeV1_CreateWithNameAndPayload_reg_dereg_ack,

    .createWithPayload        = &_ccnxContentObjectFacadeV1_CreateWithPayload,
    .setSignature             = &_ccnxContentObjectFacadeV1_SetSignature,
    .getKeyId                 = &_ccnxContentObjectFacadeV1_GetKeyId,

    .getName                  = &_ccnxContentObjectFacadeV1_GetName,
    .getPayload               = &_ccnxContentObjectFacadeV1_GetPayload,
	//by wschoi
    .getPayload_lookup               = &_ccnxContentObjectFacadeV1_GetPayload_lookup,


    .setPayload               = &_ccnxContentObjectFacadeV1_SetPayload,
    .getPayloadType           = &_ccnxContentObjectFacadeV1_GetPayloadType,

    .getFinalChunkNumber      = &ccnxChunkingFacadeV1_GetEndChunkNumber,
    .setFinalChunkNumber      = &ccnxChunkingFacadeV1_SetEndChunkNumber,
    .hasFinalChunkNumber      = &ccnxChunkingFacadeV1_HasEndChunkNumber,

    .getExpiryTime            = &_ccnxContentObjectFacadeV1_GetExpiryTime,
    .setExpiryTime            = &_ccnxContentObjectFacadeV1_SetExpiryTime,
    .hasExpiryTime            = &_ccnxContentObjectFacadeV1_HasExpiryTime,

    .getPathLabel             = &_ccnxContentObjectFacadeV1_GetPathLabel,
    .setPathLabel             = &_ccnxContentObjectFacadeV1_SetPathLabel,
    .hasPathLabel             = &_ccnxContentObjectFacadeV1_HasPathLabel,

    .toString                 = &_ccnxContentObjectFacadeV1_ToString,
    .display                  = &_ccnxContentObjectFacadeV1_Display,
    .equals                   = &_ccnxContentObjectFacadeV1_Equals,

    .assertValid              = &_assertInvariants,
};
