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
#include <parc/algol/parc_Buffer.h>

#include <ccnx/common/ccnx_PayloadType.h>
#include <ccnx/common/ccnx_InterestReturn.h>

#include <ccnx/common/codec/schema_v1/ccnxCodecSchemaV1_ManifestEncoder.h>
#include <ccnx/common/codec/schema_v1/ccnxCodecSchemaV1_MessageEncoder.h>
#include <ccnx/common/codec/schema_v1/ccnxCodecSchemaV1_NameCodec.h>
#include <ccnx/common/codec/schema_v1/ccnxCodecSchemaV1_HashCodec.h>
#include <ccnx/common/codec/schema_v1/ccnxCodecSchemaV1_Types.h>

#include <ccnx/common/codec/ccnxCodec_TlvUtilities.h>

#include <ccnx/common/ccnx_Manifest.h>
#include <ccnx/common/ccnx_ManifestHashGroup.h>

//by wschoi
#include <ccnx/common/internal/ccnx_TlvDictionary.h>

//#define LOG_CHECK

	static ssize_t
_encodeName(CCNxCodecTlvEncoder *encoder, CCNxTlvDictionary *packetDictionary)
{
	ssize_t length = -1;
	CCNxName *name = ccnxTlvDictionary_GetName(packetDictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME);
	if (name != NULL) {
		length = ccnxCodecSchemaV1NameCodec_Encode(encoder, CCNxCodecSchemaV1Types_CCNxMessage_Name, name);
	}

	// required field for everything except CCNxContentObjects
	if (!ccnxTlvDictionary_IsContentObject(packetDictionary) && length < 0) {
		CCNxCodecError *error = ccnxCodecError_Create(TLV_MISSING_MANDATORY, __func__, __LINE__, ccnxCodecTlvEncoder_Position(encoder));
		ccnxCodecTlvEncoder_SetError(encoder, error);
		ccnxCodecError_Release(&error);
	} else if (ccnxTlvDictionary_IsContentObject(packetDictionary) && name == NULL) {
		length = 0;
	}

	return length;
}

	static ssize_t
_encodeJsonPayload(CCNxCodecTlvEncoder *encoder, CCNxTlvDictionary *packetDictionary)
{
	ssize_t length = 0;
	PARCJSON *json = ccnxTlvDictionary_GetJson(packetDictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_PAYLOAD);
	if (json != NULL) {
		char *jsonString = parcJSON_ToCompactString(json);
		size_t len = strlen(jsonString);
		length = ccnxCodecTlvEncoder_AppendArray(encoder, CCNxCodecSchemaV1Types_CCNxMessage_Payload, len, (uint8_t *) jsonString);
	}
	return length;
}

//by wschoi

//refresh
#if 0
	static ssize_t
_encodePayload_refresh(CCNxCodecTlvEncoder *encoder, CCNxTlvDictionary *packetDictionary)
{
	ssize_t length = 0;
	ssize_t result = 0;
	if(ccnxTlvDictionary_IsInterest(packetDictionary))
	{

		PARCBuffer *buffer_refresh_key = ccnxTlvDictionary_GetBuffer(packetDictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME_REFRESH_KEY);
		//by wschoi
		PARCBuffer *buffer_refresh_value = ccnxTlvDictionary_GetBuffer(packetDictionary,CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME_REFRESH_VALUE);

		printf("_encodePayload_refresh()\n");
		parcBuffer_Display(buffer_refresh_key, 0);
		parcBuffer_Display(buffer_refresh_value, 0);

		if (buffer_refresh_key != NULL) 
		{
			//by wschoi

			result = ccnxCodecTlvEncoder_AppendBuffer(encoder, CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_REFRESH_KeyName, buffer_refresh_key);
			length=result+length;
			if (buffer_refresh_value != NULL) 
			{
				result = ccnxCodecTlvEncoder_AppendBuffer(encoder, CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_REFRESH_ValueName, buffer_refresh_value);
				length=result+length;

			}

		}
	}
	printf("_encodePayload_refresh(), length=%d\n", length);

	return length;

}
#endif

//dereg
#if 1
	static ssize_t
_encodePayload_registration_dereg(CCNxCodecTlvEncoder *encoder, CCNxTlvDictionary *packetDictionary)
{
	ssize_t length = 0;
	ssize_t result = 0;
	if(ccnxTlvDictionary_IsInterest(packetDictionary))
	{

		PARCBuffer *buffer_dereg_key = ccnxTlvDictionary_GetBuffer(packetDictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME_DEREG_KEY);
		//by wschoi
		PARCBuffer *buffer_dereg_value = ccnxTlvDictionary_GetBuffer(packetDictionary,CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME_DEREG_VALUE);
#ifdef LOG_CHECK
		printf("_encodePayload__registration_dereg()\n");
		parcBuffer_Display(buffer_dereg_key, 0);
		parcBuffer_Display(buffer_dereg_value, 0);
#endif

		if (buffer_dereg_key != NULL) 
		{
			//by wschoi

			result = ccnxCodecTlvEncoder_AppendBuffer(encoder, CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_DEREG_KeyName, buffer_dereg_key);
			length = result + length;
			if (buffer_dereg_value != NULL) 
			{
				result = ccnxCodecTlvEncoder_AppendBuffer(encoder, CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_DEREG_ValueName, buffer_dereg_value);
				length=result+length;

			}

		}
	}
#ifdef LOG_CHECK
	printf("_encodePayload_registration_dereg(), length=%d\n", length);
#endif
	return length;

}
#endif

//del
#if 1
	static ssize_t
_encodePayload_registration_del(CCNxCodecTlvEncoder *encoder, CCNxTlvDictionary *packetDictionary)
{
	ssize_t length = 0;
	ssize_t result = 0;
	if(ccnxTlvDictionary_IsInterest(packetDictionary))
	{

		PARCBuffer *buffer_del_key = ccnxTlvDictionary_GetBuffer(packetDictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME_DEL_KEY);
		//by wschoi
		PARCBuffer *buffer_del_value = ccnxTlvDictionary_GetBuffer(packetDictionary,CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME_DEL_VALUE);

#ifdef LOG_CHECK
		printf("_encodePayload_registration_del()\n");
		parcBuffer_Display(buffer_del_key, 0);
		parcBuffer_Display(buffer_del_value, 0);
#endif
		if (buffer_del_key != NULL) 
		{
			//by wschoi

			result = ccnxCodecTlvEncoder_AppendBuffer(encoder, CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_DEL_KeyName, buffer_del_key);
			length = result + length;
			if (buffer_del_value != NULL) 
			{
				result = ccnxCodecTlvEncoder_AppendBuffer(encoder, CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_DEL_ValueName, buffer_del_value);
				length = result + length;

			}

		}
	}

#ifdef LOG_CHECK
	printf("_encodePayload_registration_del(), length=%d\n", length);
#endif

	return length;

}
#endif

#if 1
//add
	static ssize_t
_encodePayload_registration_add(CCNxCodecTlvEncoder *encoder, CCNxTlvDictionary *packetDictionary)
{
	ssize_t length = 0;
	ssize_t result = 0;
	if(ccnxTlvDictionary_IsInterest(packetDictionary))
	{

		PARCBuffer *buffer_add_key = ccnxTlvDictionary_GetBuffer(packetDictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME_ADD_KEY);
		//by wschoi
		PARCBuffer *buffer_add_value = ccnxTlvDictionary_GetBuffer(packetDictionary,CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME_ADD_VALUE);

#ifdef LOG_CHECK
		printf("_encodePayload_registration_add()\n");
		parcBuffer_Display(buffer_add_key, 0);
		parcBuffer_Display(buffer_add_value, 0);
#endif

		if (buffer_add_key != NULL) 
		{
			//by wschoi

			result = ccnxCodecTlvEncoder_AppendBuffer(encoder, CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_ADD_KeyName, buffer_add_key);
			length = result + length;
			if (buffer_add_value != NULL) 
			{
				result = ccnxCodecTlvEncoder_AppendBuffer(encoder, CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_ADD_ValueName, buffer_add_value);
				length = result + length;

			}

		}
	}

#ifdef LOG_CHECK
	printf("_encodePayload_registration_add(), length=%d\n", length);
#endif

	return length;

}
#endif

//registration
#if 1
	static ssize_t
_encodePayload_registration(CCNxCodecTlvEncoder *encoder, CCNxTlvDictionary *packetDictionary)
{
	ssize_t length = 0;
	ssize_t result = 0;
	if(ccnxTlvDictionary_IsInterest(packetDictionary))
	{

		PARCBuffer *buffer_reg_key = ccnxTlvDictionary_GetBuffer(packetDictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME_REG_KEY);
		//by wschoi
		PARCBuffer *buffer_reg_value = ccnxTlvDictionary_GetBuffer(packetDictionary,CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME_REG_VALUE);
#ifdef LOG_CHECK
		printf("_encodePayload_registration()\n");
		parcBuffer_Display(buffer_reg_key, 0);
		parcBuffer_Display(buffer_reg_value, 0);
#endif
		if (buffer_reg_key != NULL) 
		{
			//by wschoi

			result = ccnxCodecTlvEncoder_AppendBuffer(encoder, CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_REGISTRATION_KeyName, buffer_reg_key);
			length = result + length;
			if (buffer_reg_value != NULL) 
			{
				result = ccnxCodecTlvEncoder_AppendBuffer(encoder, CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_REGISTRATION_ValueName, buffer_reg_value);
				length = result + length;

			}

		}
	}
#ifdef LOG_CHECK
	printf("_encodePayload_registration(), length=%d\n", length);
#endif

	return length;

}
#endif


//registration ack
#if 1
	static ssize_t
_encodePayload_registration_ack(CCNxCodecTlvEncoder *encoder, CCNxTlvDictionary *packetDictionary)
{
	ssize_t length = 0;
	ssize_t result = 0;
	if(ccnxTlvDictionary_IsContentObject(packetDictionary))
	{

		PARCBuffer *buffer_reg_ack = ccnxTlvDictionary_GetBuffer(packetDictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME_REG_ACK);

#ifdef LOG_CHECK
		printf("_encodePayload_registration_ack()\n");
		parcBuffer_Display(buffer_reg_ack, 0);
#endif
		if (buffer_reg_ack != NULL) 
		{
			//by wschoi

			result = ccnxCodecTlvEncoder_AppendBuffer(encoder, CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_REGISTRATION_ACK, buffer_reg_ack);
			length = result + length;

		}
	}
#ifdef LOG_CHECK
	printf("_encodePayload_registration()_ack, length=%d\n", length);
#endif
	return length;

}
#endif


//registration add ack
#if 1
	static ssize_t
_encodePayload_registration_add_ack(CCNxCodecTlvEncoder *encoder, CCNxTlvDictionary *packetDictionary)
{
	ssize_t length = 0;
	ssize_t result = 0;
	if(ccnxTlvDictionary_IsContentObject(packetDictionary))
	{

		PARCBuffer *buffer_reg_add_ack = ccnxTlvDictionary_GetBuffer(packetDictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME_ADD_ACK);

#ifdef LOG_CHECK
		printf("_encodePayload_registration_add_ack()\n");
		parcBuffer_Display(buffer_reg_add_ack, 0);
#endif
		if (buffer_reg_add_ack != NULL) 
		{
			//by wschoi

			result = ccnxCodecTlvEncoder_AppendBuffer(encoder, CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_ADD_ACK, buffer_reg_add_ack);
			length = result + length;

		}
	}
#ifdef LOG_CHECK
	printf("_encodePayload_registration()_add_ack, length=%d\n", length);
#endif
	return length;

}
#endif


//registration del ack
#if 1
	static ssize_t
_encodePayload_registration_del_ack(CCNxCodecTlvEncoder *encoder, CCNxTlvDictionary *packetDictionary)
{
	ssize_t length = 0;
	ssize_t result = 0;
	if(ccnxTlvDictionary_IsContentObject(packetDictionary))
	{

		PARCBuffer *buffer_reg_del_ack = ccnxTlvDictionary_GetBuffer(packetDictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME_DEL_ACK);

#ifdef LOG_CHECK
		printf("_encodePayload_registration_del_ack()\n");
		parcBuffer_Display(buffer_reg_del_ack, 0);
#endif
		if (buffer_reg_del_ack != NULL) 
		{
			//by wschoi

			result = ccnxCodecTlvEncoder_AppendBuffer(encoder, CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_DEL_ACK, buffer_reg_del_ack);
			length = result + length;

		}
	}
#ifdef LOG_CHECK
	printf("_encodePayload_registration()_del_ack, length=%d\n", length);
#endif
	return length;

}
#endif


//registration dereg ack
#if 1
	static ssize_t
_encodePayload_registration_dereg_ack(CCNxCodecTlvEncoder *encoder, CCNxTlvDictionary *packetDictionary)
{
	ssize_t length = 0;
	ssize_t result = 0;
	if(ccnxTlvDictionary_IsContentObject(packetDictionary))
	{

		PARCBuffer *buffer_reg_dereg_ack = ccnxTlvDictionary_GetBuffer(packetDictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_NAME_DEREG_ACK);

#ifdef LOG_CHECK
		printf("_encodePayload_registration_dereg_ack()\n");
		parcBuffer_Display(buffer_reg_dereg_ack, 0);
#endif
		if (buffer_reg_dereg_ack != NULL) 
		{
			//by wschoi

			result = ccnxCodecTlvEncoder_AppendBuffer(encoder, CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_DEREG_ACK, buffer_reg_dereg_ack);
			length = result + length;

		}
	}
#ifdef LOG_CHECK
	printf("_encodePayload_registration()_dereg_ack, length=%d\n", length);
#endif
	return length;

}
#endif


//by wschoi
#if 1
	static ssize_t
_encodePayload_lookup(CCNxCodecTlvEncoder *encoder, CCNxTlvDictionary *packetDictionary)
{

	ssize_t length = 0;
	if(ccnxTlvDictionary_IsInterest(packetDictionary))
	{

		PARCBuffer *buffer = ccnxTlvDictionary_GetBuffer(packetDictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_GETNAME);
		if (buffer != NULL) {

			length = ccnxCodecTlvEncoder_AppendBuffer(encoder, CCNxCodecSchemaV1Types_CCNxMessage_T_GETNAME, buffer);
		}
	}
	else if(ccnxTlvDictionary_IsContentObject(packetDictionary))
	{

		PARCBuffer *buffer = ccnxTlvDictionary_GetBuffer(packetDictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_PAYLOAD_GETNAME);
		if (buffer != NULL) {

			length = ccnxCodecTlvEncoder_AppendBuffer(encoder, CCNxCodecSchemaV1Types_CCNxMessage_T_PAYLOAD_GETNAME, buffer);

		}
	}

	return length;

}

#endif

	static ssize_t
_encodePayload(CCNxCodecTlvEncoder *encoder, CCNxTlvDictionary *packetDictionary)
{
	ssize_t length = 0;
	if(ccnxTlvDictionary_IsInterest(packetDictionary))
	{

		PARCBuffer *buffer = ccnxTlvDictionary_GetBuffer(packetDictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_PAYLOAD);
		if (buffer != NULL) {

			length = ccnxCodecTlvEncoder_AppendBuffer(encoder, CCNxCodecSchemaV1Types_CCNxMessage_Payload, buffer);
		}
	}
	else if(ccnxTlvDictionary_IsContentObject(packetDictionary))
	{

		PARCBuffer *buffer = ccnxTlvDictionary_GetBuffer(packetDictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_PAYLOAD);
		if (buffer != NULL) {
			length = ccnxCodecTlvEncoder_AppendBuffer(encoder, CCNxCodecSchemaV1Types_CCNxMessage_Payload, buffer);

		}
		else
		{
		}
	}

	return length;
}

	static ssize_t
_encodePayloadType(CCNxCodecTlvEncoder *encoder, CCNxTlvDictionary *packetDictionary)
{
	ssize_t length = 0;
	if (ccnxTlvDictionary_IsValueInteger(packetDictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_PAYLOADTYPE)) {
		CCNxPayloadType payloadType = (CCNxPayloadType) ccnxTlvDictionary_GetInteger(packetDictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_PAYLOADTYPE);

		CCNxCodecSchemaV1Types_PayloadType wireFormatType = CCNxCodecSchemaV1Types_PayloadType_Data;

		switch (payloadType) {
			case CCNxPayloadType_KEY:
				wireFormatType = CCNxCodecSchemaV1Types_PayloadType_Key;
				break;

			case CCNxPayloadType_LINK:
				wireFormatType = CCNxCodecSchemaV1Types_PayloadType_Link;
				break;

			default:
				// anything else is encoded as DATA
				break;
		}

		length = ccnxCodecTlvEncoder_AppendUint8(encoder, CCNxCodecSchemaV1Types_CCNxMessage_PayloadType, wireFormatType);
	} else if (ccnxTlvDictionary_IsValueBuffer(packetDictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_PAYLOADTYPE)) {
		PARCBuffer *buffer = ccnxTlvDictionary_GetBuffer(packetDictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_PAYLOADTYPE);
		length = ccnxCodecTlvEncoder_AppendBuffer(encoder, CCNxCodecSchemaV1Types_CCNxMessage_PayloadType, buffer);
	}

	return length;
}

	static ssize_t
_encodeExpiryTime(CCNxCodecTlvEncoder *encoder, CCNxTlvDictionary *packetDictionary)
{
	ssize_t length = 0;
	if (ccnxTlvDictionary_IsValueInteger(packetDictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_EXPIRY_TIME)) {
		uint64_t millis = ccnxTlvDictionary_GetInteger(packetDictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_EXPIRY_TIME);
		length = ccnxCodecTlvEncoder_AppendUint64(encoder, CCNxCodecSchemaV1Types_CCNxMessage_ExpiryTime, millis);
	} else if (ccnxTlvDictionary_IsValueBuffer(packetDictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_EXPIRY_TIME)) {
		PARCBuffer *buffer = ccnxTlvDictionary_GetBuffer(packetDictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_EXPIRY_TIME);
		length = ccnxCodecTlvEncoder_AppendBuffer(encoder, CCNxCodecSchemaV1Types_CCNxMessage_ExpiryTime, buffer);
	}

	return length;
}

	static ssize_t
_encodeEndChunkNumber(CCNxCodecTlvEncoder *encoder, CCNxTlvDictionary *packetDictionary)
{
	ssize_t length = 0;
	if (ccnxTlvDictionary_IsValueInteger(packetDictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_ENDSEGMENT)) {
		uint64_t endChunkId = ccnxTlvDictionary_GetInteger(packetDictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_ENDSEGMENT);
		length = ccnxCodecTlvEncoder_AppendVarInt(encoder, CCNxCodecSchemaV1Types_CCNxMessage_EndChunkNumber, endChunkId);
	} else {
		PARCBuffer *buffer = ccnxTlvDictionary_GetBuffer(packetDictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_ENDSEGMENT);
		if (buffer != NULL) {
			length = ccnxCodecTlvEncoder_AppendBuffer(encoder, CCNxCodecSchemaV1Types_CCNxMessage_EndChunkNumber, buffer);
		}
	}
	return length;
}

	static ssize_t
_encodeKeyIdRestriction(CCNxCodecTlvEncoder *encoder, CCNxTlvDictionary *packetDictionary)
{
	ssize_t length = 0;
	PARCCryptoHash *hash = ccnxTlvDictionary_GetObject(packetDictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_KEYID_RESTRICTION);
	if (hash != NULL) {
		size_t startPosition = ccnxCodecTlvEncoder_Position(encoder);
		ccnxCodecTlvEncoder_AppendContainer(encoder, CCNxCodecSchemaV1Types_CCNxMessage_KeyIdRestriction, 0);
		length = ccnxCodecSchemaV1HashCodec_Encode(encoder, hash);
		if (length < 0) {
			return length;
		}

		ccnxCodecTlvEncoder_SetContainerLength(encoder, startPosition, length);
		length += 4; // this accounts for the TL fields
	}
	return length;
}

	static ssize_t
_encodeContentObjectHashRestriction(CCNxCodecTlvEncoder *encoder, CCNxTlvDictionary *packetDictionary)
{
	ssize_t length = 0;
	PARCCryptoHash *hash = ccnxTlvDictionary_GetObject(packetDictionary, CCNxCodecSchemaV1TlvDictionary_MessageFastArray_OBJHASH_RESTRICTION);
	if (hash != NULL) {
		size_t startPosition = ccnxCodecTlvEncoder_Position(encoder);
		ccnxCodecTlvEncoder_AppendContainer(encoder, CCNxCodecSchemaV1Types_CCNxMessage_ContentObjectHashRestriction, 0);
		length = ccnxCodecSchemaV1HashCodec_Encode(encoder, hash);
		if (length < 0) {
			return length;
		}

		ccnxCodecTlvEncoder_SetContainerLength(encoder, startPosition, length);
		length += 4; // this accounts for the TL fields
	}
	return length;
}


	static ssize_t
_encodeContentObject(CCNxCodecTlvEncoder *encoder, CCNxTlvDictionary *packetDictionary)
{

	ssize_t length = 0;
	ssize_t result;


	//by wschoi
	uint16_t lookupType=ccnxTlvDictionary_CheckLookupType(packetDictionary);
#ifdef LOG_CHECK
	printf("_encodeContentObject(), lookupType : %x\n\n",lookupType);
#endif


	result = _encodeName(encoder, packetDictionary);
	if (result < 0) {
		return result;
	}
	length += result;

	result = _encodePayloadType(encoder, packetDictionary);
	if (result < 0) {
		return result;
	}
	length += result;

	result = _encodeExpiryTime(encoder, packetDictionary);
	if (result < 0) {
		return result;
	}
	length += result;

	result = _encodeEndChunkNumber(encoder, packetDictionary);
	if (result < 0) {
		return result;
	}
	length += result;


	//by wschoi

#ifdef LOG_CHECK
	printf("_encodeContentObject(), lookuptype: ccnxTlvDictionary_CheckLookupType : %x\n\n",lookupType);
#endif

	if(lookupType == CCNxCodecSchemaV1Types_CCNxMessage_T_GETNAME|| lookupType== CCNxCodecSchemaV1Types_CCNxMessage_T_PAYLOAD_GETNAME)
	{
		result = _encodePayload_lookup(encoder, packetDictionary);
	}
	else if(lookupType ==CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_REGISTRATION_ACK)
	{
		result = _encodePayload_registration_ack(encoder, packetDictionary);
	}
	else if(lookupType ==CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_ADD_ACK)
	{
		result = _encodePayload_registration_add_ack(encoder, packetDictionary);
	}
	else if(lookupType ==CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_DEL_ACK)
	{
		result = _encodePayload_registration_del_ack(encoder, packetDictionary);
	}
	else if(lookupType ==CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_DEREG_ACK)
	{
		result = _encodePayload_registration_dereg_ack(encoder, packetDictionary);
	}
	else
	{
		result = _encodePayload(encoder, packetDictionary);
	}



	if (result < 0) {
		return result;
	}
	length += result;

	return length;
}

	static ssize_t
_encodeInterest(CCNxCodecTlvEncoder *encoder, CCNxTlvDictionary *packetDictionary)
{
	ssize_t length = 0;
	ssize_t result;


	//by wschoi
	uint16_t lookupType=ccnxTlvDictionary_CheckLookupType(packetDictionary);

#ifdef LOG_CHECK
	printf("_encodeInteres(), ccnxTlvDictionary_CheckLookupType : %x\n", lookupType);
#endif

	result = _encodeName(encoder, packetDictionary);
	if (result < 0) {
		return result;
	}
	length += result;

	result = _encodeKeyIdRestriction(encoder, packetDictionary);
	if (result < 0) {
		return result;
	}
	length += result;

	result = _encodeContentObjectHashRestriction(encoder, packetDictionary);
	if (result < 0) {
		return result;
	}
	length += result;

#ifdef LOG_CHECK
	printf("_encodeInterest(), lookup Type=%x\n\n", lookupType);
#endif
	if(lookupType == CCNxCodecSchemaV1Types_CCNxMessage_T_GETNAME || lookupType== CCNxCodecSchemaV1Types_CCNxMessage_T_PAYLOAD_GETNAME )
	{
		result = _encodePayload_lookup(encoder, packetDictionary);
	}

	//registration
	else if(lookupType ==CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_REGISTRATION_KeyName)
	{
		result = _encodePayload_registration(encoder, packetDictionary);
	}

	//add
	else if(lookupType ==CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_ADD_KeyName)
	{
		result = _encodePayload_registration_add(encoder, packetDictionary);
	}

	//del
	else if(lookupType ==CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_DEL_KeyName)
	{
		result = _encodePayload_registration_del(encoder, packetDictionary);
	}

	//dereg
	else if(lookupType ==CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_DEREG_KeyName)
	{
		result = _encodePayload_registration_dereg(encoder, packetDictionary);
	}
#if 0
	//refresh
	else if(lookupType ==CCNxCodecSchemaV1Types_CCNxMessage_T_NAME_REFRESH_KeyName)
	{
		result = _encodePayload_refresh(encoder, packetDictionary);
	}
#endif

	else
	{
		result = _encodePayload(encoder, packetDictionary);
	}

	if (result < 0) {
		return result;
	}
	length += result;

	return length;
}

	static ssize_t
_encodeControl(CCNxCodecTlvEncoder *encoder, CCNxTlvDictionary *packetDictionary)
{
	ssize_t length = 0;
	ssize_t result;

	result = _encodeName(encoder, packetDictionary);
	if (result < 0) {
		return result;
	}
	length += result;

	result = _encodeJsonPayload(encoder, packetDictionary);
	if (result < 0) {
		return result;
	}
	length += result;

	return length;
}

	static ssize_t
_encodeManifest(CCNxCodecTlvEncoder *encoder, CCNxTlvDictionary *packetDictionary)
{
	ssize_t length = 0;
	ssize_t result;

	result = _encodeName(encoder, packetDictionary);
	if (result < 0) {
		return result;
	}
	length += result;

	result = ccnxCodecSchemaV1ManifestEncoder_Encode(encoder, packetDictionary);
	if (result < 0) {
		return result;
	}
	length += result;

	return length;
}

	ssize_t
ccnxCodecSchemaV1MessageEncoder_Encode(CCNxCodecTlvEncoder *encoder, CCNxTlvDictionary *packetDictionary)
{
	assertNotNull(encoder, "Parameter encoder must be non-null");
	assertNotNull(packetDictionary, "Parameter packetDictionary must be non-null");

	ssize_t length = -1;


	if (ccnxTlvDictionary_IsInterest(packetDictionary)) {
		length = _encodeInterest(encoder, packetDictionary);
	} else if (ccnxTlvDictionary_IsInterestReturn(packetDictionary)) {
		length = _encodeInterest(encoder, packetDictionary);
	} else if (ccnxTlvDictionary_IsContentObject(packetDictionary)) {
		length = _encodeContentObject(encoder, packetDictionary);
	} else if (ccnxTlvDictionary_IsControl(packetDictionary)) {
		length = _encodeControl(encoder, packetDictionary);
	} else if (ccnxTlvDictionary_IsManifest(packetDictionary)) {
		length = _encodeManifest(encoder, packetDictionary);
	} else {
		CCNxCodecError *error = ccnxCodecError_Create(TLV_ERR_PACKETTYPE, __func__, __LINE__, ccnxCodecTlvEncoder_Position(encoder));
		ccnxCodecTlvEncoder_SetError(encoder, error);
		ccnxCodecError_Release(&error);
		length = -1;
	}


	if (length >= 0) {
		// Put custom fields all last
		ssize_t customLength = ccnxCodecTlvUtilities_EncodeCustomList(encoder, packetDictionary, CCNxCodecSchemaV1TlvDictionary_Lists_MESSAGE_LIST);
		if (customLength < 0) {
			return customLength;
		}
		length += customLength;
	}

	return length;
}
