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
 * @file ccnxCodecSchemaV1_MessageEncoder.h
 * @brief Encode the list of optional headers
 *
 */

#ifndef TransportRTA_ccnxCodecSchemaV1_MessageEncoder_h
#define TransportRTA_ccnxCodecSchemaV1_MessageEncoder_h

#include <ccnx/common/internal/ccnx_TlvDictionary.h>
#include <ccnx/common/codec/ccnxCodec_TlvEncoder.h>
#include <parc/security/parc_Signer.h>

/**
 * Encodes the body of the CCNxMessage
 *
 * Encodes an Interest, ContentObject, or Control message
 *
 * @param [in] encoder Appends the CCNx message to the encoder
 * @param [in] packetDictionary The fields to encode
 *
 * @return non-negative Total bytes appended to encoder
 * @return -1 An error
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
ssize_t ccnxCodecSchemaV1MessageEncoder_Encode(CCNxCodecTlvEncoder *encoder, CCNxTlvDictionary *packetDictionary);

#endif // TransportRTA_ccnxCodecSchemaV1_MessageEncoder_h
