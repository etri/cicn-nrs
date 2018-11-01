/*
 * Copyright (c) 2014-2015, Xerox Corporation (Xerox) and Palo Alto Research Center, Inc (PARC)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL XEROX OR PARC BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * ################################################################################
 * #
 * # PATENT NOTICE
 * #
 * # This software is distributed under the BSD 2-clause License (see LICENSE
 * # file).  This BSD License does not make any patent claims and as such, does
 * # not act as a patent grant.  The purpose of this section is for each contributor
 * # to define their intentions with respect to intellectual property.
 * #
 * # Each contributor to this source code is encouraged to state their patent
 * # claims and licensing mechanisms for any contributions made. At the end of
 * # this section contributors may each make their own statements.  Contributor's
 * # claims and grants only apply to the pieces (source code, programs, text,
 * # media, etc) that they have contributed directly to this software.
 * #
 * # There is no guarantee that this section is complete, up to date or accurate. It
 * # is up to the contributors to maintain their portion of this section and up to
 * # the user of the software to verify any claims herein.
 * #
 * # Do not remove this header notification.  The contents of this section must be
 * # present in all distributions of the software.  You may only modify your own
 * # intellectual property statements.  Please provide contact information.
 *
 * - Palo Alto Research Center, Inc
 * This software distribution does not grant any rights to patents owned by Palo
 * Alto Research Center, Inc (PARC). Rights to these patents are available via
 * various mechanisms. As of January 2016 PARC has committed to FRAND licensing any
 * intellectual property used by its contributions to this software. You may
 * contact PARC at cipo@parc.com for more information or visit http://www.ccnx.org
 */
/**
 * @author Alan Walendowski, Palo Alto Research Center (Xerox PARC)
 * @copyright (c) 2014-2015, Xerox Corporation (Xerox) and Palo Alto Research Center, Inc (PARC).  All rights reserved.
 */
#include <stdio.h>

#include "ccnxSimpleFileTransfer_Common.h"

#include <ccnx/common/ccnx_NameSegmentNumber.h>

#include <parc/security/parc_Security.h>
#include <parc/security/parc_Pkcs12KeyStore.h>
#include <parc/security/parc_IdentityFile.h>

/**
 * The name of this tutorial. This is what shows when you run the client or server with '-h'
 */
const char *ccnxSimpleFileTransferCommon_TutorialName = "CCNx 1.0 Simple File Transfer Tutorial";

/**
 * The CCNx Name prefix we'll use for the tutorial.
 */
const char *ccnxSimpleFileTransferCommon_NamePrefix = "ccnx:/ccnx/tutorial";

/**
 * The size of a chunk. We break CCNx Content payloads up into pieces of this size.
 * 1200 was chosen as a size that should prevent IP fragmentation of CCNx ContentObject Messages.
 */
const uint32_t ccnxSimpleFileTransferCommon_DefaultChunkSize = 1200;

/**
 * The string we use for the 'fetch' command.
 */
const char *ccnxSimpleFileTransferCommon_CommandFetch = "fetch";

/**
 * The string we use for the 'list' command.
 */
const char *ccnxSimpleFileTransferCommon_CommandList = "list";

PARCIdentity *
ccnxSimpleFileTransferCommon_CreateAndGetIdentity(const char *keystoreName,
                                                  const char *keystorePassword,
                                                  const char *subjectName)
{
    parcSecurity_Init();

    unsigned int keyLength = 1024;
    unsigned int validityDays = 30;

    bool success = parcPkcs12KeyStore_CreateFile(keystoreName, keystorePassword, subjectName, keyLength, validityDays);
    assertTrue(success,
               "parcPkcs12KeyStore_CreateFile('%s', '%s', '%s', %d, %d) failed.",
               keystoreName, keystorePassword, subjectName, keyLength, validityDays);

    PARCIdentityFile *identityFile = parcIdentityFile_Create(keystoreName, keystorePassword);
    PARCIdentity *result = parcIdentity_Create(identityFile, PARCIdentityFileAsPARCIdentity);
    parcIdentityFile_Release(&identityFile);

    parcSecurity_Fini();

    return result;
}

CCNxPortalFactory *
ccnxSimpleFileTransferCommon_SetupPortalFactory(const char *keystoreName,
                                                const char *keystorePassword,
                                                const char *subjectName)
{
    PARCIdentity *identity = ccnxSimpleFileTransferCommon_CreateAndGetIdentity(keystoreName,
                                                                               keystorePassword,
                                                                               subjectName);
    CCNxPortalFactory *result = ccnxPortalFactory_Create(identity);
    parcIdentity_Release(&identity);

    return result;
}

uint64_t
ccnxSimpleFileTransferCommon_GetChunkNumberFromName(const CCNxName *name)
{
    size_t numberOfSegmentsInName = ccnxName_GetSegmentCount(name);
    CCNxNameSegment *chunkNumberSegment = ccnxName_GetSegment(name, numberOfSegmentsInName - 1);

    assertTrue(ccnxNameSegment_GetType(chunkNumberSegment) == CCNxNameLabelType_CHUNK,
               "Last segment is the wrong type, expected CCNxNameLabelType %02X got %02X",
               CCNxNameLabelType_CHUNK,
               ccnxNameSegment_GetType(chunkNumberSegment))
    {
        //ccnxName_Display(name, 0); // This executes only if the enclosing assertion fails
    }

    return ccnxNameSegmentNumber_Value(chunkNumberSegment);
}


CCNxName *
ccnxSimpleFileTransferCommon_CreateWithBaseName(const CCNxName *name)
{
    size_t numberOfSegmentsInName = ccnxName_GetSegmentCount(name);

    CCNxName *result = ccnxName_Create();

    // Copy all segments, except the last one - which is the chunk number.
    for (int i = 0; i < numberOfSegmentsInName - 1; i++) {
        ccnxName_Append(result, ccnxName_GetSegment(name, i));
    }

    return result;
}

char *
ccnxSimpleFileTransferCommon_CreateFileNameFromName(const CCNxName *name)
{
    // For the Tutorial, the second to last NameSegment is the filename.
    CCNxNameSegment *fileNameSegment =
        ccnxName_GetSegment(name,
                            ccnxName_GetSegmentCount(name) - 2); // '-2' because we want the second to last segment
//by wschoi
    assertTrue(ccnxNameSegment_GetType(fileNameSegment) == CCNxNameLabelType_App(0x0001),
    //assertTrue(ccnxNameSegment_GetType(fileNameSegment) == CCNxNameLabelType_NAME,
               "Last segment is the wrong type, expected CCNxNameLabelType %02X got %02X",
               CCNxNameLabelType_App(0x0001),
               //CCNxNameLabelType_NAME,
               ccnxNameSegment_GetType(fileNameSegment))
    {
//        ccnxName_Display(name, 0); // This executes only if the enclosing assertion fails
    }

//by wschoi
	PARCBuffer *fileNameValue = ccnxNameSegment_GetValue(fileNameSegment);
 char *fileNameValueString = parcBuffer_ToString(fileNameValue);
 //printf("fileNameValueString: %s\n\n",fileNameValueString );


    return fileNameValueString; // This memory must be freed by the caller.
    //return ccnxNameSegment_ToString(fileNameSegment); // This memory must be freed by the caller.
}

char *
ccnxSimpleFileTransferCommon_CreateCommandStringFromName(const CCNxName *name, const CCNxName *domainPrefix)
{
    // For the Tutorial, the NameSegment immediately following the domain prefix contains the command.
    CCNxNameSegment *commandSegment = ccnxName_GetSegment(name, ccnxName_GetSegmentCount(domainPrefix));
//by wschoi

	int segmentcount_i=ccnxName_GetSegmentCount(domainPrefix);
//	printf("segmentcount_i: %d \n\n", segmentcount_i);

//printf("############ name ##################\n\n");
//	ccnxName_Display(name, 0);
//printf("############ domainPrefix ##################\n\n");
//	ccnxName_Display(domainPrefix, 0);
//printf("##############################\n\n");

//by wschoi
    //assertTrue(ccnxNameSegment_GetType(commandSegment) == CCNxNameLabelType_NAME,
    assertTrue(ccnxNameSegment_GetType(commandSegment) == CCNxNameLabelType_App(0x0000),
               "Last segment is the wrong type, expected CCNxNameLabelType %02X got %02X",
               //CCNxNameLabelType_NAME,
               CCNxNameLabelType_App(0x0000),
               ccnxNameSegment_GetType(commandSegment))
    {
//        ccnxName_Display(name, 0); // This executes only if the enclosing assertion fails
    }
//by wschoi


	PARCBuffer *commandValue = ccnxNameSegment_GetValue(commandSegment);
 char *commandValueString = parcBuffer_ToString(commandValue);
// printf("commandValueString: %s\n\n",commandValueString );

    return commandValueString; // This memory must be freed by the caller.
    //return ccnxNameSegment_ToString(commandSegment); // This memory must be freed by the caller.
}

