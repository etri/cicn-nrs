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
 * @author Glenn Scott, Alan Walendowski, Palo Alto Research Center (Xerox PARC)
 * @copyright (c) 2014-2015, Xerox Corporation (Xerox) and Palo Alto Research Center, Inc (PARC).  All rights reserved.
 */

#include <strings.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>

#include "ccnxSimpleFileTransfer_Common.h"
#include "ccnxSimpleFileTransfer_FileIO.h"
#include "ccnxSimpleFileTransfer_ChunkList.h"

#include <parc/algol/parc_HashMap.h>

#include <ccnx/api/ccnx_Portal/ccnx_PortalRTA.h>

#include <ccnx/common/ccnx_NameSegmentNumber.h>


typedef struct serverState {
    CCNxName *namePrefix;
    size_t chunkSize;
    char *sourceDirectoryPath;
    bool doPreChunkIntoMemory;
    bool beVerbose;
} ServerState;

static PARCHashMap *_contentByFilename = NULL;

/**
 * Create a new CCNxPortalFactory instance using a randomly generated identity saved to
 * the specified keystore.
 *
 * @return A new CCNxPortalFactory instance which must eventually be released by calling ccnxPortalFactory_Release().
 */
static CCNxPortalFactory *
_setupServerPortalFactory(void)
{
    const char *keystoreName = "server.keystore";
    const char *keystorePassword = "keystore_password";
    const char *subjectName = "ccnxSimpleFileTransfer_Server";

    return ccnxSimpleFileTransferCommon_SetupPortalFactory(keystoreName, keystorePassword, subjectName);
}

/**
 * Given the size of some data and a chunk size, calculate the number of chunks that would be
 * required to contain the data.
 *
 * @param [in] dataLength The size of the data being chunked.
 * @param [in] chunkSize The size of the chunks to break the data in to.
 *
 * @return The number of chunks required to contain the specified data length.
 */
static uint64_t
_getNumberOfChunksRequired(uint64_t dataLength, size_t chunkSize)
{
    uint64_t chunks = (dataLength / chunkSize) + (dataLength % chunkSize > 0 ? 1 : 0);
    return (chunks == 0) ? 1 : chunks;
}

/**
 * Given the full path to a file, calculate and return the number of the final chunk in the file.
 * The final chunk nunber is a function of the size of the file and the specified chunk size. It
 * is 0-based and is never negative. A file of size 0 has a final chunk number of 0.
 *
 * @param [in] filePath The full path to a file.
 * @param [in] chunkSize The size of the chunks to break the file in to.
 *
 * @return The number of the final chunk required to transfer the specified file.
 */
static u_int64_t
_getFinalChunkNumberOfFile(const char *filePath, size_t chunkSize)
{
    size_t fileSize = ccnxSimpleFileTransferFileIO_GetFileSize(filePath);
    uint64_t totalNumberOfChunksInFile = _getNumberOfChunksRequired(fileSize, chunkSize);

    // If the file size == 0, the the final chunk number is 0. Else, it's one less
    // than the number of chunks in the file.

    return totalNumberOfChunksInFile > 0 ? (totalNumberOfChunksInFile - 1) : 0;
}

/**
 * Given a Name, a payload, and the number of the last chunk, create a CCNxContentObject suitable for
 * passing to the Portal. This new CCNxContentObject must eventually be released by calling
 * ccnxContentObject_Release().
 *
 * @param name [in] The CCNxName to use when creating the new ContentObject.
 * @param payload [in] A PARCBuffer to use as the payload of the new ContentObject.
 * @param finalChunkNumber [in] The number of the final chunk that will be required to completely transfer
 *        the requested content.
 *
 * @return A newly created CCNxContentObject with the specified name, payload, and finalChunkNumber.
 */
static CCNxContentObject *
_createContentObject(const CCNxName *name, const PARCBuffer *payload, const uint64_t finalChunkNumber)
{
    // In the call below, we are un-const'ing name for ccnxContentObject_CreateWithNameAndPayload()
    // but we will not be changing it.
    CCNxContentObject *result = ccnxContentObject_CreateWithNameAndPayload((CCNxName *) name, payload);
	//ccnxName_Display(name, 0);
//	ccnxContentObject_Display(result, 1);
/*	 char *nameString = ccnxName_ToString(name);
	 printf("nameString size:%d\n\n\n", sizeof(nameString));

for(int i=0; i<56; i++)
{
	printf(" %x ", nameString[i]);
}
printf("\n\n");

for(int i=0; i<56; i++)
{
	printf(" %c ", nameString[i]);
}
printf("\n\n");
*/
    ccnxContentObject_SetFinalChunkNumber(result, finalChunkNumber);

    return result;
}

CCNxSimpleFileTransferChunkList *
_chunkFileIntoMemory(char *fullFilePath, const CCNxName *baseName, size_t chunkSize)
{
    CCNxSimpleFileTransferChunkList *result = NULL;

    printf("## Pre-chunking %s into memory...\n", fullFilePath);

    // Make sure the file exists and is accessible before creating a ContentObject response.
    if (ccnxSimpleFileTransferFileIO_IsFileAvailable(fullFilePath)) {
        uint64_t finalChunkNumber = _getFinalChunkNumberOfFile(fullFilePath, chunkSize);

        result = ccnxSimpleFileTransferChunkList_Create(fullFilePath, finalChunkNumber + 1);


        for (uint64_t i = 0; i <= finalChunkNumber; i++) {
            // Get the actual contents of the specified chunk of the file.
            PARCBuffer *payload = ccnxSimpleFileTransferFileIO_GetFileChunk(fullFilePath, chunkSize, i);

            if (payload != NULL) {
                CCNxName *chunkName = ccnxName_Copy(baseName);
                CCNxNameSegment *chunkSegment = ccnxNameSegmentNumber_Create(CCNxNameLabelType_CHUNK, i);
                ccnxName_Append(chunkName, chunkSegment);

                CCNxContentObject *contentObject = _createContentObject(chunkName, payload, finalChunkNumber);

                parcBuffer_Release(&payload);
                ccnxName_Release(&chunkName);
                ccnxNameSegment_Release(&chunkSegment);

                ccnxSimpleFileTransferChunkList_SetChunk(result, i, contentObject);
            } else {
                trapUnexpectedState("Could not get required chunk");
            }
        }
        printf("## Finished chunking %s into memory. Resulted in %llu content objects.\n", fullFilePath,
               finalChunkNumber + 1);
    } else {
        //trapUnexpectedState("Could not open file %s for chunking.", fullFilePath);

        printf("## !! ## Could not access requested file [%s]. Could not pre-chunk. ## !! ##\n", fullFilePath);
    }

    return result;
}


/**
 * Given a CCNxName, a directory path, a file name, and a requested chunk number, return a new CCNxContentObject
 * with that CCNxName and containing the specified chunk of the file. The new CCNxContentObject will also
 * contain the number of the last chunk required to transfer the complete file. Note that the last chunk of the
 * file being retrieved is calculated each time we retrieve a chunk so the file can be growing in size as we
 * transfer it.
 * The new CCnxContentObject must eventually be released by calling ccnxContentObject_Release().
 *
 * @param [in] name The CCNxName to use when creating the new CCNxContentObject.
 * @param [in] directoryPath The directory in which to find the specified file.
 * @param [in] fileName The name of the file.
 * @param [in] requestedChunkNumber The number of the requested chunk from the file.
 *
 * @return A new CCNxContentObject instance containing the request chunk of the specified file, or NULL if
 *         the file did not exist or was otherwise unavailable.
 */
static CCNxContentObject *
_createFetchResponse(ServerState *serverState, CCNxName *name,
                     char *fileName, int64_t requestedChunkNumber)
{
    CCNxContentObject *result = NULL;
    uint64_t finalChunkNumber = 0;
//printf("_createFetchResponse(), requestedChunkNumber: %d\n", requestedChunkNumber);
    // Combine the directoryPath and fileName into the full path name of the desired file
    size_t filePathBufferSize =
        strlen(fileName) + strlen(serverState->sourceDirectoryPath) + 2; // +2 for '/' and trailing null.

//printf("_createFetchResponse(), filePathBufferSize: %d\n", filePathBufferSize);
    char *fullFilePath = parcMemory_Allocate(filePathBufferSize);
    assertNotNull(fullFilePath, "parcMemory_Allocate(%zu) returned NULL", filePathBufferSize);
    snprintf(fullFilePath, filePathBufferSize, "%s/%s", serverState->sourceDirectoryPath, fileName);

    // Make sure the file exists and is accessible before creating a ContentObject response.
    if (ccnxSimpleFileTransferFileIO_IsFileAvailable(fullFilePath)) {
        // Since the file's length can change (e.g. if it is being written to while we're fetching
        // it), the final chunk number can change between requests for content chunks. So, update
        // it each time this function is called.
        finalChunkNumber = _getFinalChunkNumberOfFile(fullFilePath, serverState->chunkSize);
//printf("_createFetchResponse(), finalChunkNumber: %d\n", finalChunkNumber);
        // Get the actual contents of the specified chunk of the file.
        PARCBuffer *payload = ccnxSimpleFileTransferFileIO_GetFileChunk(fullFilePath,
                                                                        serverState->chunkSize,
                                                                        requestedChunkNumber);
//parcBuffer_Display(payload,0);
        if (payload != NULL) {
            result = _createContentObject(name, payload, finalChunkNumber);
            parcBuffer_Release(&payload);
        }
    }

    parcMemory_Deallocate((void **) &fullFilePath);

    return result; // Could be NULL if there was no payload
}

/**
 * Same as _createFetchResponse(), but pre-calculates ALL of the content objects and stores them in memory for quick retrieval.
 */
static CCNxContentObject *
_createFetchResponseWithPreChunking(const ServerState *serverState, const CCNxName *name,
                                    const char *fileName, const uint64_t requestedChunkNumber)
{
    CCNxContentObject *result = NULL;

    CCNxSimpleFileTransferChunkList *fileChunks = NULL;

    // Get a copy of the name, but without the chunk number.
    CCNxName *baseName = ccnxSimpleFileTransferCommon_CreateWithBaseName(name);

    fileChunks = (CCNxSimpleFileTransferChunkList *) parcHashMap_Get(_contentByFilename, baseName);
    // We're assuming no name collisions in the hashmap...

    if (fileChunks == NULL) {
        // Chunk list for this file was empty. Build it. This will take a while.

        // Combine the directoryPath and fileName into the full path name of the desired file
        size_t filePathBufferSize =
            strlen(fileName) + strlen(serverState->sourceDirectoryPath) + 2; // +2 for '/' and trailing null.
        char *fullFilePath = parcMemory_Allocate(filePathBufferSize);
        assertNotNull(fullFilePath, "parcMemory_Allocate(%zu) returned NULL", filePathBufferSize);
        snprintf(fullFilePath, filePathBufferSize, "%s/%s", serverState->sourceDirectoryPath, fileName);

        fileChunks = _chunkFileIntoMemory(fullFilePath, baseName, serverState->chunkSize);

        if (fileChunks != NULL) {
            parcHashMap_Put(_contentByFilename, baseName, fileChunks);
            parcMemory_Deallocate((void **) &fullFilePath);
        }
    }
    ccnxName_Release(&baseName);

    if (fileChunks != NULL) {

        if (requestedChunkNumber < ccnxSimpleFileTransferChunkList_GetNumChunks(fileChunks)) {
            result = ccnxSimpleFileTransferChunkList_GetChunk(fileChunks, requestedChunkNumber);
            if (result != NULL) {
                // We actually want to return a reference to the ContentObject chunk, as
                // the calling code expects to be able to release what we return.
                result = ccnxContentObject_Acquire(result);
            }
        } else {
            printf("Requested out of range chunk %lld for %s. Returning NULL\n", requestedChunkNumber, fileName);
        }
    }

    return result; // Could be NULL if there was no payload
}


/**
 * Given a CCNxName, a directory path, and a requested chunk number, create a directory listing and return the specified
 * chunk of the directory listing as the payload of a newly created CCNxContentObject.
 * The new CCnxContentObject must eventually be released by calling ccnxContentObject_Release().
 *
 * @param [in] name The CCNxName to use when creating the new CCNxContentObject.
 * @param [in] directoryPath The directory whose contents are being listed.
 * @param [in] requestedChunkNumber The number of the requested chunk from the complete directory listing.
 *
 * @return A new CCNxContentObject instance containing the request chunk of the directory listing.
 */
static CCNxContentObject *
_createListResponse(const ServerState *serverState, CCNxName *name, uint64_t requestedChunkNumber)
{
    CCNxContentObject *result = NULL;

    PARCBuffer *directoryList = ccnxSimpleFileTransferFileIO_CreateDirectoryListing(serverState->sourceDirectoryPath);

    uint64_t totalChunksInDirList = _getNumberOfChunksRequired(parcBuffer_Limit(directoryList),
                                                               serverState->chunkSize);
    if (requestedChunkNumber < totalChunksInDirList) {
        // Set the buffer's position to the start of the desired chunk.
        parcBuffer_SetPosition(directoryList, (requestedChunkNumber * serverState->chunkSize));

        // See if we have more than 1 chunk's worth of data to in the buffer. If so, set the buffer's limit
        // to the end of the chunk.
        size_t chunkLen = parcBuffer_Remaining(directoryList);

        if (chunkLen > serverState->chunkSize) {
            parcBuffer_SetLimit(directoryList,
                                parcBuffer_Position(directoryList) + serverState->chunkSize);
        }

        // Calculate the final chunk number
        uint64_t finalChunkNumber = (totalChunksInDirList > 0) ? totalChunksInDirList - 1
                                                               : 0; // the final chunk, 0-based

        // At this point, dirListBuf has its position and limit set to the beginning and end of the
        // specified chunk.
        result = _createContentObject(name, directoryList, finalChunkNumber);
    }

    parcBuffer_Release(&directoryList);

    return result;
}

/**
 * Given a CCnxInterest that matched our domain prefix, see what the embedded command is and
 * create a corresponding CCNxContentObject as a response. The resulting CCNxContentObject
 * must eventually be released by calling ccnxContentObject_Release().
 *
 * @param [in] interest A CCNxInterest that matched the specified domain prefix.
 * @param [in] domainPrefix A CCNxName containing the domain prefix.
 * @param [in] directoryPath A string containing the path to the directory being served.
 *
 * @return A newly creatd CCNxContentObject contaning a response to the specified Interest,
 *         or NULL if the Interest couldn't be answered.
 */
static CCNxContentObject *
_createInterestResponse(const ServerState *serverState, const CCNxInterest *interest)
{
    CCNxName *interestName = ccnxInterest_GetName(interest);

    char *command = ccnxSimpleFileTransferCommon_CreateCommandStringFromName(interestName,
                                                                             (const CCNxName *) serverState->namePrefix);

    uint64_t requestedChunkNumber = ccnxSimpleFileTransferCommon_GetChunkNumberFromName(interestName);


	//by wschoi
	//printf("command: %s\n\n", command);
//	printf("requestedChunkNumber : %d, %04x \n\n", requestedChunkNumber, requestedChunkNumber);

    CCNxContentObject *result = NULL;
    if (strncasecmp(command, ccnxSimpleFileTransferCommon_CommandList, strlen(command)) == 0) {
        // This was a 'list' command. We should return the requested chunk of the directory listing.
        result = _createListResponse(serverState, interestName, requestedChunkNumber);
    } else if (strncasecmp(command, ccnxSimpleFileTransferCommon_CommandFetch, strlen(command)) == 0) {
        // This was a 'fetch' command. We should return the requested chunk of the file specified.
        char *fileName = ccnxSimpleFileTransferCommon_CreateFileNameFromName(interestName);

	//by wschoi
	//printf("fileName: %s\n\n", fileName);


        if (serverState->doPreChunkIntoMemory) {
//			printf("!!!!!!!!!!!!!!!!!!!!!!!!!\n\n");
            result = _createFetchResponseWithPreChunking(serverState,
                                                         interestName,
                                                         fileName,
                                                         requestedChunkNumber);
        } else {
//			printf("@@@@@@@@@@@@@@@@@@@@@\n\n");
            result = _createFetchResponse(serverState,
                                          interestName,
                                          fileName,
                                          requestedChunkNumber);
        }

        parcMemory_Deallocate((void **) &fileName);
    } else {
        printf("_createInterestResponse() called with unknown command: %s\n", command);
    }

    parcMemory_Deallocate((void **) &command);
    return result;
}
// type, to be consider

	//by wschoi
#if 0
	static CCNxContentObject *
keyName_parse(ServerState *serverState, CCNxInterest *interest)
{
	//printf("###########################ccnxInterest_GetPayload_KeyName buffer\n");
	PARCBuffer *interestKey_payload = ccnxInterest_GetPayload_KeyName(interest);

	PARCBuffer *interestKey_payload_clone = parcBuffer_Copy(interestKey_payload);
	PARCBuffer *interestKey_payload_clone_size = parcBuffer_Copy(interestKey_payload);
	//parcBuffer_Display(interestKey_payload_clone_size, 3);
	parcBuffer_Mark(interestKey_payload_clone_size);
	//parcBuffer_Display(interestKey_payload_clone_size, 3);
	parcBuffer_Resize(interestKey_payload_clone_size, 4);
	//parcBuffer_Display(interestKey_payload_clone_size, 3);
	
	uint8_t *actual_array_size = parcBuffer_ToString(interestKey_payload_clone_size);

	int  interestKey_payload_clone_resize_value = actual_array_size[3]+4;

	//printf("#####Mark%d\n\n", interestKey_payload_clone_resize_value);
	parcBuffer_Mark(interestKey_payload_clone);
	//parcBuffer_Display(interestKey_payload_clone, 3);

	//printf("#####resize\n\n");
	parcBuffer_Resize(interestKey_payload_clone, interestKey_payload_clone_resize_value);
	//parcBuffer_Display(interestKey_payload_clone, 3);
	uint8_t *keyName_array=parcBuffer_ToString(interestKey_payload_clone);

	for(int i=0; i<actual_array_size[3]+4; i++)
	{
//		printf(" keyName_array_%d, %x\n", i, keyName_array[i]);
	}

	// Make a string Name from KEYNAME
	int actual_array_name_size=(int)keyName_array[3];
	char actual_array_trans[actual_array_name_size];
	int k=0, n=0;
	int actual_array_trans_size=0;
	char command_array[128];
	int command_array_size=0;
	int command_array_each_size[128];
	int command_array_each_size_i=0;
	int command_start_point=4;
	int command_actual_array_size=0;



	for(int i=4; i<actual_array_name_size+4;i++)
	{
		if(keyName_array[i]==0x00 && keyName_array[i+1]==0x01 && keyName_array[i+2]==0x00)
		{
			actual_array_trans[k]='/';
	//		printf("actual_array_trans: %c\n", actual_array_trans[k]);
			k++;
			command_start_point= command_start_point +4 + keyName_array[i+3];

			for (int j=0; j<keyName_array[i+3];j++)
			{
				actual_array_trans[k]=keyName_array[i+4+j];

	//			printf("actual_array_trans: %c\n", actual_array_trans[k]);
				k++;
				actual_array_trans_size++;
			}
			actual_array_trans_size++;
		}
		else if(keyName_array[i]==0x10 && keyName_array[i+2]==0x00)
		{

			command_array[n]='/';
	//		printf("command_array: %c\n", command_array[n]);
			n++;
			command_array_each_size[command_array_each_size_i]=keyName_array[i+3];
			command_array_each_size_i++;



			for (int j=0; j<keyName_array[i+3];j++)
			{
				command_array[n]=keyName_array[i+4+j];
	//			printf("command_array: %c\n", command_array[n]);
				n++;
				command_array_size++;
			}
			command_array_size++;
		}

		else if(keyName_array[i]==0x00 && keyName_array[i+1]==0x10 && keyName_array[i+2]==0x00)
		{
			break;
		}

	}

	command_actual_array_size= 4+actual_array_name_size-command_start_point;
//	printf("#####################command_start_point: %d, command_actual_array_size: %d\n\n", command_start_point, command_actual_array_size);

//	printf("command_array_each_size1: %d, command_array_each_size2: %d, command_array_size: %d\n\n", command_array_each_size[0],command_array_each_size[1], command_array_size);
	char command_tow_dimension[command_array_each_size_i][128];
	int m=0;
	for(int i=0; i<command_array_each_size_i;i++)
	{
		for(int j=0; j<command_array_each_size[i];j++)
		{
			if(command_array[m]!='/')
			{
				command_tow_dimension[i][j]=command_array[m];
	//			printf("#####################ccommand_array %c\n", command_array[m]);
	//			printf("#####################command_tow_dimension %c, i=%d, j=%d\n", command_tow_dimension[i][j], i, j);
				if(j==command_array_each_size[i]-1)
				{
					command_tow_dimension[i][command_array_each_size[i]]=NULL;
				}

			}
			else
			{
				j--;
			}
			m++;


		}
	}
		//printf("command1: %s\n\n", command_tow_dimension[0]);
		//printf("command2: %s\n\n", command_tow_dimension[1]);
		//printf("check command2: %c, %c, %c, %c, %c\n", command_tow_dimension[1][0], command_tow_dimension[1][1], command_tow_dimension[1][2], command_tow_dimension[1][3]);





//#################################################


		PARCBuffer *commandBuffer;
		PARCBuffer *filenameBuffer;
		PARCBuffer *chunknumberBuffer;

		CCNxNameSegment *commandSegment;
		CCNxNameSegment *filenameSegment;
		CCNxNameSegment *chunknumberSegment;
		uint8_t chunkNumber[1];



		if(command_array_each_size_i==2)
		{
			commandBuffer= parcBuffer_WrapCString(command_tow_dimension[0]);
//			parcBuffer_Display(commandBuffer, 0);
			commandSegment = ccnxNameSegment_CreateTypeValue(CCNxNameLabelType_App(0x0000), commandBuffer);
//			ccnxNameSegment_Display(commandSegment, 10);


			filenameBuffer = parcBuffer_WrapCString(command_tow_dimension[1]);
//			parcBuffer_Display(filenameBuffer, 0);
			filenameSegment = ccnxNameSegment_CreateTypeValue(CCNxNameLabelType_App(0x0001), filenameBuffer);
//			ccnxNameSegment_Display(filenameSegment, 10);


			chunkNumber[0]=keyName_array[actual_array_name_size+3];
			printf("keyName_parse(), chunkNumber[0]: %x\n", chunkNumber[0]);
			
//			printf("########################## keyName_array[actual_array_name_size+4]= %x, actual_array_name_size=%d\n\n", keyName_array[actual_array_name_size+1], actual_array_name_size);
			chunknumberBuffer = parcBuffer_Wrap(chunkNumber, 1, 0, 1);
//			parcBuffer_Display(chunknumberBuffer,0);

			chunknumberSegment = ccnxNameSegment_CreateTypeValue(CCNxNameLabelType_CHUNK, chunknumberBuffer);
//			ccnxNameSegment_Display(chunknumberSegment, 10);
		}
		else
		{

			commandBuffer= parcBuffer_WrapCString(command_tow_dimension[0]);
//			parcBuffer_Display(commandBuffer, 0);
			commandSegment = ccnxNameSegment_CreateTypeValue(CCNxNameLabelType_NAME, commandBuffer);
//			ccnxNameSegment_Display(commandSegment, 10);
		}



		//  make a ccnxName of name1 for GETNAME/GETNAME_PAYLOAD format
		char actural_array_trans_add_domain_str[128]="ccnx:";
		strcat(actural_array_trans_add_domain_str, actual_array_trans);
		CCNxName *interestKey_with_command= ccnxName_CreateFromCString(actural_array_trans_add_domain_str);
		CCNxName *interestKey_without_command= ccnxName_CreateFromCString(actural_array_trans_add_domain_str);
		//##############add command

		if(command_array_each_size_i==2)
		{
			ccnxName_Append(interestKey_with_command, commandSegment);
			ccnxName_Append(interestKey_with_command, filenameSegment);
			ccnxName_Append(interestKey_with_command, chunknumberSegment);
	printf("keyName_parse(), interestKey_with_command\n");
			ccnxName_Display(interestKey_with_command, 0);
		}
		else
		{
			ccnxName_Append(interestKey_with_command, commandSegment);
		}
//		printf("###########interestKey_with_command\n\n");
//		ccnxName_Display(interestKey_with_command, 10);

//#############################



//CCNxInterest *interest_test=ccnxInterest_CreateSimple(interestKey_with_command);
//CCNxMetaMessage *metamessage_test = ccnxMetaMessage_CreateFromInterest(interest_test);
//CCNxName *interestname_test=ccnxInterest_GetName(metamessage_test);
//printf("name display\n");
//ccnxName_Display(interestname_test, 0);




//    CCNxName *interestName = ccnxInterest_GetName(interest);

    char *command = ccnxSimpleFileTransferCommon_CreateCommandStringFromName(interestKey_with_command, interestKey_without_command);

    uint8_t requestedChunkNumber = ccnxSimpleFileTransferCommon_GetChunkNumberFromName(interestKey_with_command);


	//by wschoi
	printf("keyName_parse(), command: %s\n\n", command);
	printf("keyName_parse(), requestedChunkNumber : %d, %x \n\n", requestedChunkNumber, requestedChunkNumber);

    CCNxContentObject *result= NULL;

    if (strncasecmp(command, ccnxSimpleFileTransferCommon_CommandList, strlen(command)) == 0) {
        // This was a 'list' command. We should return the requested chunk of the directory listing.
        result = _createListResponse(serverState, interestKey_with_command, requestedChunkNumber);
    } else if (strncasecmp(command, ccnxSimpleFileTransferCommon_CommandFetch, strlen(command)) == 0) {
        // This was a 'fetch' command. We should return the requested chunk of the file specified.
        char *fileName = ccnxSimpleFileTransferCommon_CreateFileNameFromName(interestKey_with_command);

	//by wschoi
	printf("keyName_parse(), fileName: %s\n\n", fileName);


        if (serverState->doPreChunkIntoMemory) {

//			printf("!!!!!!!!!!!!!!!!!!!!!!!!!\n\n");
			result = _createFetchResponseWithPreChunking(serverState,
                                                         interestKey_with_command,
                                                         fileName,
                                                         requestedChunkNumber);
        } else {
			printf("@@@@@@@@@@@@@@@@@@@@@@@\n\n");
            result = _createFetchResponse(serverState,
                                          interestKey_with_command,
                                          fileName,
                                          requestedChunkNumber);

        }

        parcMemory_Deallocate((void **) &fileName);
    } else {
        printf("_createInterestResponse() called with unknown command: %s\n", command);
    }

    parcMemory_Deallocate((void **) &command);


printf("keyName_parse(), ccnxMetaMessage_Display\n");
ccnxContentObject_Display(result, 0);;

CCNxName *name_test= ccnxContentObject_GetName(result);
ccnxName_Display(name_test, 0);

    return result;


//	printf("\n\n");

//	return 0;

}
#endif

/**
 * Listen for arriving Interests and respond to them if possible. We expect that the Portal we are passed is
 * listening for messages matching the specified domainPrefix.
 *
 * @param [in] portal The CCNxPortal that we will read from.
 * @param [in] domainPrefix A CCNxName containing the domain prefix that the specified `portal` is listening for.
 * @param [in] directoryPath A string containing the path to the directory being served.
 *
 * @return true if at least one Interest is received and responded to, false otherwise.
 */
static bool
_receiveAndAnswerInterests(ServerState *serverState, CCNxPortal *portal)
{
    bool result = false;
    CCNxMetaMessage *inboundMessage = NULL;

    while ((inboundMessage = ccnxPortal_Receive(portal, CCNxStackTimeout_Never)) != NULL) {
        if (ccnxMetaMessage_IsInterest(inboundMessage)) {
            CCNxInterest *interest = ccnxMetaMessage_GetInterest(inboundMessage);

            if (serverState->beVerbose) {
                CCNxName *interestName = ccnxInterest_GetName(interest);
                char *nameString = ccnxName_ToString(interestName);
                uint64_t requestedChunkNumber = ccnxSimpleFileTransferCommon_GetChunkNumberFromName(interestName);
                printf("<- Received interest for [%s] (chunk #%" PRIu64 ")\n", nameString, requestedChunkNumber);
                parcMemory_Deallocate(&nameString);
            }

			//by wchoi
			//		keyName_parse(interest);
			CCNxContentObject *response;
			
			if(ccnxInterest_GetPayload_KeyName(interest)==NULL)
			{
				response = _createInterestResponse(serverState, interest);



#if 1
//CCNxName *name_test= ccnxContentObject_GetName(response);
//ccnxName_Display(name_test, 0);

            // At this point, response has either the requested chunk of the request file/command,
            // or remains NULL.

            if (serverState->beVerbose) {
                if (response != NULL) {
                    PARCBuffer *payload = ccnxContentObject_GetPayload(response);
                    size_t payloadSize = 0;
                    if (payload != NULL) {
                        payloadSize = parcBuffer_Limit(payload);
                    }
                    printf(" -> Responding with %ld bytes\n", payloadSize);
                }
            }

            if (response != NULL) {
                // We had a response, so send it back through the Portal.

//ccnxContentObject_Display(response, 0);;


                CCNxMetaMessage *responseMessage = ccnxMetaMessage_CreateFromContentObject(response);
//printf("ccnxMetaMessage_Display\n");
//ccnxMetaMessage_Display(responseMessage, 0);;

                if (ccnxPortal_Send(portal, responseMessage, CCNxStackTimeout_Never) == false) {
                //if (ccnxPortal_Send(portal, response, CCNxStackTimeout_Never) == false) {
                    fprintf(stderr, "ccnxPortal_Send failed (error %d). Is the Forwarder running?\n",
                            ccnxPortal_GetError(portal));
                }

                ccnxMetaMessage_Release(&responseMessage);
//                ccnxContentObject_Release(&response);

                result = true; // We have received, and responded to, at least one Interest.
            }
#endif

			}



			else
			{
//printf("\n\n\n\nSTART!!!!!!!!!!!!!!!!!!!!!!START!!!!!!!!!!!!!!!!!!!!!!START!!!!!!!!!!!!!!!!!!!!!!START!!!!!!!!!!!!!!!!!!!!!!START!!!!!!!!!!!!!!!!!!!!!!\n");
//printf("START!!!!!!!!!!!!!!!!!!!!!!START!!!!!!!!!!!!!!!!!!!!!!START!!!!!!!!!!!!!!!!!!!!!!START!!!!!!!!!!!!!!!!!!!!!!START!!!!!!!!!!!!!!!!!!!!!!\n");
//printf("START!!!!!!!!!!!!!!!!!!!!!!START!!!!!!!!!!!!!!!!!!!!!!START!!!!!!!!!!!!!!!!!!!!!!START!!!!!!!!!!!!!!!!!!!!!!START!!!!!!!!!!!!!!!!!!!!!!\n");
				
#if 1
	//printf("###########################ccnxInterest_GetPayload_KeyName buffer\n");
	PARCBuffer *interestKey_payload = ccnxInterest_GetPayload_KeyName(interest);

	PARCBuffer *interestKey_payload_clone = parcBuffer_Copy(interestKey_payload);
	PARCBuffer *interestKey_payload_clone_size = parcBuffer_Copy(interestKey_payload);
	//parcBuffer_Display(interestKey_payload_clone_size, 3);
	parcBuffer_Mark(interestKey_payload_clone_size);
	//parcBuffer_Display(interestKey_payload_clone_size, 3);
	parcBuffer_Resize(interestKey_payload_clone_size, 4);
	//parcBuffer_Display(interestKey_payload_clone_size, 3);
	
	uint8_t *actual_array_size = parcBuffer_ToString(interestKey_payload_clone_size);

	int  interestKey_payload_clone_resize_value = actual_array_size[3]+4;

	//printf("#####Mark%d\n\n", interestKey_payload_clone_resize_value);
	parcBuffer_Mark(interestKey_payload_clone);
	//parcBuffer_Display(interestKey_payload_clone, 3);

	//printf("#####resize\n\n");
	parcBuffer_Resize(interestKey_payload_clone, interestKey_payload_clone_resize_value);
	//parcBuffer_Display(interestKey_payload_clone, 3);
	uint8_t *keyName_array=parcBuffer_ToString(interestKey_payload_clone);

	for(int i=0; i<actual_array_size[3]+4; i++)
	{
//		printf(" keyName_array_%d, %x\n", i, keyName_array[i]);
	}

	// Make a string Name from KEYNAME
	int actual_array_name_size=(int)keyName_array[3];
	char actual_array_trans[actual_array_name_size];
	int k=0, n=0;
	int actual_array_trans_size=0;
	char command_array[128];
	int command_array_size=0;
	int command_array_each_size[128];
	int command_array_each_size_i=0;
	int command_start_point=4;
	int command_actual_array_size=0;



	for(int i=4; i<actual_array_name_size+4;i++)
	{
		if(keyName_array[i]==0x00 && keyName_array[i+1]==0x01 && keyName_array[i+2]==0x00)
		{
			actual_array_trans[k]='/';
	//		printf("actual_array_trans: %c\n", actual_array_trans[k]);
			k++;
			command_start_point= command_start_point +4 + keyName_array[i+3];

			for (int j=0; j<keyName_array[i+3];j++)
			{
				actual_array_trans[k]=keyName_array[i+4+j];

	//			printf("actual_array_trans: %c\n", actual_array_trans[k]);
				k++;
				actual_array_trans_size++;
			}
			actual_array_trans_size++;
		}
		else if(keyName_array[i]==0x10 && keyName_array[i+2]==0x00)
		{

			command_array[n]='/';
	//		printf("command_array: %c\n", command_array[n]);
			n++;
			command_array_each_size[command_array_each_size_i]=keyName_array[i+3];
			command_array_each_size_i++;



			for (int j=0; j<keyName_array[i+3];j++)
			{
				command_array[n]=keyName_array[i+4+j];
	//			printf("command_array: %c\n", command_array[n]);
				n++;
				command_array_size++;
			}
			command_array_size++;
		}

		else if(keyName_array[i]==0x00 && keyName_array[i+1]==0x10 && keyName_array[i+2]==0x00)
		{
			break;
		}

	}

	command_actual_array_size= 4+actual_array_name_size-command_start_point;
//	printf("#####################command_start_point: %d, command_actual_array_size: %d\n\n", command_start_point, command_actual_array_size);

//	printf("command_array_each_size1: %d, command_array_each_size2: %d, command_array_size: %d\n\n", command_array_each_size[0],command_array_each_size[1], command_array_size);
	char command_tow_dimension[command_array_each_size_i][128];
	int m=0;
	for(int i=0; i<command_array_each_size_i;i++)
	{
		for(int j=0; j<command_array_each_size[i];j++)
		{
			if(command_array[m]!='/')
			{
				command_tow_dimension[i][j]=command_array[m];
	//			printf("#####################ccommand_array %c\n", command_array[m]);
	//			printf("#####################command_tow_dimension %c, i=%d, j=%d\n", command_tow_dimension[i][j], i, j);
				if(j==command_array_each_size[i]-1)
				{
					command_tow_dimension[i][command_array_each_size[i]]=NULL;
				}

			}
			else
			{
				j--;
			}
			m++;


		}
	}
		//printf("command1: %s\n\n", command_tow_dimension[0]);
		//printf("command2: %s\n\n", command_tow_dimension[1]);
		//printf("check command2: %c, %c, %c, %c, %c\n", command_tow_dimension[1][0], command_tow_dimension[1][1], command_tow_dimension[1][2], command_tow_dimension[1][3]);





//#################################################


		PARCBuffer *commandBuffer;
		PARCBuffer *filenameBuffer;
		PARCBuffer *chunknumberBuffer;

		CCNxNameSegment *commandSegment;
		CCNxNameSegment *filenameSegment;
		CCNxNameSegment *chunknumberSegment;
		uint8_t chunkNumber[1];



		if(command_array_each_size_i==2)
		{
			commandBuffer= parcBuffer_WrapCString(command_tow_dimension[0]);
//			parcBuffer_Display(commandBuffer, 0);
			commandSegment = ccnxNameSegment_CreateTypeValue(CCNxNameLabelType_App(0x0000), commandBuffer);
//			ccnxNameSegment_Display(commandSegment, 10);


			filenameBuffer = parcBuffer_WrapCString(command_tow_dimension[1]);
//			parcBuffer_Display(filenameBuffer, 0);
			filenameSegment = ccnxNameSegment_CreateTypeValue(CCNxNameLabelType_App(0x0001), filenameBuffer);
//			ccnxNameSegment_Display(filenameSegment, 10);


			chunkNumber[0]=keyName_array[actual_array_name_size+3];
//			printf("keyName_parse(), chunkNumber[0]: %x\n", chunkNumber[0]);
			
//			printf("########################## keyName_array[actual_array_name_size+4]= %x, actual_array_name_size=%d\n\n", keyName_array[actual_array_name_size+1], actual_array_name_size);
			chunknumberBuffer = parcBuffer_Wrap(chunkNumber, 1, 0, 1);
//			parcBuffer_Display(chunknumberBuffer,0);

			chunknumberSegment = ccnxNameSegment_CreateTypeValue(CCNxNameLabelType_CHUNK, chunknumberBuffer);
//			ccnxNameSegment_Display(chunknumberSegment, 10);
		}
		else
		{

			commandBuffer= parcBuffer_WrapCString(command_tow_dimension[0]);
//			parcBuffer_Display(commandBuffer, 0);
			commandSegment = ccnxNameSegment_CreateTypeValue(CCNxNameLabelType_NAME, commandBuffer);
//			ccnxNameSegment_Display(commandSegment, 10);
		}



		//  make a ccnxName of name1 for GETNAME/GETNAME_PAYLOAD format
		char actural_array_trans_add_domain_str[128]="ccnx:";
		actual_array_trans[actual_array_trans_size]='\0';
		strcat(actural_array_trans_add_domain_str, actual_array_trans);
		CCNxName *interestKey_with_command= ccnxName_CreateFromCString(actural_array_trans_add_domain_str);
		CCNxName *interestKey_without_command= ccnxName_CreateFromCString(actural_array_trans_add_domain_str);
		//##############add command

		if(command_array_each_size_i==2)
		{
			ccnxName_Append(interestKey_with_command, commandSegment);
			ccnxName_Append(interestKey_with_command, filenameSegment);
			ccnxName_Append(interestKey_with_command, chunknumberSegment);
//	printf("keyName_parse(), interestKey_with_command\n");
//			ccnxName_Display(interestKey_with_command, 0);
		}
		else
		{
			ccnxName_Append(interestKey_with_command, commandSegment);
		}
//		printf("###########interestKey_with_command\n\n");
//		ccnxName_Display(interestKey_with_command, 10);

//#############################



//CCNxInterest *interest_test=ccnxInterest_CreateSimple(interestKey_with_command);
//CCNxMetaMessage *metamessage_test = ccnxMetaMessage_CreateFromInterest(interest_test);
//CCNxName *interestname_test=ccnxInterest_GetName(metamessage_test);
//printf("name display\n");
//ccnxName_Display(interestname_test, 0);




//    CCNxName *interestName = ccnxInterest_GetName(interest);

    char *command = ccnxSimpleFileTransferCommon_CreateCommandStringFromName(interestKey_with_command, interestKey_without_command);

    uint64_t requestedChunkNumber = ccnxSimpleFileTransferCommon_GetChunkNumberFromName(interestKey_with_command);


	//by wschoi
//	printf("keyName_parse(), command: %s\n\n", command);
//	printf("keyName_parse(), requestedChunkNumber : %d \n\n", requestedChunkNumber);

//    CCNxContentObject *result= NULL;

    if (strncasecmp(command, ccnxSimpleFileTransferCommon_CommandList, strlen(command)) == 0) {
        // This was a 'list' command. We should return the requested chunk of the directory listing.
        result = _createListResponse(serverState, interestKey_with_command, requestedChunkNumber);
    } else if (strncasecmp(command, ccnxSimpleFileTransferCommon_CommandFetch, strlen(command)) == 0) {
        // This was a 'fetch' command. We should return the requested chunk of the file specified.
        char *fileName = ccnxSimpleFileTransferCommon_CreateFileNameFromName(interestKey_with_command);

	//by wschoi
//	printf("keyName_parse(), fileName: %s\n\n", fileName);


        if (serverState->doPreChunkIntoMemory) {

//			printf("!!!!!!!!!!!!!!!!!!!!!!!!!\n\n");
			response = _createFetchResponseWithPreChunking(serverState,
                                                         interestKey_with_command,
                                                         fileName,
                                                         requestedChunkNumber);
        } else {
//			printf("@@@@@@@@@@@@@@@@@@@@@@@\n\n");
            response = _createFetchResponse(serverState,
                                          interestKey_with_command,
                                          fileName,
                                          requestedChunkNumber);

        }

        parcMemory_Deallocate((void **) &fileName);
    } else {
        printf("_createInterestResponse() called with unknown command: %s\n", command);
    }

    parcMemory_Deallocate((void **) &command);


//printf("keyName_parse(), ccnxMetaMessage_Display\n");
//ccnxContentObject_Display(response, 0);;


//    return result;
//response=result;


//	printf("\n\n");

//	return 0;


//CCNxName *name_test= ccnxContentObject_GetName(response);
//ccnxName_Display(name_test, 0);

            // At this point, response has either the requested chunk of the request file/command,
            // or remains NULL.

            if (serverState->beVerbose) {
                if (response != NULL) {
                    PARCBuffer *payload = ccnxContentObject_GetPayload(response);
                    size_t payloadSize = 0;
                    if (payload != NULL) {
                        payloadSize = parcBuffer_Limit(payload);
                    }
                    printf(" -> Responding with %ld bytes\n", payloadSize);
                }
            }

            if (response != NULL) {
                // We had a response, so send it back through the Portal.

//ccnxContentObject_Display(response, 0);;


                CCNxMetaMessage *responseMessage = ccnxMetaMessage_CreateFromContentObject(response);
//printf("ccnxMetaMessage_Display\n");
//ccnxMetaMessage_Display(responseMessage, 0);;

                if (ccnxPortal_Send(portal, responseMessage, CCNxStackTimeout_Never) == false) {
                //if (ccnxPortal_Send(portal, response, CCNxStackTimeout_Never) == false) {
                    fprintf(stderr, "ccnxPortal_Send failed (error %d). Is the Forwarder running?\n",
                            ccnxPortal_GetError(portal));
                }

//                ccnxMetaMessage_Release(&responseMessage);
//                ccnxContentObject_Release(&response);
sleep(1);
                result = true; // We have received, and responded to, at least one Interest.
            }
#else

//				response =keyName_parse(serverState, interest);
//				printf("\n\n_receiveAndAnswerInterests(), ccnxContentObject_Display\n");
//ccnxContentObject_Display(response, 0);





#endif
			}
#if 0
CCNxName *name_test= ccnxContentObject_GetName(response);
ccnxName_Display(name_test, 0);

            // At this point, response has either the requested chunk of the request file/command,
            // or remains NULL.

            if (serverState->beVerbose) {
                if (response != NULL) {
                    PARCBuffer *payload = ccnxContentObject_GetPayload(response);
                    size_t payloadSize = 0;
                    if (payload != NULL) {
                        payloadSize = parcBuffer_Limit(payload);
                    }
                    printf(" -> Responding with %ld bytes\n", payloadSize);
                }
            }

            if (response != NULL) {
                // We had a response, so send it back through the Portal.

//ccnxContentObject_Display(response, 0);;


                CCNxMetaMessage *responseMessage = ccnxMetaMessage_CreateFromContentObject(response);
//printf("ccnxMetaMessage_Display\n");
//ccnxMetaMessage_Display(responseMessage, 0);;

                if (ccnxPortal_Send(portal, responseMessage, CCNxStackTimeout_Never) == false) {
                //if (ccnxPortal_Send(portal, response, CCNxStackTimeout_Never) == false) {
                    fprintf(stderr, "ccnxPortal_Send failed (error %d). Is the Forwarder running?\n",
                            ccnxPortal_GetError(portal));
                }

                ccnxMetaMessage_Release(&responseMessage);
//                ccnxContentObject_Release(&response);

                result = true; // We have received, and responded to, at least one Interest.
            }
#endif
        }
//        ccnxMetaMessage_Release(&inboundMessage);
    }

    return result;
}

/**
 * Using the CCNxPortal API, listen for and respond to Interests matching our domain prefix (as defined in ccnxSimpleFileTransfer_Common.c).
 * The specified directoryPath is the location of the directory from which file and listing responses will originate.
 *
 * @param [in] directoryPath A string containing the path to the directory being served.
 *
 * @return true if at least one Interest is received and responded to, false otherwise.
 */
static bool
_serveFiles(ServerState *serverState)
{
    bool result = false;

    CCNxPortalFactory *factory = _setupServerPortalFactory();

    CCNxPortal *portal = ccnxPortalFactory_CreatePortal(factory, ccnxPortalRTA_Message);

    assertNotNull(portal, "Expected a non-null CCNxPortal pointer. Is the Forwarder running?");

    time_t secondsToLive = 365 * 86400; // 365 days
    if (ccnxPortal_Listen(portal, serverState->namePrefix, secondsToLive, CCNxStackTimeout_Never)) {
        printf("ccnxSimpleFileTransfer_Server: now serving files from %s\n", serverState->sourceDirectoryPath);
        result = _receiveAndAnswerInterests(serverState, portal);
    }

    ccnxPortal_Release(&portal);
    ccnxPortalFactory_Release(&factory);

    return result;
}

/**
 * Display an explanation of arguments accepted by this program.
 *
 * @param [in] programName The name of this program.
 */
static void
_displayUsage(char *programName)
{
    printf("\n%s, %s\n\n", ccnxSimpleFileTransferCommon_TutorialName, programName);

    printf(" This example file server application can provide access to files in the specified directory.\n");
    printf(" A CCNx forwarder (e.g. Metis or Athena) must be running before running it. Once running, the peer\n");
    printf(" ccnxSimpleFileTransfer_Client application can request a listing or a specified file.\n\n");

    printf("Usage: %s [-h] [-s chunkSizeInBytes] [-m] [-l <name>] <directory path>\n", programName);
    printf("    -l <CCN name> specifies the name the server will listen for.\n");
    printf("    -s <size in bytes> specifies the size of the chunks to be returned.\n");
    printf("    -m specifies that files should be pre-chunked into memory. This increases\n");
    printf("       performance at the expense of memory.\n");
    printf("Examples:\n");
    printf("  '%s ~/files' will serve the files in ~/files\n", programName);
    printf("  '%s -l ccnx:/foo/bar -d ~/files' will serve the files in ~/files, \n", programName);
    printf("      responding to the name ccnx:/foo/bar\n");
    printf("  '%s -m -s 8192 ~/files' will serve the files in ~/files, chunking in to memory first,\n", programName);
    printf("      using a 8Kb chunk size, using the default name.\n");
    printf("  '%s -h' will show this help\n\n", programName);
}

static void
_dumpState(ServerState *config)
{
    printf("Server Configuration: \n");
    char *nameString = NULL;

    if (config->namePrefix != NULL) {
        nameString = ccnxName_ToString(config->namePrefix);
    }

    printf("  namePrefix:    [%s]\n", nameString == NULL ? "MISSING" : nameString);
    printf("  doPreChunk:    [%s]\n", config->doPreChunkIntoMemory ? "true" : "false");
    printf("  directoryPath: [%s]\n", config->sourceDirectoryPath == NULL ? "MISSING" : config->sourceDirectoryPath);
    printf("  chunkSize:     [%ld]\n", config->chunkSize);
    printf("  beVerbose:     [%s]\n", config->beVerbose ? "true" : "false");

    if (nameString != NULL) {
        parcMemory_Deallocate(&nameString);
    }
}

static bool
_parseCommandLine(int argc, char *argv[], ServerState *serverState)
{
    int c;
    while ((c = getopt(argc, argv, "l:s:mhv")) != -1) {
        switch (c) {
            case 'l': // -l ccnx:/foo/bar
                if (serverState->namePrefix != NULL) {
                    ccnxName_Release(&serverState->namePrefix);
                }
                serverState->namePrefix = ccnxName_CreateFromCString(optarg);
                break;
            case 's': // -s 1200
                serverState->chunkSize = atoi(optarg);
                break;
            case 'm': // -m
                serverState->doPreChunkIntoMemory = true;
                break;
            case 'v': // -v (verbose)
                serverState->beVerbose = true;
                break;
            case 'h':
                _displayUsage(argv[0]);
                return false;
            case '?':
                if (optopt == 'l' || optopt == 's') {
                    fprintf(stderr, "Option -%c requires an argument.\n", optopt);
                } else if (isascii(optopt)) {
                    fprintf(stderr, "Unknown option `-%c'.\n", optopt);
                } else {
                    fprintf(stderr,
                            "Unknown option character `\\x%x'.\n",
                            optopt);
                }
                return false;
            default:
                break;
        }
    }

    if (argv[optind] != NULL) {
        serverState->sourceDirectoryPath = argv[optind];
    }

    return true;
}

static bool
_isStateValid(ServerState *serverState)
{
    return (serverState->chunkSize > 0)
           && (serverState->sourceDirectoryPath != 0)
           && (serverState->namePrefix != NULL);
}

int
main(int argc, char *argv[argc])
{
    int status = EXIT_FAILURE;

    ServerState serverState;
    serverState.doPreChunkIntoMemory = false;
    serverState.chunkSize = ccnxSimpleFileTransferCommon_DefaultChunkSize;
    serverState.namePrefix = ccnxName_CreateFromCString(ccnxSimpleFileTransferCommon_NamePrefix);
    serverState.sourceDirectoryPath = NULL;
    serverState.beVerbose = false;

    if (_parseCommandLine(argc, argv, &serverState)) {
        if (_isStateValid(&serverState)) {
            _dumpState(&serverState);
            _contentByFilename = parcHashMap_Create();
            status = (_serveFiles(&serverState) ? EXIT_SUCCESS : EXIT_FAILURE);
        } else {
            _displayUsage(argv[0]);
            printf("Cannot proceed with the specified parameters - stopping.\n");
            _dumpState(&serverState);
        }
    } else {
        _displayUsage(argv[0]);
    }

    if (serverState.namePrefix != NULL) {
        ccnxName_Release(&serverState.namePrefix);
    }

    exit(status);
}
