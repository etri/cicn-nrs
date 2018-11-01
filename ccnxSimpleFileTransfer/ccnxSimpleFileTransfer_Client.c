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
#include <stdio.h>
#include <strings.h>
#include <unistd.h>
#include <ctype.h>

#include "ccnxSimpleFileTransfer_Common.h"

#include <ccnx/api/ccnx_Portal/ccnx_PortalRTA.h>
#include <parc/developer/parc_Stopwatch.h>
#include <fcntl.h>
//#include <ccnx/common/ccnx_NameLabel.h>
typedef struct clientState {
    CCNxName *namePrefix;
    char *commandArg[2];
    bool beVerbose;
    bool doSaveToDisk;

    uint64_t numBytesTransferred;
    uint64_t transferTimeInMillis;
    int fileBeingTransferred;
} ClientState;

/**
 * Create a new CCNxPortalFactory instance using a randomly generated identity saved to
 * the specified keystore.
 *
 * @return A new CCNxPortalFactory instance which must eventually be released by calling ccnxPortalFactory_Release().
 */
static CCNxPortalFactory *
_setupConsumerPortalFactory(void)
{
    const char *keystoreName = "client.keystore";
    const char *keystorePassword = "keystore_password";
    const char *subjectName = "ccnxSimpleFileTransfer_Client";

    return ccnxSimpleFileTransferCommon_SetupPortalFactory(keystoreName, keystorePassword, subjectName);
}

/**
 * Given a sequential chunk of a 'list' response, append it to the in-memory buffer
 * that holds the listing. When the directory listing is complete, return it as a
 * string. The string must be freed by the caller.
 *
 * @param [in] payload A PARCBuffer containing the chunk of the directory listing to be appended.
 * @param [in] chunkNumber The number of the chunk that this payload belongs to.
 * @param [in] finalChunkNumber The number of the final chunk in this list response.
 *
 * @return A string containing the complete directory listing, or NULL if the complete directory
 *         listing hasn't yet been received.
 */
static char *
_assembleDirectoryListing(PARCBuffer *payload, uint64_t chunkNumber, uint64_t finalChunkNumber)
{
    char *result = NULL;
    static PARCBufferComposer *directoryList = NULL;

    if (directoryList == NULL) {
        directoryList = parcBufferComposer_Create();
    }

    parcBufferComposer_PutBuffer(directoryList, payload);

    if (chunkNumber == finalChunkNumber) {
        PARCBuffer *buffer = parcBufferComposer_ProduceBuffer(directoryList);

        // Since this was the last chunk, return the completed directory listing.
        result = parcBuffer_ToString(buffer);
        parcBuffer_Release(&buffer);
        parcBufferComposer_Release(&directoryList);
    }

    return result;
}


/**
 * Receive a chunk of a directory listing and add it to the directory listing that we're
 * building. When it's complete, print it and return true. We assume the chunks arrive in the
 * correct order.
 *
 * @param [in] payload A PARCBuffer containing the chunk of the directory listing to write.
 * @param [in] chunkNumber The number of the chunk to be written.
 * @param [in] finalChunkNumber The number of the final chunk in the directory listing.
 *
 * @return true if the entire listing has been received, false otherwise.
 */
static bool
_receiveDirectoryListingChunk(ClientState *clientState,
                              PARCBuffer *payload, uint64_t chunkNumber, uint64_t finalChunkNumber)
{
    bool result = false;
    char *directoryList = _assembleDirectoryListing(payload, chunkNumber, finalChunkNumber);

    // When the directory listing is complete, dirListing will be non-NULL.
    if (directoryList != NULL) {
        printf("Directory Listing follows:\n");
        printf("%s", directoryList);
        parcMemory_Deallocate((void **) &directoryList);
        result = true;
    }
    return result;
}

/*
 * Receive a chunk of a file and append it to the local file of the specified name. When the file is
 * complete, print a message stating so and return true. Otherwise, print a message showing the
 * file transfer progress and return false. We assume the file chunks arrive in the correct order.
 *
 * @param [in] fileName The full path to the file to be received.
 * @param [in] payload A PARCBuffer containing the chunk of the file to write.
 * @param [in] chunkNumber The number of the chunk to be written.
 * @param [in] finalChunkNumber The number of the final chunk in the directory listing.
 *
 * @return true if the entire file has been written, false otherwise.
 */
static bool
_receiveFileChunk(ClientState *clientState, const char *fileName,
                  const PARCBuffer *payload, uint64_t chunkNumber, uint64_t finalChunkNumber)
{
    // The file is complete when the chunknumber of the current ContentObject
    // matches the one specified in the finalChunkNumber.
    bool isComplete = (chunkNumber == finalChunkNumber);

    if (clientState->doSaveToDisk) {
        if (chunkNumber == 0) {
            // If we're the first chunk (chunk #0), then make sure we're starting with an empty file.
            clientState->fileBeingTransferred = open(fileName, O_CREAT | O_WRONLY, 0777);
        }

        void *buffer = parcBuffer_Overlay((PARCBuffer *) payload, 0);
        ssize_t numBytesWritten = write(clientState->fileBeingTransferred, buffer, parcBuffer_Remaining(payload));
    }

    if (isComplete) {
        printf("File '%s' has been fully transferred in %ld chunks.\n", fileName,
               (unsigned long) finalChunkNumber + 1L);

        if (clientState->doSaveToDisk) {
            close(clientState->fileBeingTransferred);
        }
    } else {
        printf("File '%s' has been %04.2f%% transferred.\r", fileName,
               ((float) chunkNumber / (float) finalChunkNumber) * 100.0f);
        fflush(stdout);
    }

    return isComplete;
}

/**
 * Receive a ContentObject message that comes back from the ccnxSimpleFileTransfer_Server in response to an Interest we sent.
 * This message will be a chunk of the requested content, and should be received in ordered sequence.
 * Depending on the CCNxName in the content object, we hand it off to either _receiveFileChunk() or
 * _receiveDirectoryListingChunk() to process.
 *
 * @param [in] contentObject A CCNxContentObject containing a response to an CCNxInterest we sent.
 * @param [in] domainPrefix A CCNxName containing the domain prefix of the content we requested.
 *
 * @return The number of chunks of the content left to transfer.
 */
static uint64_t
_receiveContentObject(ClientState *clientState, CCNxContentObject *contentObject)
{
    CCNxName *contentName = ccnxContentObject_GetName(contentObject);

    uint64_t chunkNumber = ccnxSimpleFileTransferCommon_GetChunkNumberFromName(contentName);

    // Get the number of the final chunk, as specified by the sender.
    uint64_t finalChunkNumberSpecifiedByServer = ccnxContentObject_GetFinalChunkNumber(contentObject);

    // Get the type of the incoming message. Was it a response to a fetch' or a 'list' command?
    char *command = ccnxSimpleFileTransferCommon_CreateCommandStringFromName(contentName, clientState->namePrefix);

    // Process the payload.
    PARCBuffer *payload = ccnxContentObject_GetPayload(contentObject);
    clientState->numBytesTransferred += parcBuffer_Remaining(payload);

    if (strncasecmp(command, ccnxSimpleFileTransferCommon_CommandList, strlen(command)) == 0) {
        // This is a chunk of the directory listing.
        _receiveDirectoryListingChunk(clientState, payload, chunkNumber, finalChunkNumberSpecifiedByServer);
    } else if (strncasecmp(command, ccnxSimpleFileTransferCommon_CommandFetch, strlen(command)) == 0) {
        // This is a chunk of a file.
        char *fileName = ccnxSimpleFileTransferCommon_CreateFileNameFromName(contentName);
        _receiveFileChunk(clientState, fileName, payload, chunkNumber, finalChunkNumberSpecifiedByServer);
        parcMemory_Deallocate((void **) &fileName);
    } else {
        printf("ccnxSimpleFileTransfer_Client: Unknown command: %s\n", command);
    }

    parcMemory_Deallocate((void **) &command);

    return (finalChunkNumberSpecifiedByServer - chunkNumber); // number of chunks left to transfer
}

/**
 * Create and return a CCNxInterest whose Name contains our commend (e.g. "fetch" or "list"),
 * and, optionally, the name of a target object (e.g. "file.txt"). The newly created CCNxInterest
 * must eventually be released by calling ccnxInterest_Release().
 *
 * @param command The command to embed in the created CCNxInterest.
 * @param targetName The name of the content, if any, that the command applies to.
 *
 * @return A newly created CCNxInterest for the specified command and targetName.
 */
static CCNxInterest *
_createInterest(ClientState *clientState)
{
    char *command = clientState->commandArg[0];
    char *targetName = clientState->commandArg[1];

    CCNxName *interestName = ccnxName_Copy(clientState->namePrefix); // Start with the prefix. We append to this.

    // Create a NameSegment for our command, which we will append after the prefix we just created.
    PARCBuffer *commandBuffer = parcBuffer_WrapCString(command);

	//by wschoi
    CCNxNameSegment *commandSegment = ccnxNameSegment_CreateTypeValue(CCNxNameLabelType_App(0x0000), commandBuffer);


    //CCNxNameSegment *commandSegment = ccnxNameSegment_CreateTypeValue(CCNxNameLabelType_NAME, commandBuffer);
    parcBuffer_Release(&commandBuffer);

    // Append the new command segment to the prefix
    ccnxName_Append(interestName, commandSegment);
    ccnxNameSegment_Release(&commandSegment);

    // If we have a target, then create another NameSegment for it and append that.
    if (targetName != NULL) {
        // Create a NameSegment for our target object
        PARCBuffer *targetBuf = parcBuffer_WrapCString(targetName);

//by wschoi
        CCNxNameSegment *targetSegment = ccnxNameSegment_CreateTypeValue(CCNxNameLabelType_App(0x0001), targetBuf);
        //CCNxNameSegment *targetSegment = ccnxNameSegment_CreateTypeValue(CCNxNameLabelType_NAME, targetBuf);
        parcBuffer_Release(&targetBuf);

        // Append it to the ccnxName.
        ccnxName_Append(interestName, targetSegment);
        ccnxNameSegment_Release(&targetSegment);
    }

    CCNxInterest *result = ccnxInterest_CreateSimple(interestName);
    ccnxName_Release(&interestName);

    return result;
}

/**
 * Wait for a response to a previously issued Interest. This function reads from the specified Portal
 * until the requested content is fully received. It's not very clever, as it ignores all incoming
 * portal message types except those that are CCNxContentObjects.
 *
 * @param portal An instance of CCNxPortal to read from.
 *
 * @return true If the requested content has been fully received, false otherwise.
 */
static bool
_receiveResponseToIssuedInterest(ClientState *clientState, CCNxPortal *portal)
{
    bool isTransferComplete = false;

    while (isTransferComplete == false && ccnxPortal_IsError(portal) == false) {
        CCNxMetaMessage *response = ccnxPortal_Receive(portal, CCNxStackTimeout_Never);

        if (response != NULL) {
            if (ccnxMetaMessage_IsContentObject(response)) {
                CCNxContentObject *contentObject = ccnxMetaMessage_GetContentObject(response);

                // Receive the content message. This returns the number of blocks remaining
                // in the transfer. If it returns 0, it was the final block of the content
                // and we're done.

                if (_receiveContentObject(clientState, contentObject) == 0) {
                    isTransferComplete = true;
                }
            }
            ccnxMetaMessage_Release(&response);
        }
    }

    return isTransferComplete;
}

/**
 * Given a command (e.g "fetch") and an optional target name (e.g. "file.txt"), create an appropriate CCNxInterest
 * and write it to the Portal.
 *
 * @param command The command to be handled.
 * @param targetName The name of the target content, if any, that the command applies to.
 *
 * @return true If a CCNxInterest for the specified command and optional target was successfully issued and answered.
 */
static bool
_executeUserCommand(ClientState *clientState)
{
    bool result = false;
    CCNxPortalFactory *factory = _setupConsumerPortalFactory();

    CCNxPortal *portal = ccnxPortalFactory_CreatePortal(factory, ccnxPortalRTA_Chunked);

    assertNotNull(portal, "Expected a non-null CCNxPortal pointer.");

    // Given the user's command and optional target, create an Interest.
    CCNxInterest *interest = _createInterest(clientState);

    // Send the Interest through the Portal, and wait for a response.
    CCNxMetaMessage *message = ccnxMetaMessage_CreateFromInterest(interest);

    PARCStopwatch *timer = parcStopwatch_Create();
    parcStopwatch_Start(timer);

	//printf("ccnxMetaMessage_Display(messsage, 3)\n\n");
	//ccnxMetaMessage_Display(message, 3);

    if (ccnxPortal_Send(portal, message, CCNxStackTimeout_Never)) {
        result = _receiveResponseToIssuedInterest(clientState, portal);
    }

    clientState->transferTimeInMillis = parcStopwatch_ElapsedTimeMillis(timer);

    parcStopwatch_Release(&timer);
    ccnxMetaMessage_Release(&message);
    ccnxInterest_Release(&interest);
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

    printf(" This example application can retrieve a specified file or the list of available files from\n");
    printf(" the ccnxSimpleFileTransfer_Server application, which should be running when this application is used.\n");
    printf(" A CCNx forwarder (e.g. Athena or Metis) must also be running.\n\n");

    printf("Usage: %s  [-h] [-m] [-l <name>] <[list | fetch <filename>]>\n", programName);
    printf("    -l <name> specifies the name the server will listen for.\n");
    printf("    -m specifies that the incoming file not be saved to disk. Just discard the chunks as they arrive.\n");

    printf("Examples:\n");
    printf("  '%s list' will list the files in the directory served by ccnxSimpleFileTransfer_Server\n", programName);
    printf("  '%s fetch <filename>' will fetch the specified filename\n", programName);
    printf("  '%s -l ccnx:/foo/bar list' will list the files the files in ~/files, \n", programName);
    printf("      assuming there is an instance of ccnxSimpleFileTransfer_Server listening for ccnx:/foo/bar\n");
    printf("  '%s -m fetch foo.zip' will fetch foo.zip, but not save it to disk.\n", programName);
    printf("  '%s -h' will show this help\n\n", programName);
}

static bool
_isConfigValid(ClientState *config)
{
    bool result = false;

    if ((config->namePrefix != NULL) && (config->commandArg[0] != NULL)) {
        if (strcasecmp(config->commandArg[0], ccnxSimpleFileTransferCommon_CommandFetch) == 0) {
            // If the command is 'fetch', we need a filename argument too.
            result = (config->commandArg[1] != NULL);
        } else {
            // otherwise, the only other command we know is 'list'.
            result = strcasecmp(config->commandArg[0], ccnxSimpleFileTransferCommon_CommandList) == 0;
        }
    }
    return result;
}

static bool
_parseCommandLine(int argc, char *argv[], ClientState *clientState)
{
    int c;
    while ((c = getopt(argc, argv, "l:mvh")) != -1) {
        switch (c) {
            case 'l': // -l ccnx:/foo/bar
                clientState->namePrefix = ccnxName_CreateFromCString(optarg);
                break;
            case 'm': // -m
                clientState->doSaveToDisk = false;
                break;
            case 'v': // -v (verbose)
                clientState->beVerbose = true;
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
                _displayUsage(argv[0]);
                return false;
            default:
                break;
        }
    }

    int argIndex = 0;
    for (int index = optind; index < optind + 2; index++) {
        clientState->commandArg[argIndex++] = argv[index];
    }
    return true;
}

static void
_dumpConfig(ClientState *config)
{
    printf("Client Configuration: \n");
    char *nameString = NULL;

    if (config->namePrefix != NULL) {
        nameString = ccnxName_ToString(config->namePrefix);
    }

    printf("  namePrefix:    [%s]\n", nameString == NULL ? "MISSING" : nameString);
    printf("  doSaveToDisk:  [%s]\n", config->doSaveToDisk ? "true" : "false");
    printf("  beVerbose:     [%s]\n\n", config->beVerbose ? "true" : "false");

    printf("  Command: [%s] [%s]\n\n",
           config->commandArg[0] ? config->commandArg[0] : "MISSING",
           config->commandArg[1] ? config->commandArg[1] : "");

    if (nameString != NULL) {
        parcMemory_Deallocate(&nameString);
    }
}

int
main(int argc, char *argv[argc])
{
    int status = EXIT_FAILURE;

    ClientState clientState;
    clientState.doSaveToDisk = true;
    clientState.beVerbose = false;
    clientState.namePrefix = ccnxName_CreateFromCString(ccnxSimpleFileTransferCommon_NamePrefix);
    clientState.transferTimeInMillis = 0;
    clientState.numBytesTransferred = 0;
    clientState.commandArg[0] = NULL;          // 'fetch' or 'list'
    clientState.commandArg[1] = NULL;          // optional filename for 'fetch'
    clientState.fileBeingTransferred = -1;

    if (_parseCommandLine(argc, argv, &clientState)) {
        _dumpConfig(&clientState);
        if (_isConfigValid(&clientState)) {
            if (_executeUserCommand(&clientState)) {
                double mb = (double) clientState.numBytesTransferred / (double) (1024 * 1024);
                double secs = clientState.transferTimeInMillis / 1000.0;
                double mbPerSec = mb / secs;

                printf("%" PRIu64 " bytes transferred in %" PRIu64 " ms (%.3f MB/sec)\n",
                       clientState.numBytesTransferred, clientState.transferTimeInMillis, mbPerSec);

                status = EXIT_SUCCESS;
            }

        } else {
            _displayUsage(argv[0]);
        }
    }

    if (clientState.namePrefix != NULL) {
        ccnxName_Release(&clientState.namePrefix);
    }

    exit(status);
}
