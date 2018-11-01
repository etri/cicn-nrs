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

#ifndef ccnxSimpleFileTransfer_FileIO_h
#define ccnxSimpleFileTransfer_FileIO_h

#include <parc/algol/parc_Buffer.h>

/**
 * Given a fileName and chunk number, retrieve that chunk from the specified file. The
 * contents of the chunk are returned in a PARCBuffer that must eventually be released
 * via a call to parcBuffer_Release(&buf). The chunkNumber is 0-based.
 *
 * @param [in] fileName A pointer to a string containing the name of the file to read from.
 * @param [in] chunkSize The maximum number of bytes to be returned in each chunk.
 * @param [in] chunkNumber The 0-based number of chunk to return from the file.
 *
 * @return A newly created PARCBuffer containing the contents of the specified chunk.
 */
PARCBuffer *ccnxSimpleFileTransferFileIO_GetFileChunk(const char *fileName, size_t chunkSize, uint64_t chunkNumber);

/**
 * Check if a file exists and is readable.
 * Return true if it does, false otherwise.
 *
 * @param [in] fileName A pointer to a string containing the name of the file to test.
 *
 * @return true If the file exists and is readable.
 * @return false If the file doesn't exist or is not readable.
 */
bool ccnxSimpleFileTransferFileIO_IsFileAvailable(const char *fileName);

/**
 * Return the size, in bytes, of the specified file.
 *
 * @param [in] fileName A pointer to a string containing the name of file from which to get the size.
 *
 * @return The size of the file, in bytes.
 */
size_t ccnxSimpleFileTransferFileIO_GetFileSize(const char *fileName);


/**
 * Return a PARCBuffer containing a string representing the list of files and their sizes in the directory
 * specified by 'dirName'. File names and sizes in the returned string are seperated by newlines. This
 * function does not recurse into subdirectories.
 *
 * The returned PARCBuffer must eventually be released via a call to parcBuffer_Release().
 *
 * @param dirName A pointer to a string containing the name of the directory to inspect.
 */
PARCBuffer *ccnxSimpleFileTransferFileIO_CreateDirectoryListing(const char *dirName);
#endif // ccnxSimpleFileTransfer_FileIO_h
