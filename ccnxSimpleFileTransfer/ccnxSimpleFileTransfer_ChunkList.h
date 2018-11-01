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

#ifndef ccnxSimpleFileTransfer_ChunkList_h
#define ccnxSimpleFileTransfer_ChunkList_h

#include <parc/algol/parc_Buffer.h>
#include <parc/algol/parc_HashCode.h>

#include <ccnx/common/ccnx_ContentObject.h>

struct ccnxSimpleFileTransfer_ChunkList;

typedef struct ccnxSimpleFileTransfer_ChunkList CCNxSimpleFileTransferChunkList;

/**
 * Create a new instance of `CCNxSimpleFileTransferChunkList`, referencing the specified
 * fileName and expecting to hold the specified number of chunks. Note that this call
 * does not actually read the file in and chunk it.
 * The newly created instance must eventually be released by calling `CCNxSimpleFileTransferChunkList_Release`.
 *
 * @param [in] fileName - the name of the file whose chunks will be contained by this chunkList
 * @param [in] numChunks - the number of chunks needed to contain the file.
 */
CCNxSimpleFileTransferChunkList *ccnxSimpleFileTransferChunkList_Create(const char *fileName, size_t numChunks);

/**
 * Increase the number of references to a `CCNxSimpleFileTransferChunkList` instance.
 *
 * Note that a new `CCNxSimpleFileTransferChunkList` is not created,
 * only that the given `CCNxSimpleFileTransferChunkList` reference count is incremented.
 * Discard the reference by invoking {@link CCNxSimpleFileTransferChunkList_Release}.
 *
 * @param [in] name A pointer to the original `CCNxSimpleFileTransferChunkList`.
 * @return The value of the input parameter @p name.
 *
 * Example:
 * @code
 * {
 *     CCNxSimpleFileTransferChunkList *original = CCNxSimpleFileTransferChunkList_Create();
 *
 *     CCNxSimpleFileTransferChunkList *reference = CCNxSimpleFileTransferChunkList_Acquire(original);
 *
 *     CCNxSimpleFileTransferChunkList_Release(&original);
 *     CCNxSimpleFileTransferChunkList_Release(&reference);
 * }
 * @endcode
 *
 * @see CCNxSimpleFileTransferChunkList_Release
 */
CCNxSimpleFileTransferChunkList *ccnxSimpleFileTransferChunkList_Acquire(
    const CCNxSimpleFileTransferChunkList *instance);


/**
 * Release a previously acquired reference to the specified instance,
 * decrementing the reference count for the instance.
 *
 * The pointer to the instance is set to NULL as a side-effect of this function.
 *
 * If the invocation causes the last reference to the instance to be released,
 * the instance is deallocated and the instance's implementation will perform
 * additional cleanup and release other privately held references.
 *
 * @param [in,out] nameP A pointer to a pointer to the instance to release.
 *
 * Example:
 * @code
 * {
 *     CCNxSimpleFileTransferChunkList *name = CCNxSimpleFileTransferChunkList_Create(...);
 *
 *     CCNxSimpleFileTransferChunkList_Release(&name);
 * }
 * @endcode
 *
 * @see {@link CCNxSimpleFileTransferChunkList_Acquire}
 */
void ccnxSimpleFileTransferChunkList_Release(CCNxSimpleFileTransferChunkList **chunkListPtr);

/**
 * Return true if two `CCNxSimpleFileTransferChunkList` instances are equal to each other.
 *
 * @param [in] a a `CCNxSimpleFileTransferChunkList` instance
 * @param [in] b another `CCNxSimpleFileTransferChunkList` instance
 *
 * @return true if the two instances are equal.
 * @return false if the two instances are not equal.
 */
bool ccnxSimpleFileTransferChunkList_Equals(const CCNxSimpleFileTransferChunkList *a,
                                            const CCNxSimpleFileTransferChunkList *b);

/**
 * Assign a `CCNxContentObject` to the specified slot in the specified chunk list.
 * The chunk list will acquire a reference to the ContentObject. If the specified slot
 * is already in use, the existing CCNxContentObject will be released.
 *
 * @param [in] chunkList - the chunk list to which to add the content object
 * @param [in] slot - the slot in the chunk list on which to add the content object
 * @param [in] content the `CCNxContentObject` instance to assign to the specified slot.
 *
 */
void ccnxSimpleFileTransferChunkList_SetChunk(CCNxSimpleFileTransferChunkList *chunkList,
                                              int slot, const CCNxContentObject *content);

/**
 * Return a pointer to the `CCNxContentObject` instance in the specified slot in the
 * specified chunk list.
 *
 * @param [in] chunkList - the chunk list from which to retrieve the content object pointer.
 * @param [in] slot - the slot in the chunk list from which to retrieve the content object.
 * @return the `CCNxContentObject` instance assigned to the specified slot, or NULL if there is none.
 *
 */CCNxContentObject *ccnxSimpleFileTransferChunkList_GetChunk(CCNxSimpleFileTransferChunkList *chunkList, int slot);

/**
 * Return the number of chunks contained in the specified chunk list. This assumes the chunk list
 * has been fully populated (by calling `ccnxSimpleFileTransferChunkList_SetChunk`), for each chunk
 * slot.
 *
 * @param [in] chunkList - the chunk list from which to retrieve the number of chunks.
 * @return the the number of chunks in the specified chunk list.
 */
uint64_t ccnxSimpleFileTransferChunkList_GetNumChunks(CCNxSimpleFileTransferChunkList *chunkList);

/**
 * Return a PARCHashCode value for the specified `CCNxSimpleFileTransferChunkList` instance.
 * The value is based on the chunkList's filename and number of chunks.
 *
 * @param [in] chunkList A pointer to `CCNxSimpleFileTransferChunkList` instance.
 * @return a PARCHashCode
 *
 * @see `PARCHashCode`
 */
PARCHashCode ccnxSimpleFileTransferChunkList_HashCode(const CCNxSimpleFileTransferChunkList *chunkList);
#endif // ccnxSimpleFileTransfer_ChunkList_h
