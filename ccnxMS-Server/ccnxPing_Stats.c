/*
 * Copyright (c) 2016, Xerox Corporation (Xerox) and Palo Alto Research Center, Inc (PARC)
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
 * @author Nacho Solis, Christopher A. Wood, Palo Alto Research Center (Xerox PARC)
 * @copyright (c) 2016, Xerox Corporation (Xerox) and Palo Alto Research Center, Inc (PARC).  All rights reserved.
 */
#include <stdio.h>

#include <ccnx/common/ccnx_Name.h>
#include <ccnx/transport/common/transport_MetaMessage.h>

#include <parc/algol/parc_HashMap.h>
#include <parc/algol/parc_Object.h>
#include <parc/algol/parc_DisplayIndented.h>

#include "ccnxPing_Stats.h"

typedef struct ping_stats_entry {
    uint64_t sendTimeInUs;
    uint64_t receivedTimeInUs;
    uint64_t rtt;
    size_t size;
    CCNxName *nameSent;
    CCNxMetaMessage *message;
} CCNxPingStatsEntry;

struct ping_stats {
    uint64_t totalRtt;
    size_t totalReceived;
    size_t totalSent;
    PARCHashMap *pings;
};

static bool
_ccnxPingStatsEntry_Destructor(CCNxPingStatsEntry **statsPtr)
{
    CCNxPingStatsEntry *entry = *statsPtr;
    ccnxName_Release(&entry->nameSent);
    if (entry->message) {
        ccnxMetaMessage_Release(&entry->message);
    }
    return true;
}

static bool
_ccnxPingStats_Destructor(CCNxPingStats **statsPtr)
{
    CCNxPingStats *stats = *statsPtr;
    parcHashMap_Release(&stats->pings);
    return true;
}

parcObject_Override(CCNxPingStatsEntry, PARCObject,
                    .destructor = (PARCObjectDestructor *) _ccnxPingStatsEntry_Destructor);

parcObject_ImplementAcquire(ccnxPingStatsEntry, CCNxPingStatsEntry);
parcObject_ImplementRelease(ccnxPingStatsEntry, CCNxPingStatsEntry);

CCNxPingStatsEntry *
ccnxPingStatsEntry_Create()
{
    return parcObject_CreateInstance(CCNxPingStatsEntry);
}

parcObject_Override(CCNxPingStats, PARCObject,
                    .destructor = (PARCObjectDestructor *) _ccnxPingStats_Destructor);

parcObject_ImplementAcquire(ccnxPingStats, CCNxPingStats);
parcObject_ImplementRelease(ccnxPingStats, CCNxPingStats);

CCNxPingStats *
ccnxPingStats_Create(void)
{
    CCNxPingStats *stats = parcObject_CreateInstance(CCNxPingStats);

    stats->pings = parcHashMap_Create();
    stats->totalSent = 0;
    stats->totalReceived = 0;
    stats->totalRtt = 0;

    return stats;
}

void
ccnxPingStats_RecordRequest(CCNxPingStats *stats, CCNxName *name, uint64_t currentTime)
{
    CCNxPingStatsEntry *entry = ccnxPingStatsEntry_Create();

    entry->nameSent = ccnxName_Acquire(name);
    entry->message = NULL;
    entry->sendTimeInUs = currentTime;

    stats->totalSent++;

    parcHashMap_Put(stats->pings, name, entry);
}

size_t
ccnxPingStats_RecordResponse(CCNxPingStats *stats, CCNxName *nameResponse, uint64_t currentTime, CCNxMetaMessage *message)
{
    size_t pingsReceived = stats->totalReceived + 1;
    CCNxPingStatsEntry *entry = (CCNxPingStatsEntry *) parcHashMap_Get(stats->pings, nameResponse);

    if (entry != NULL) {
        stats->totalReceived++;

        entry->receivedTimeInUs = currentTime;
        entry->rtt = entry->receivedTimeInUs - entry->sendTimeInUs;
        stats->totalRtt += entry->rtt;

        CCNxContentObject *contentObject = ccnxMetaMessage_GetContentObject(message);
        PARCBuffer *payload = ccnxContentObject_GetPayload(contentObject);
        entry->size = parcBuffer_Remaining(payload);

        return entry->rtt;
    }

    return 0;
}

bool
ccnxPingStats_Display(CCNxPingStats *stats)
{
    if (stats->totalReceived > 0) {
        parcDisplayIndented_PrintLine(0, "Sent = %zu : Received = %zu : AvgDelay %llu us",
                                      stats->totalSent, stats->totalReceived, stats->totalRtt / stats->totalReceived);
        return true;
    }
    return false;
}
