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
 * Right now, the FIB table is sparse.  There can be an entry for /a and for /a/b/c, but
 * not for /a/b.  This means we need to exhastively lookup all the components to make sure
 * there's not a route for it.
 *
 */

#include <config.h>
#include <stdio.h>

#include <ccnx/forwarder/metis/processor/metis_FIB.h>
#include <ccnx/forwarder/metis/processor/metis_FibEntry.h>
#include <ccnx/forwarder/metis/processor/metis_HashTableFunction.h>
#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_TreeRedBlack.h>

#include <LongBow/runtime.h>

//by wschoi
//#define LOG_CHECK

// by wschoi
#if 1

struct metis_rct {
	// KEY = tlvName, VALUE = FibEntry
	//    PARCHashCodeTable *tableByName;
	uint8_t *NameA;
	uint8_t *NameB;

	//  uint8_t *length;
	//  uint8_t *numberOfTable;
	//  MetisTlvName prefixNameA;

	unsigned refcount;

	unsigned NameA_size;
	unsigned NameB_size;
};



MetisRCT *
//metisRCT_Create(MetisLogger *logger)
metisRCT_Create()
{
	//    unsigned initialSize = 1024;
#if 0
	//  MetisRCT *rct = parcMemory_AllocateAndClear(sizeof(MetisRCT) * 16);
	MetisRCT rct[16];
	//MetisRCT *rct = parcMemory_AllocateAndClear(sizeof(MetisRCT) * 65536);

	rct->NameA=parcMemory_AllocateAndClear(sizeof(uint8_t) * 256);
	//  rct->NameA_size=parcMemory_AllocateAndClear(sizeof(unsigned) * 16);
	rct->NameA_size=0;

	rct->NameB=parcMemory_AllocateAndClear(sizeof(uint8_t) * 256);

	//rct->NameB_size=parcMemory_AllocateAndClear(sizeof(unsigned) * 16);
	rct->NameB_size=0;

	//rct->length=parcMemory_AllocateAndClear(sizeof(uint8_t) * 16);

	//rct->numberOfTable=parcMemory_AllocateAndClear(sizeof(uint8_t) * 16);
	//  rct->prefixNameA=parcMemory_AllocateAndClear(sizeof(MetisTlvName) * 16);


	rct->refcount=0;
#endif


#if 1
	MetisRCT rct[16];
	for(int i=0; i<16; i++)
	{
		rct[i].NameA=parcMemory_AllocateAndClear(sizeof(uint8_t) * 256);
		rct[i].NameB=parcMemory_AllocateAndClear(sizeof(uint8_t) * 256);
		rct[i].NameA_size=0;
		rct[i].NameB_size=0;
		rct[i].refcount=0;
	}
#else
	MetisRCT *rct=parcMemory_AllocateAndClear(sizeof(MetisRCT) * 16);
	rct->NameA=parcMemory_AllocateAndClear(sizeof(uint8_t) * 256);
	rct->NameB=parcMemory_AllocateAndClear(sizeof(uint8_t) * 256);
	rct->NameA_size=0;
	rct->NameB_size=0;
	rct->refcount=0;
#endif
	return rct;
}


	MetisRCT *
metisRct_Match(MetisRCT *rct, const uint8_t *NameA, const unsigned NameA_size)
{
	unsigned compareResult=0;

	for (size_t i=0; i< rct->refcount; i++)
	{

		if(rct[i].NameA_size==NameA_size)
		{
			for(size_t j=0; j<NameA_size;j++)
			{
				if(rct[i].NameA[j]==NameA[j])
				{
					compareResult++;

				}
			}

			if(NameA_size==compareResult)
			{
				return i; //rct->refcount;
			}
		}
	}


	return NULL;
}

	bool
metisRCT_AddOrUpdate(MetisRCT *rct, const uint8_t *newNameA, const unsigned newNameA_size, const uint8_t *newNameB, const unsigned newNameB_size )
{
	unsigned count= rct->refcount;
	rct[count].NameA=newNameA;
	rct[count].NameA_size=newNameA_size;
	rct[count].NameB=newNameB;
	rct[count].NameB_size=newNameB_size;



	rct->refcount++;


	return true;
}

#endif









//by wschoi

struct metis_tlv_name {
    uint8_t *memory;
    size_t memoryLength;

    // the refcount is shared between all copies
    unsigned  *refCountPtr;

    // the memory extents of each path segment
    MetisTlvExtent *segmentArray;
    size_t segmentArrayLength;

    // hashes of the name through different prefix lengths
    // It is allocated out to the limit (same assegmentArrayLength),
    // but only computed so far through segmentCumulativeHashArrayLength
    // This is to avoid computing the hash over unnecessary suffix segments.
    size_t segmentCumulativeHashArrayLimit;

    // the cumulative hash array length is shared between all copies, so if
    // one copy extends the array, all copies see it
    size_t *segmentCumulativeHashArrayLengthPtr;
    uint32_t *segmentCumulativeHashArray;
};



// =====================================================

/**
 * @function hashTableFunction_FibEntryDestroyer
 * @abstract Used in the hash table to destroy the data pointer when an item's removed
 * @discussion
 *   <#Discussion#>
 *
 * @param <#param1#>
 * @return <#return#>
 */
static void
_hashTableFunction_FibEntryDestroyer(void **dataPtr)
{
    metisFibEntry_Release((MetisFibEntry **) dataPtr);
}

/**
 * @function hashTableFunction_TlvNameDestroyer
 * @abstract Used in the hash table to destroy the key pointer when an item's removed
 * @discussion
 *   <#Discussion#>
 *
 * @param <#param1#>
 * @return <#return#>
 */
static void
_hashTableFunction_TlvNameDestroyer(void **dataPtr)
{
    metisTlvName_Release((MetisTlvName **) dataPtr);
}

// =====================================================

struct metis_fib {
    // KEY = tlvName, VALUE = FibEntry
    PARCHashCodeTable *tableByName;

    // KEY = tlvName.  We use a tree for the keys because that
    // has the same average insert and remove time.  The tree
    // is only used by GetEntries, which in turn is used by things
    // that want to enumerate the FIB
    PARCTreeRedBlack *tableOfKeys;

    MetisLogger *logger;

    // If there are no forward paths, we return an emtpy set.  Allocate this
    // once and return a reference to it whenever we need an empty set.
    MetisNumberSet *emptySet;
};

static MetisFibEntry *_metisFIB_CreateFibEntry(MetisFIB *fib, MetisTlvName *tlvName, const char *fwdStrategy);

// =====================================================
// Public API

MetisFIB *
metisFIB_Create(MetisLogger *logger)
{
    unsigned initialSize = 1024;

    MetisFIB *fib = parcMemory_AllocateAndClear(sizeof(MetisFIB));
    assertNotNull(fib, "parcMemory_AllocateAndClear(%zu) returned NULL", sizeof(MetisFIB));
    fib->emptySet = metisNumberSet_Create();
    fib->logger = metisLogger_Acquire(logger);
    fib->tableByName = parcHashCodeTable_Create_Size(metisHashTableFunction_TlvNameEquals,
                                                     metisHashTableFunction_TlvNameHashCode,
                                                     _hashTableFunction_TlvNameDestroyer,
                                                     _hashTableFunction_FibEntryDestroyer,
                                                     initialSize);

    fib->tableOfKeys =
        parcTreeRedBlack_Create(metisHashTableFunction_TlvNameCompare, NULL, NULL, NULL, NULL, NULL);

    if (metisLogger_IsLoggable(fib->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug)) {
        metisLogger_Log(fib->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug, __func__,
                        "FIB %p created with initialSize %u",
                        (void *) fib, initialSize);
    }

    return fib;
}

void
metisFIB_Destroy(MetisFIB **fibPtr)
{
    assertNotNull(fibPtr, "Parameter must be non-null double pointer");
    assertNotNull(*fibPtr, "Parameter must dereference to non-null pointer");

    MetisFIB *fib = *fibPtr;

    if (metisLogger_IsLoggable(fib->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug)) {
        metisLogger_Log(fib->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug, __func__,
                        "FIB %p destroyed",
                        (void *) fib);
    }

    metisNumberSet_Release(&fib->emptySet);
    metisLogger_Release(&fib->logger);
    parcTreeRedBlack_Destroy(&fib->tableOfKeys);
    parcHashCodeTable_Destroy(&fib->tableByName);
    parcMemory_Deallocate((void **) &fib);
    *fibPtr = NULL;
}

	MetisFibEntry *
metisFIB_Match(MetisFIB *fib, const MetisMessage *interestMessage)
{
	assertNotNull(fib, "Parameter fib must be non-null");
	assertNotNull(interestMessage, "Parameter interestMessage must be non-null");
	//wschoi
#ifdef LOG_CHECK
	printf("$$$$$$$$$$$$$$$$$$$$$$$$$metisFIB_Match()#####################\n\n");
#endif
//	if (metisMessage_HasName(interestMessage)) {
		// this is NOT reference counted, don't destroy it
#if 1
		MetisTlvName *tlvName=metisMessage_GetName(interestMessage);
#else 
		MetisTlvName *tlvName;
		//by wschoi
		if(metisMessage_HasGetname(interestMessage))
			//if(0)
		{

			printf("metisMessage_HasGetname() is success\n\n");

			//		    tlvName = metisMessage_GetGetname(interestMessage);
			uint8_t encodedName[] = {0x00, 0x01, 0x00, 0x05, 'a', 'p', 'p', 'l', 'e', 0x00, 0x01, 0x00, 0x03, 'p', 'i', 'e'};

			// uint8_t encodedName[] = {0x00, 0x01, 0x00, 0x01, 'X', 0x00, 0x01, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o', 0x00, 0x01, 0x00, 0x01, '1', 0x00, 0x01, 0x00, 0x01, '2'};
			tlvName = metisTlvName_Create(encodedName, sizeof(encodedName));


		}
		else
		{

			tlvName = metisMessage_GetName(interestMessage);
		}
#endif
		MetisFibEntry *longestMatchingFibEntry = NULL;
		// because the FIB table is sparse, we need to scan all the name segments in order.
		size_t segmentcount=metisTlvName_SegmentCount(tlvName);
#ifdef LOG_CHECK
		printf("metisTlvName_SegmentCount(tlvName) = %d\n\n", segmentcount);
#endif
		for (size_t i = 0; i < metisTlvName_SegmentCount(tlvName); i++) {
			MetisTlvName *prefixName = metisTlvName_Slice(tlvName, i + 1);


			//by wschoi
#ifdef LOG_CHECK
			printf("prefixname in metisFIB_Match \n");
			for(int i=0;  i<prefixName->memoryLength;i++)
			{
				printf("%c ", prefixName->memory[i]);
			}
			printf("\n\n");
			printf("\n\n");
#endif
			MetisFibEntry *fibEntry = parcHashCodeTable_Get(fib->tableByName, prefixName);

			if (fibEntry != NULL) {
				//by wschoi
#ifdef LOG_CHECK
				printf("fibEntry != NULL\n\n");
#endif

				// we can accept the FIB entry if it does not contain the ingress connection id or if
				// there is more than one forward path besides the ingress connection id.
				const MetisNumberSet *nexthops = metisFibEntry_GetNexthops(fibEntry);
				bool containsIngressConnectionId = metisNumberSet_Contains(nexthops, metisMessage_GetIngressConnectionId(interestMessage));
				size_t nextHopsCount = metisNumberSet_Length(nexthops);
				// Further control on the nextHopCount, because if the first condition is true (no ingress connection among the next hops), the number of next hops could still be 0.
				if ((!containsIngressConnectionId && nextHopsCount > 0) || nextHopsCount > 1) {
					longestMatchingFibEntry = fibEntry;
				}
			}
			else
			{
#ifdef LOG_CHECK

				printf("fibEntry is NULL\n\n");
#endif
			}

			metisTlvName_Release(&prefixName);
		}
		return longestMatchingFibEntry;
//	}

//	return NULL;
}

bool
metisFIB_AddOrUpdate(MetisFIB *fib, CPIRouteEntry *route, char const * fwdStrategy) 
{
    assertNotNull(fib, "Parameter fib must be non-null");
    assertNotNull(route, "Parameter route must be non-null");

    const CCNxName *ccnxName = cpiRouteEntry_GetPrefix(route);
    MetisTlvName *tlvName = metisTlvName_CreateFromCCNxName(ccnxName);

    MetisFibEntry *fibEntry = parcHashCodeTable_Get(fib->tableByName, tlvName);
    if (fibEntry == NULL) {
        if(fwdStrategy == NULL){
            fwdStrategy = "random"; //default strategy for now
        }
        fibEntry = _metisFIB_CreateFibEntry(fib, tlvName, fwdStrategy);
    }

    metisFibEntry_AddNexthop(fibEntry, route);

    // if anyone saved the name in a table, they copied it.
    metisTlvName_Release(&tlvName);

    return true;
}

bool
metisFIB_Remove(MetisFIB *fib, CPIRouteEntry *route)
{
    assertNotNull(fib, "Parameter fib must be non-null");
    assertNotNull(route, "Parameter route must be non-null");

    bool routeRemoved = false;

    const CCNxName *ccnxName = cpiRouteEntry_GetPrefix(route);
    MetisTlvName *tlvName = metisTlvName_CreateFromCCNxName(ccnxName);

    MetisFibEntry *fibEntry = parcHashCodeTable_Get(fib->tableByName, tlvName);
    if (fibEntry != NULL) {
        metisFibEntry_RemoveNexthopByRoute(fibEntry, route);
        if (metisFibEntry_NexthopCount(fibEntry) == 0) {
            parcTreeRedBlack_Remove(fib->tableOfKeys, tlvName);

            // this will de-allocate the key, so must be done last
            parcHashCodeTable_Del(fib->tableByName, tlvName);

            routeRemoved = true;
        }
    }

    metisTlvName_Release(&tlvName);
    return routeRemoved;
}

size_t
metisFIB_Length(const MetisFIB *fib)
{
    assertNotNull(fib, "Parameter fib must be non-null");
    return parcHashCodeTable_Length(fib->tableByName);
}

MetisFibEntryList *
metisFIB_GetEntries(const MetisFIB *fib)
{
    assertNotNull(fib, "Parameter fib must be non-null");
    MetisFibEntryList *list = metisFibEntryList_Create();

    PARCArrayList *values = parcTreeRedBlack_Values(fib->tableOfKeys);
    for (size_t i = 0; i < parcArrayList_Size(values); i++) {
        MetisFibEntry *original = (MetisFibEntry *) parcArrayList_Get(values, i);
        metisFibEntryList_Append(list, original);
    }
    parcArrayList_Destroy(&values);
    return list;
}

void
metisFIB_RemoveConnectionIdFromRoutes(MetisFIB *fib, unsigned connectionId)
{
    assertNotNull(fib, "Parameter fib must be non-null");

    // Walk the entire tree and remove the connection id from every entry.
    PARCArrayList *values = parcTreeRedBlack_Values(fib->tableOfKeys);
    for (size_t i = 0; i < parcArrayList_Size(values); i++) {
        MetisFibEntry *original = (MetisFibEntry *) parcArrayList_Get(values, i);
        metisFibEntry_RemoveNexthopByConnectionId(original, connectionId);
    }
    parcArrayList_Destroy(&values);
}

// =========================================================================
// Private API

/**
 * @function metisFib_CreateFibEntry
 * @abstract Create the given FIB entry
 * @discussion
 *    PRECONDITION: You know that the FIB entry does not exist already
 *
 * @param <#param1#>
 * @return <#return#>
 */
static MetisFibEntry *
_metisFIB_CreateFibEntry(MetisFIB *fib, MetisTlvName *tlvName, const char *fwdStrategy)
{
    MetisFibEntry *entry = metisFibEntry_Create(tlvName, fwdStrategy);

    // add a reference counted name, as we specified a key destroyer when we
    // created the table.
    MetisTlvName *copy = metisTlvName_Acquire(tlvName);
    parcHashCodeTable_Add(fib->tableByName, copy, entry);

    // this is an index structure.  It does not have its own destroyer functions in
    // the data structure.  The data in this table is the same pointer as in the hash table.
    parcTreeRedBlack_Insert(fib->tableOfKeys, copy, entry);

    return entry;
}
