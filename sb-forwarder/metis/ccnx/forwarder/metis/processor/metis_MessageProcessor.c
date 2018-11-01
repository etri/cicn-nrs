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

/*****NOTICE*******
* When you use 'fopen()' function, you shoud change "file_path" according to installing your own path for 'CICN-NRS' 
* end of notice */

/**
 */

#include <config.h>
#include <stdio.h>
#include <string.h>

#include <ccnx/forwarder/metis/processor/metis_MessageProcessor.h>
#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_ArrayList.h>

#include <ccnx/forwarder/metis/processor/metis_StandardPIT.h>
#include <ccnx/forwarder/metis/processor/metis_FIB.h>

#include <ccnx/forwarder/metis/content_store/metis_ContentStoreInterface.h>
#include <ccnx/forwarder/metis/content_store/metis_LRUContentStore.h>

#include <ccnx/forwarder/metis/strategies/metis_StrategyImpl.h>
#include <ccnx/forwarder/metis/strategies/strategy_Rnd.h>
#include <ccnx/forwarder/metis/strategies/strategy_LoadBalancer.h>
#include <ccnx/forwarder/metis/strategies/strategy_RndSegment.h>
#include <ccnx/forwarder/metis/strategies/strategy_LoadBalancerWithPD.h>


#include <LongBow/runtime.h>

//by wschoi

#include <parc/logging/parc_LogReporterTextStdout.h>

//by wschoi

//#define LOG_CHECK



//by wschoi
#if 1

#define MAX_RCT_SIZE 65536

struct metis_rct {
	uint8_t *NameA;
	uint8_t *NameB;

	unsigned refcount;

	unsigned NameA_size;
	unsigned NameB_size;
};

#endif



//by wschoi
#if 1


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



struct metis_message {
    MetisLogger *logger;

    MetisTicks receiveTime;
    unsigned ingressConnectionId;

    PARCEventBuffer *messageBytes;
    uint8_t *messageHead;

    unsigned refcount;

    struct tlv_skeleton skeleton;

    bool hasKeyId;
    uint32_t keyIdHash;
    bool isKeyIdVerified;

    bool hasContentObjectHash;
    // may be null, even if hasContentObjectHash true due to lazy calculation
    PARCBuffer *contentObjectHash;
    PARCBuffer *certificate;

    PARCBuffer *publicKey;

    bool hasInterestLifetime;
    uint64_t interestLifetimeTicks;

    bool hasExpiryTimeTicks;
    uint64_t expiryTimeTicks;
    bool hasRecommendedCacheTimeTicks;
    uint64_t recommendedCacheTimeTicks;

    bool hasName;
    MetisTlvName *name;

	//by wschoi
    bool hasGetname;
    MetisTlvName *Getname;    

    //by wschoi
    bool hasPayloadGetname;
    MetisTlvName *payloadGetname;

    //by wschoi
    bool hasKeyname;
    MetisTlvName *Keyname;

    //by wschoi
    bool registration_from_CR;
    bool registration_from_Consumer;
    bool hasRegname;
    MetisTlvName *Regname;

    bool registration_add_from_CR;
    bool registration_add_from_Consumer;
    bool hasReg_addname;
    MetisTlvName *Reg_addname;


    bool registration_del_from_CR;
    bool registration_del_from_Consumer;
    bool hasReg_delname;
    MetisTlvName *Reg_delname;

    bool registration_dereg_from_CR;
    bool registration_dereg_from_Consumer;
    bool hasReg_deregname;
    MetisTlvName *Reg_deregname;



    bool hasFragmentPayload;

    MetisMessagePacketType packetType;


    bool hasPathLabel;
    uint64_t pathLabel;

    bool hasWldr;
    //the following fields are valid only if hasWldr is true
    uint8_t wldrType;
    uint16_t wldrLbl;           //if wldrType == WLDR_LBL this indicates the message label
    //if wldrType == WLDR_NOTIFICATION this indicates the expected message label
    uint16_t wldrLastReceived;  //this field is valid only when wldrType == WLDR_NOTIFICATION. In this case,
    //all the messages between wldrLbl (included) and wldrLastReceived (excluded)
    //are considered lost
};



#endif




/**
 * @typedef MetisProcessorStats
 * @abstract MessageProcessor         event counters
 *
 * @constant countReceived            All received messages, the good, the bad, the ugly
 * @constant countInterestsReceived   Count of received interests
 * @constant countObjectsReceived     Count of received content objects
 *
 * @constant countInterestsAggregated         Number of Interests suppressed via PIT table aggregation
 * @constant countInterestForwarded           Number of Interests forwarded, for each outbound interface
 * @constant countObjectsForwarded            Number of Content Objects forwarded, for each outbound interface
 * @constant countInterestsSatisfiedFromStore Number of Interests satisfied from the Content Store
 *
 * @constant countDropped              Number of messages dropped, for any reason
 * @constant countInterestsDropped     Number of Interests dropped, for any reason
 * @constant countDroppedNoRoute       Number of Interests dropped because no FIB entry
 * @constant countDroppedNoReversePath Number of Content Objects dropped because no PIT entry
 * @constant countDroppedNoHopLimit    Number of Interests without a HopLimit
 * @constant countDroppedZeroHopLimitFromRemote Number of Interest from a remote node with a 0 hoplimit
 *
 * @constant countDroppedZeroHopLimitToRemote Number of Interest not forwarded to a FIB entry because hoplimit is 0 and its remote
 * @constant countSendFailures         Number of send failures (problems using MetisIoOperations)
 *
 * @discussion <#Discussion#>
 */
typedef struct metis_processor_stats {
    uint32_t countReceived;
    uint32_t countInterestsReceived;
    uint32_t countObjectsReceived;

    uint32_t countInterestsAggregated;

    uint32_t countDropped;
    uint32_t countInterestsDropped;
    uint32_t countDroppedNoRoute;
    uint32_t countDroppedNoReversePath;

    uint32_t countDroppedConnectionNotFound;
    uint32_t countObjectsDropped;

    uint32_t countSendFailures;
    uint32_t countInterestForwarded;
    uint32_t countObjectsForwarded;
    uint32_t countInterestsSatisfiedFromStore;

    uint32_t countDroppedNoHopLimit;
    uint32_t countDroppedZeroHopLimitFromRemote;
    uint32_t countDroppedZeroHopLimitToRemote;
} _MetisProcessorStats;

struct metis_message_processor {
    MetisForwarder *metis;
    MetisLogger *logger;
    MetisTap *tap;

    MetisPIT *pit;
    MetisContentStoreInterface *contentStore;
    MetisFIB *fib;

	//by wschoi
	//MetisRCT *rct;
	MetisRCT rct[MAX_RCT_SIZE];

    bool store_in_cache;
    bool serve_from_cache;

    _MetisProcessorStats stats;
};

static void metisMessageProcessor_Drop(MetisMessageProcessor *processor, MetisMessage *message);
static void metisMessageProcessor_ReceiveInterest(MetisMessageProcessor *processor, MetisMessage *interestMessage);

//by wschoi
static void metisMessageProcessor_ReceiveInterestRegistrationMS(MetisMessageProcessor *processor, MetisMessage *interestMessage);
//by wschoi
static void metisMessageProcessor_ReceiveInterestRegistrationMS_add(MetisMessageProcessor *processor, MetisMessage *interestMessage);
//by wschoi
static void metisMessageProcessor_ReceiveInterestRegistrationMS_del(MetisMessageProcessor *processor, MetisMessage *interestMessage);
//by wschoi
static void metisMessageProcessor_ReceiveInterestRegistrationMS_dereg(MetisMessageProcessor *processor, MetisMessage *interestMessage);
//by wschoi

//by wschoi
static void metisMessageProcessor_ReceiveInterestRegistration(MetisMessageProcessor *processor, MetisMessage *interestMessage);
//by wschoi
static void metisMessageProcessor_ReceiveInterestRegistration_add(MetisMessageProcessor *processor, MetisMessage *interestMessage);
//by wschoi
static void metisMessageProcessor_ReceiveInterestRegistration_del(MetisMessageProcessor *processor, MetisMessage *interestMessage);
//by wschoi
static void metisMessageProcessor_ReceiveInterestRegistration_dereg(MetisMessageProcessor *processor, MetisMessage *interestMessage);

//by wschoi
static void metisMessageProcessor_ReceiveInterestGetname(MetisMessageProcessor *processor, MetisMessage *interestMessage);

//by wschoi
//static void metisMessageProcessor_ReceiveInterestkeyname(MetisMessageProcessor *processor, MetisMessage *interestMessage);


static void metisMessageProcessor_ReceiveContentObject(MetisMessageProcessor *processor, MetisMessage *objectMessage);

//by wschoi
static void metisMessageProcessor_ReceiveContentObjectPayloadGetname(MetisMessageProcessor *processor, MetisMessage *objectMessage);

static unsigned metisMessageProcessor_ForwardToNexthops(MetisMessageProcessor *processor, MetisMessage *message, const MetisNumberSet *nexthops);

static void metisMessageProcessor_ForwardToInterfaceId(MetisMessageProcessor *processor, MetisMessage *message, unsigned interfaceId);

// ============================================================
// Public API

MetisMessageProcessor *
metisMessageProcessor_Create(MetisForwarder *metis)
{
    size_t objectStoreSize = metisConfiguration_GetObjectStoreSize(metisForwarder_GetConfiguration(metis));

    MetisMessageProcessor *processor = parcMemory_AllocateAndClear(sizeof(MetisMessageProcessor));
    assertNotNull(processor, "parcMemory_AllocateAndClear(%zu) returned NULL", sizeof(MetisMessageProcessor));
    memset(processor, 0, sizeof(MetisMessageProcessor));

    processor->metis = metis;
    processor->logger = metisLogger_Acquire(metisForwarder_GetLogger(metis));
    processor->pit = metisStandardPIT_Create(metis);

    processor->fib = metisFIB_Create(processor->logger);


	//by wschoi
	//  for(int i=0 ; i<16 ; i++)
	//  {
	//      processor->rct[i] = metisRCT_Create();
	//  }
	for(int i=0 ; i<MAX_RCT_SIZE ; i++)
	{
		processor->rct[i].NameA=parcMemory_AllocateAndClear(sizeof(uint8_t) * 256);
		processor->rct[i].NameB=parcMemory_AllocateAndClear(sizeof(uint8_t) * 256);
		processor->rct[i].NameA_size=0;
		processor->rct[i].NameB_size=0;
		processor->rct[i].refcount=0;
	}





    if (metisLogger_IsLoggable(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug)) {
        metisLogger_Log(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug, __func__,
                        "MessageProcessor %p created",
                        (void *) processor);
    }

    MetisContentStoreConfig contentStoreConfig = {
        .objectCapacity = objectStoreSize,
    };

    // Currently, this will instantiate an LRUContentStore. Perhaps someday it'll switch stores
    // based on the MetisContentStoreConfig passed to it.
    processor->contentStore = metisLRUContentStore_Create(&contentStoreConfig, processor->logger);

    //the two flags for the cache are set to true by default. If the cache
    //is active it always work as expected unless the use modifies this
    //values using metis_control
    processor->store_in_cache = true;
    processor->serve_from_cache = true;

    return processor;
}

void
metisMessageProcessor_SetContentObjectStoreSize(MetisMessageProcessor *processor, size_t maximumContentStoreSize)
{
    assertNotNull(processor, "Parameter processor must be non-null");
    metisContentStoreInterface_Release(&processor->contentStore);

    MetisContentStoreConfig contentStoreConfig = {
        .objectCapacity = maximumContentStoreSize
    };

    processor->contentStore = metisLRUContentStore_Create(&contentStoreConfig, processor->logger);
}

void
metisMessageProcessor_ClearCache(MetisMessageProcessor *processor)
{
    assertNotNull(processor, "Parameter processor must be non-null");
    size_t objectStoreSize = metisConfiguration_GetObjectStoreSize(metisForwarder_GetConfiguration(processor->metis));

    metisContentStoreInterface_Release(&processor->contentStore);

    MetisContentStoreConfig contentStoreConfig = {
        .objectCapacity = objectStoreSize,
    };

    processor->contentStore = metisLRUContentStore_Create(&contentStoreConfig, processor->logger);
}

MetisContentStoreInterface *
metisMessageProcessor_GetContentObjectStore(const MetisMessageProcessor *processor)
{
    assertNotNull(processor, "Parameter processor must be non-null");
    return processor->contentStore;
}

void
metisMessageProcessor_Destroy(MetisMessageProcessor **processorPtr)
{
    assertNotNull(processorPtr, "Parameter must be non-null double pointer");
    assertNotNull(*processorPtr, "Parameter dereference to non-null pointer");

    MetisMessageProcessor *processor = *processorPtr;

    if (metisLogger_IsLoggable(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug)) {
        metisLogger_Log(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug, __func__,
                        "MessageProcessor %p destroyed",
                        (void *) processor);
    }

    metisLogger_Release(&processor->logger);
    metisFIB_Destroy(&processor->fib);
    metisContentStoreInterface_Release(&processor->contentStore);
    metisPIT_Release(&processor->pit);

    parcMemory_Deallocate((void **) &processor);
    *processorPtr = NULL;
}

void
metisMessageProcessor_Receive(MetisMessageProcessor *processor, MetisMessage *message)
{
	//by wschoi
#ifdef LOG_CHECK
	printf("metisMessageProcessor_Receive()\n\n");
#endif
    assertNotNull(processor, "Parameter processor must be non-null");
    assertNotNull(message, "Parameter message must be non-null");

    processor->stats.countReceived++;

    if (processor->tap != NULL && processor->tap->isTapOnReceive(processor->tap)) {
        processor->tap->tapOnReceive(processor->tap, message);
    }

    if (metisLogger_IsLoggable(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug)) {
	    char *nameString = "NONAME";
	    if (metisMessage_HasName(message)) {
		    CCNxName *name = metisTlvName_ToCCNxName(metisMessage_GetName(message));
		    nameString = ccnxName_ToString(name);

		    metisLogger_Log(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug, __func__,
				    "Message %p ingress %3u length %5u received name %s",
				    (void *) message,
				    metisMessage_GetIngressConnectionId(message),
				    metisMessage_Length(message),
				    nameString);

		    parcMemory_Deallocate((void **) &nameString);
		    ccnxName_Release(&name);
	    }
    }

    switch (metisMessage_GetType(message)) {
	    case MetisMessagePacketType_Interest:


		    //by wschoi
#ifdef LOG_CHECK
			printf("registration_from_Consumer: %d \n", message->registration_from_Consumer);
			printf("registration_from_CR: %d \n", message->registration_from_CR);

			printf("registration_from_Consumer: %d \n", message->registration_add_from_Consumer);
			printf("registration_from_CR: %d \n", message->registration_add_from_CR);

			printf("registration_from_Consumer: %d \n", message->registration_del_from_Consumer);
			printf("registration_from_CR: %d \n", message->registration_del_from_CR);

			printf("registration_from_Consumer: %d \n", message->registration_dereg_from_Consumer);
			printf("registration_from_CR: %d \n", message->registration_dereg_from_CR);
#endif

#if 1
		    if(message->hasGetname==0 && message->hasKeyname==0)
		    {
			    if(message->registration_from_Consumer != 0)
			    {
				    metisMessageProcessor_ReceiveInterestRegistration(processor, message);
			    }
			    else if(message->registration_add_from_Consumer != 0)
			    {
				    metisMessageProcessor_ReceiveInterestRegistration_add(processor, message);
			    }
			    else if(message->registration_del_from_Consumer != 0)
			    {
				    metisMessageProcessor_ReceiveInterestRegistration_del(processor, message);
			    }
			    else if(message->registration_dereg_from_Consumer != 0)
			    {
				    metisMessageProcessor_ReceiveInterestRegistration_dereg(processor, message);
			    }
			    else
			    {

#ifdef LOG_CHECK
				    printf("###########GOING TO metisMessageProcessor_ReceiveInterest()\n");
				    printf("###########GOING TO metisMessageProcessor_ReceiveInterest()\n");
				    printf("###########GOING TO metisMessageProcessor_ReceiveInterest()\n");
#endif
				    metisMessageProcessor_ReceiveInterest(processor, message);
			    }
		    }
		    else if(message->hasGetname==1)
		    {
#ifdef LOG_CHECK
			    printf("###########GOING TO metisMessageProcessor_ReceiveInterestGetname()\n");
			    printf("###########GOING TO metisMessageProcessor_ReceiveInterestGetname()\n");
			    printf("###########GOING TO metisMessageProcessor_ReceiveInterestGetname()\n");
			    printf("###########GOING TO metisMessageProcessor_ReceiveInterestGetname()\n");
#endif
			    metisMessageProcessor_ReceiveInterestGetname(processor, message);
		    }
		    else if(message->hasKeyname==1)
		    {
#ifdef LOG_CHECK
			    printf("###########GOING TO metisMessageProcessor_ReceiveIntereskeyname()\n");
			    printf("###########GOING TO metisMessageProcessor_ReceiveIntereskeyname()\n");
			    printf("###########GOING TO metisMessageProcessor_ReceiveIntereskeyname()\n");
			    printf("###########GOING TO metisMessageProcessor_ReceiveIntereskeyname()\n");
#endif
			    metisMessageProcessor_ReceiveInterestKeyname(processor, message);
		    }
#else

		    metisMessageProcessor_ReceiveInterest(processor, message);
#endif


		    break;
	    case MetisMessagePacketType_ContentObject:
#if 1
		    if(message->hasPayloadGetname==0)
		    {
#ifdef LOG_CHECK
			    printf("metisMessageProcessor_ReceiveContentObject()\n");
#endif
			    metisMessageProcessor_ReceiveContentObject(processor, message);


		    }
		    else
		    {
#ifdef LOG_CHECK
			    printf("metisMessageProcessor_ReceiveContentObjectPayloadGetname()\n");
#endif
			    metisMessageProcessor_ReceiveContentObjectPayloadGetname(processor, message);
		    }
#else
		    metisMessageProcessor_ReceiveContentObject(processor, message);
#endif
		    break;

	    default:
		    metisMessageProcessor_Drop(processor, message);
		    break;
    }

    // if someone wanted to save it, they made a copy
    metisMessage_Release(&message);
}

void
metisMessageProcessor_AddTap(MetisMessageProcessor *processor, MetisTap *tap)
{
    assertNotNull(processor, "Parameter processor must be non-null");
    assertNotNull(tap, "Parameter tap must be non-null");

    processor->tap = tap;
}

void
metisMessageProcessor_RemoveTap(MetisMessageProcessor *processor, const MetisTap *tap)
{
    assertNotNull(processor, "Parameter processor must be non-null");
    assertNotNull(tap, "Parameter tap must be non-null");

    if (processor->tap == tap) {
        processor->tap = NULL;
    }
}

static void
_metisMessageProcess_CheckForwardingStrategies(MetisMessageProcessor *processor)
{
    MetisFibEntryList *fib_entries = metisMessageProcessor_GetFibEntries(processor);
    size_t size = metisFibEntryList_Length(fib_entries);
    for (unsigned i = 0; i < size; i++) {
        MetisFibEntry *entry = (MetisFibEntry *) metisFibEntryList_Get(fib_entries, i);
        const char *strategy = metisFibEntry_GetFwdStrategyType(entry);
        if (strcmp(strategy, FWD_STRATEGY_LOADBALANCER_WITH_DELAY) == 0) {
            strategyLoadBalancerWithPD_SetConnectionTable(metisFibEntry_GetFwdStrategy(entry),
                                                          metisForwarder_GetConnectionTable(processor->metis));
        }
    }
    metisFibEntryList_Destroy(&fib_entries);
}

bool
metisMessageProcessor_AddOrUpdateRoute(MetisMessageProcessor *processor, CPIRouteEntry *route)
{
    MetisConfiguration *config = metisForwarder_GetConfiguration(processor->metis);
    const char *fwdStrategy = metisConfiguration_GetForwarginStrategy(config, cpiRouteEntry_GetPrefix(route));
    bool res = metisFIB_AddOrUpdate(processor->fib, route, fwdStrategy);
    _metisMessageProcess_CheckForwardingStrategies(processor);
    return res;
}

bool
metisMessageProcessor_RemoveRoute(MetisMessageProcessor *processor, CPIRouteEntry *route)
{
    return metisFIB_Remove(processor->fib, route);
}

void
metisMessageProcessor_RemoveConnectionIdFromRoutes(MetisMessageProcessor *processor, unsigned connectionId)
{
    metisFIB_RemoveConnectionIdFromRoutes(processor->fib, connectionId);
}

void
metisProcessor_SetStrategy(MetisMessageProcessor *processor, CCNxName *prefix, const char *strategy)
{
    MetisFibEntryList *fib_entries = metisMessageProcessor_GetFibEntries(processor);
    MetisTlvName *strategyPrefix = metisTlvName_CreateFromCCNxName(prefix);
    size_t size = metisFibEntryList_Length(fib_entries);
    for (unsigned i = 0; i < size; i++) {
        MetisFibEntry *entry = (MetisFibEntry *) metisFibEntryList_Get(fib_entries, i);
        MetisTlvName *entryPrefix = metisFibEntry_GetPrefix(entry);
        if (metisTlvName_Equals(entryPrefix, strategyPrefix)) {
            metisFibEntry_SetStrategy(entry, strategy);
        }
    }
    metisTlvName_Release(&strategyPrefix);
    metisFibEntryList_Destroy(&fib_entries);
    _metisMessageProcess_CheckForwardingStrategies(processor);
}

MetisFibEntryList *
metisMessageProcessor_GetFibEntries(MetisMessageProcessor *processor)
{
    assertNotNull(processor, "Parameter processor must be non-null");
    return metisFIB_GetEntries(processor->fib);
}

// ============================================================
// Internal API

/**
 * @function metisMessageProcessor_Drop
 * @abstract Whenever we "drop" a message, notify the OnDrop tap and increment countes
 * @discussion
 *   This is a bookkeeping function.  It notifies the tap, if its an onDrop tap, and
 *   it increments the appropriate counters.
 *
 *   The default action for a message is to destroy it in <code>metisMessageProcessor_Receive()</code>,
 *   so this function does not need to do that.
 *
 * @param <#param1#>
 */
static void
metisMessageProcessor_Drop(MetisMessageProcessor *processor, MetisMessage *message)
{
    if (processor->tap != NULL && processor->tap->isTapOnDrop && processor->tap->isTapOnDrop(processor->tap)) {
        processor->tap->tapOnDrop(processor->tap, message);
    }

    processor->stats.countDropped++;

    switch (metisMessage_GetType(message)) {
        case MetisMessagePacketType_Interest:
            processor->stats.countInterestsDropped++;
            break;

        case MetisMessagePacketType_ContentObject:
            processor->stats.countObjectsDropped++;
            break;

        default:
            break;
    }

    // dont destroy message here, its done at end of receive
}

/**
 * @function metisMessageProcessor_AggregateInterestInPit
 * @abstract Try to aggregate the interest in the PIT
 * @discussion
 *   Tries to aggregate the interest with another interest.
 *
 * @param <#param1#>
 * @return true if interest aggregagted (no more forwarding needed), false if need to keep processing it.
 */
static bool
metisMessageProcessor_AggregateInterestInPit(MetisMessageProcessor *processor, MetisMessage *interestMessage)
{

//by wschoi
#ifdef LOG_CHECK
	printf("metisMessageProcessor_AggregateInterestInPit() start\n\n");
#endif


    MetisPITVerdict verdict = metisPIT_ReceiveInterest(processor->pit, interestMessage);

    if (verdict == MetisPITVerdict_Aggregate) {
        // PIT has it, we're done
        processor->stats.countInterestsAggregated++;

        if (metisLogger_IsLoggable(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug)) {
            metisLogger_Log(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug, __func__,
                            "Message %p aggregated in PIT (aggregated count %u)",
                            (void *) interestMessage,
                            processor->stats.countInterestsAggregated);
        }

        return true;
    }

    if (metisLogger_IsLoggable(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug)) {
        metisLogger_Log(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug, __func__,
                        "Message %p not aggregated in PIT (aggregated count %u)",
                        (void *) interestMessage,
                        processor->stats.countInterestsAggregated);
    }

    return false;
}

static bool
_satisfyFromContentStore(MetisMessageProcessor *processor, MetisMessage *interestMessage)
{
//by wschoi
#ifdef LOG_CHECK
	printf("_satisfyFromContentStore() start\n\n");
#endif

    bool result = false;

    if (!processor->serve_from_cache) {
        return result;
    }

    // See if there's a match in the store.
    MetisMessage *objectMessage = metisContentStoreInterface_MatchInterest(processor->contentStore, interestMessage);

    if (objectMessage) {
        // If the Interest specified a KeyId restriction and we had a match, check to see if the ContentObject's KeyId
        // has been verified. If not, we don't respond with it.
        if (metisMessage_HasKeyId(interestMessage) && !metisMessage_IsKeyIdVerified(objectMessage)) {
            // We don't match if they specified a KeyId restriction and we haven't yet verified it.
            objectMessage = NULL;
        }
    }

    if (objectMessage != NULL) {
        bool hasExpired = false;
        bool hasExceededRCT = false;

        uint64_t currentTimeTicks = metisForwarder_GetTicks(processor->metis);

        // Check for ExpiryTime exceeded.
        if (metisMessage_HasExpiryTime(objectMessage)
            && (currentTimeTicks > metisMessage_GetExpiryTimeTicks(objectMessage))) {
            hasExpired = true;
        }

        // Check for RCT exceeded.
        if (metisMessage_HasRecommendedCacheTime(objectMessage)
            && (currentTimeTicks > metisMessage_GetRecommendedCacheTimeTicks(objectMessage))) {
            hasExceededRCT = true;
        }

        if (!hasExpired) { // && !hasExceededRCT ? It's up to us.
            // Remove it from the PIT.  nexthops is allocated, so need to destroy
            MetisNumberSet *nexthops = metisPIT_SatisfyInterest(processor->pit, objectMessage);
            assertNotNull(nexthops, "Illegal state: got a null nexthops for an interest we just inserted.");

            // send message in reply, then done
            processor->stats.countInterestsSatisfiedFromStore++;

            if (metisLogger_IsLoggable(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug)) {
                metisLogger_Log(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug, __func__,
                                "Message %p satisfied from content store (satisfied count %u)",
                                (void *) interestMessage,
                                processor->stats.countInterestsSatisfiedFromStore);
            }

            metisMessage_ResetPathLabel(objectMessage);

            metisMessageProcessor_ForwardToNexthops(processor, objectMessage, nexthops);
            metisNumberSet_Release(&nexthops);

            result = true;
        }

        // Remove the retrieved ContentObject from the ContentStore if it has expired, or exceeded its RCT.
        if (hasExpired || hasExceededRCT) {
            metisContentStoreInterface_RemoveContent(processor->contentStore, objectMessage);
        }
    }

    return result;
}

//by wschoi

        static bool
metisMessageProcessor_ForwardViaFib_RegtoMS(MetisMessageProcessor *processor, MetisMessage *interestMessage, MetisMessage *interestPitMessage)
{

        //wschoi
#ifdef LOG_CHECK
        printf("metisMessageProcessor_ForwardViaFib_RegtoMS()\n");

#endif

        MetisFibEntry *fibEntry = metisFIB_Match(processor->fib, interestMessage);
        if (fibEntry == NULL) {
                return false;
        }

        MetisPitEntry *pitEntry = metisPIT_GetPitEntry(processor->pit, interestPitMessage);
        if (pitEntry == NULL) {
                return false;
        }
metisPitEntry_AddFibEntry(pitEntry, fibEntry);

        MetisNumberSet *nexthops = (MetisNumberSet *) metisFibEntry_GetNexthopsFromForwardingStrategy(fibEntry, interestMessage);
        //this requires some additional checks. It may happen that some of the output faces selected by the forwarding strategy are not
        //usable. So far all the forwarding strategy return only valid faces (or an empty list)
        for (unsigned i = 0; i < metisNumberSet_Length(nexthops); i++) {
                metisPitEntry_AddEgressId(pitEntry, metisNumberSet_GetItem(nexthops, i));
        }

        //The function GetPitEntry encreases the ref counter in the pit entry
        //we need to decrease it
        metisPitEntry_Release(&pitEntry);
        if (metisMessageProcessor_ForwardToNexthops(processor, interestMessage, nexthops) > 0) {
                metisNumberSet_Release(&nexthops);
                return true;
        } else {
                if (metisLogger_IsLoggable(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug)) {
                        metisLogger_Log(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug, __func__,
                                        "Message %p returned an emtpy next hop set", (void *) interestMessage);
                }
        }
        return false;
}




//by wschoi

	static bool
metisMessageProcessor_ForwardViaFib_Reg(MetisMessageProcessor *processor, MetisMessage *interestMessage, MetisMessage *interestRegMessage)
{

	//wschoi
#ifdef LOG_CHECK
	printf("metisMessageProcessor_ForwardViaFib_Reg()\n");

#endif

	MetisFibEntry *fibEntry = metisFIB_Match(processor->fib, interestRegMessage);
	if (fibEntry == NULL) {
#ifdef LOG_CHECK
		printf("metisMessageProcessor_ForwardViaFib_Reg(), fibEntry is NULL\n");
#endif
		return false;
	}

	MetisPitEntry *pitEntry = metisPIT_GetPitEntry(processor->pit, interestMessage);
	if (pitEntry == NULL) {

#ifdef LOG_CHECK
		printf("metisMessageProcessor_ForwardViaFib_Reg(), pitEntry is NULL\n");
#endif
		return false;
	}

	metisPitEntry_AddFibEntry(pitEntry, fibEntry);

	MetisNumberSet *nexthops = (MetisNumberSet *) metisFibEntry_GetNexthopsFromForwardingStrategy(fibEntry, interestMessage);
	//this requires some additional checks. It may happen that some of the output faces selected by the forwarding strategy are not
	//usable. So far all the forwarding strategy return only valid faces (or an empty list)
	for (unsigned i = 0; i < metisNumberSet_Length(nexthops); i++) {
		metisPitEntry_AddEgressId(pitEntry, metisNumberSet_GetItem(nexthops, i));
	}

	//The function GetPitEntry encreases the ref counter in the pit entry
	//we need to decrease it
	metisPitEntry_Release(&pitEntry);
	if (metisMessageProcessor_ForwardToNexthops(processor, interestRegMessage, nexthops) > 0) {
		metisNumberSet_Release(&nexthops);
		return true;
	} else {
		if (metisLogger_IsLoggable(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug)) {
			metisLogger_Log(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug, __func__,
					"Message %p returned an emtpy next hop set", (void *) interestMessage);
		}
	}

	return false;
}




//by wschoi
static bool
metisMessageProcessor_ForwardViaFib_Getname(MetisMessageProcessor *processor, MetisMessage *interestMessage, MetisMessage *GetnameMessage)
{

//wschoi
#ifdef LOG_CHECk
	printf("############metisMessageProcessor_ForwardViaFib_Getname()##############\n\n");
#endif

    MetisFibEntry *fibEntry = metisFIB_Match(processor->fib, interestMessage);
    if (fibEntry == NULL) {
#ifdef LOG_CHECK
		printf("fibEntry== NULL, in metisMessageProcessor_ForwardViaFib()\n\n");
#endif
        return false;
    }

    MetisPitEntry *pitEntry = metisPIT_GetPitEntry(processor->pit, GetnameMessage);
    if (pitEntry == NULL) {
#ifdef LOG_CHECK
		printf("pitEntry== NULL, in metisMessageProcessor_ForwardViaFib()\n\n");
#endif
        return false;
    }

    metisPitEntry_AddFibEntry(pitEntry, fibEntry);

    MetisNumberSet *nexthops = (MetisNumberSet *) metisFibEntry_GetNexthopsFromForwardingStrategy(fibEntry, interestMessage);
    //this requires some additional checks. It may happen that some of the output faces selected by the forwarding strategy are not
    //usable. So far all the forwarding strategy return only valid faces (or an empty list)
    for (unsigned i = 0; i < metisNumberSet_Length(nexthops); i++) {
        metisPitEntry_AddEgressId(pitEntry, metisNumberSet_GetItem(nexthops, i));
    }

    //The function GetPitEntry encreases the ref counter in the pit entry
    //we need to decrease it
    metisPitEntry_Release(&pitEntry);

    if (metisMessageProcessor_ForwardToNexthops(processor, interestMessage, nexthops) > 0) {
        metisNumberSet_Release(&nexthops);
        return true;
    } else {
        if (metisLogger_IsLoggable(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug)) {
            metisLogger_Log(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug, __func__,
                            "Message %p returned an emtpy next hop set", (void *) interestMessage);
        }
    }

    return false;
}





//by wschoi

	static bool
metisMessageProcessor_ForwardViaFib_Keyname(MetisMessageProcessor *processor, MetisMessage *interestMessage, MetisMessage *KeynameMessage)
{

	//wschoi
#ifdef LOG_CHECK
	printf("############metisMessageProcessor_ForwardViaFib_Keynameb()##############\n\n");
#endif

	MetisFibEntry *fibEntry = metisFIB_Match(processor->fib, interestMessage);
	if (fibEntry == NULL) {
#ifdef LOG_CHECK
		printf("fibEntry== NULL, in metisMessageProcessor_ForwardViaFib_Keyname()\n\n");
#endif
		return false;
	}

	MetisPitEntry *pitEntry = metisPIT_GetPitEntry(processor->pit, KeynameMessage);
	if (pitEntry == NULL) {
#ifdef LOG_CHECK
		printf("pitEntry== NULL, in metisMessageProcessor_ForwardViaFib_Keyname()\n\n");
#endif
		return false;
	}

	metisPitEntry_AddFibEntry(pitEntry, fibEntry);


	MetisNumberSet *nexthops = (MetisNumberSet *) metisFibEntry_GetNexthopsFromForwardingStrategy(fibEntry, interestMessage);
	//this requires some additional checks. It may happen that some of the output faces selected by the forwarding strategy are not
	//usable. So far all the forwarding strategy return only valid faces (or an empty list)
	for (unsigned i = 0; i < metisNumberSet_Length(nexthops); i++) {
		metisPitEntry_AddEgressId(pitEntry, metisNumberSet_GetItem(nexthops, i));
	}

	//The function GetPitEntry encreases the ref counter in the pit entry
	//we need to decrease it
	metisPitEntry_Release(&pitEntry);
	if (metisMessageProcessor_ForwardToNexthops(processor, interestMessage, nexthops) > 0) {
		metisNumberSet_Release(&nexthops);
		return true;
	} else {
		if (metisLogger_IsLoggable(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug)) {
			metisLogger_Log(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug, __func__,
					"Message %p returned an emtpy next hop set", (void *) interestMessage);
		}
	}

	return false;
}








/**
 * @function metisMessageProcessor_ForwardViaFib
 * @abstract Try to forward the interest via the FIB
 * @discussion
 *   This calls <code>metisMessageProcessor_ForwardToNexthops()</code>, so if we find any nexthops,
 *   the interest will be sent on its way.  Depending on the MetisIoOperations of each nexthop,
 *   it may be a deferred write and bump up the <code>interestMessage</code> refernce count, or it
 *   may copy the data out.
 *
 *   A TRUE return means we did our best to forward it via the routes.  If those routes are actually
 *   down or have errors, we still return TRUE.  A FALSE return means there were no routes to try.
 *
 * @param <#param1#>
 * @return true if we found a route and tried to forward it, false if no route
 */
static bool
metisMessageProcessor_ForwardViaFib(MetisMessageProcessor *processor, MetisMessage *interestMessage)
{

//wschoi
#ifdef LOG_CHECK
	printf("############metisMessageProcessor_ForwardViaFib()##############\n\n");
#endif

    MetisFibEntry *fibEntry = metisFIB_Match(processor->fib, interestMessage);
    if (fibEntry == NULL) {
#ifdef LOG_CHECK
		printf("fibEntry== NULL, in metisMessageProcessor_ForwardViaFib()\n\n");
#endif
        return false;
    }

    MetisPitEntry *pitEntry = metisPIT_GetPitEntry(processor->pit, interestMessage);
    if (pitEntry == NULL) {
#ifdef LOG_CHECK
		printf("pitEntry== NULL, in metisMessageProcessor_ForwardViaFib()\n\n");
#endif
        return false;
    }

    metisPitEntry_AddFibEntry(pitEntry, fibEntry);

    MetisNumberSet *nexthops = (MetisNumberSet *) metisFibEntry_GetNexthopsFromForwardingStrategy(fibEntry, interestMessage);
    //this requires some additional checks. It may happen that some of the output faces selected by the forwarding strategy are not
    //usable. So far all the forwarding strategy return only valid faces (or an empty list)
    for (unsigned i = 0; i < metisNumberSet_Length(nexthops); i++) {
        metisPitEntry_AddEgressId(pitEntry, metisNumberSet_GetItem(nexthops, i));
    }

    //The function GetPitEntry encreases the ref counter in the pit entry
    //we need to decrease it
    metisPitEntry_Release(&pitEntry);

    if (metisMessageProcessor_ForwardToNexthops(processor, interestMessage, nexthops) > 0) {
        metisNumberSet_Release(&nexthops);
        return true;
    } else {
        if (metisLogger_IsLoggable(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug)) {
            metisLogger_Log(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug, __func__,
                            "Message %p returned an emtpy next hop set", (void *) interestMessage);
        }
    }
#ifdef LOG_CHECk
		printf("result, in metisMessageProcessor_ForwardViaFib()\n\n");
#endif
    return false;
}

static bool
metisMessageProcessor_IsIngressConnectionLocal(MetisMessageProcessor *processor, MetisMessage *interestMessage)
{
    MetisConnectionTable *connTable = metisForwarder_GetConnectionTable(processor->metis);
    unsigned ingressConnId = metisMessage_GetIngressConnectionId(interestMessage);
    const MetisConnection *ingressConn = metisConnectionTable_FindById(connTable, ingressConnId);

    bool isLocal = false;
    if (ingressConn) {
        isLocal = metisConnection_IsLocal(ingressConn);
    }
    return isLocal;
}

/**
 * On ingress, a remote connection must have hop limit > 0.  All interests must have a hop limit.
 *
 * This function will log the error, if any, but it does not drop the message.
 *
 * If Interest is from a local application, the hop limit is not decremented and may be 0.
 *
 * If Interest is from a remote connection, the hop limit must be greater than 0 and will be decremented.
 *
 * @param [<#in out in,out#>] <#name#> <#description#>
 *
 * @retval true The interest passes the hop limit check
 * @retval false The interest fails the hop limit check, should be dropped
 *
 * Example:
 * @code
 * <#example#>
 * @endcode
 */
	static bool
metisMessageProcessor_CheckAndDecrementHopLimitOnIngress(MetisMessageProcessor *processor, MetisMessage *interestMessage)
{
	//by wschoi
#ifdef LOG_CHECK
	printf("metisMessageProcessor_CheckAndDecrementHopLimitOnIngress()\n\n");
#endif
	bool success = true;
	if (!metisMessage_HasHopLimit(interestMessage)) {
		processor->stats.countDroppedNoHopLimit++;

		if (metisLogger_IsLoggable(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug)) {
			metisLogger_Log(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug, __func__,
					"Message %p did not have a hop limit (count %u)",
					(void *) interestMessage,
					processor->stats.countDroppedNoHopLimit);
		}

		success = false;
	} else {
		// Is the ingress connection remote?  If so check for non-zero and decrement
		if (!metisMessageProcessor_IsIngressConnectionLocal(processor, interestMessage)) {
			uint8_t hoplimit = metisMessage_GetHopLimit(interestMessage);
			if (hoplimit == 0) {
				processor->stats.countDroppedZeroHopLimitFromRemote++;

				if (metisLogger_IsLoggable(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug)) {
					metisLogger_Log(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug, __func__,
							"Message %p from remote host has 0 hop limit (count %u)",
							(void *) interestMessage,
							processor->stats.countDroppedZeroHopLimitFromRemote);
				}

				success = false;
			} else {
				hoplimit--;
				metisMessage_SetHopLimit(interestMessage, hoplimit);
			}
		}
	}
	return success;
}



//by wschoi
	static bool
metisMessageProcessor_RctLookup(MetisMessageProcessor *processor, MetisMessage *interestMessage)
{

	//by wschoi
#ifdef LOG_CHECK
	printf("metisMessageProcessor_RctLookup()\n\n");
#endif
	uint8_t NameA[interestMessage->name->memoryLength];
	int NameA_prefix_size=0;
	for(int i=0; i<interestMessage->name->memoryLength; i++)
	{
		NameA[i]=interestMessage->name->memory[i];
#ifdef LOG_CHECK
		printf("##        NameA[%d]= %x, size=%d\n", i, NameA[i], interestMessage->name->memoryLength);
#endif

	}
	//make a Name A array without command and chunk fields
	for(int i=0; i<(interestMessage->name->memoryLength); i++)
	{
		if(NameA[i]==0x10 && NameA[i+2]==0x00)
		{
			break;
		}
#ifdef LOG_CHECK
		printf("i=%d\n", i);
#endif
		NameA_prefix_size=i+1;


	}

	uint8_t NameA_prefix[NameA_prefix_size];

	for(int i=0; i<NameA_prefix_size;i++)
	{
		NameA_prefix[i]=NameA[i];
#ifdef LOG_CHECK
		printf("NameA_prefix[%d]=%x\n",i,NameA_prefix[i] );
#endif
	}

	int NameA_Command_size=interestMessage->name->memoryLength-NameA_prefix_size;
	uint8_t NameA_Command[NameA_Command_size];
	for(int i=0; i<NameA_Command_size; i++)
	{
		NameA_Command[i]=interestMessage->name->memory[NameA_prefix_size+i];
#ifdef LOG_CHECK
		printf("NameA_Command[%d]=%x\n",i,NameA_Command[i] );
#endif
	}


	int check_RCT=0;
	int rct_number=0;
	int NameB_prefix_size=0;

	//lookup Name B in RCT
	for(int i=0; i<processor->rct[0].refcount; i++)
	{
		if(processor->rct[i].NameA_size==NameA_prefix_size)
		{
#ifdef LOG_CHECK
			printf("Bingo\n");
#endif
			for(int j=0; j<NameA_prefix_size; j++)

			{
				if(NameA_prefix[j]==processor->rct[i].NameA[j])
				{
					check_RCT++;
				}
			}
			if(check_RCT==NameA_prefix_size)
			{
				NameB_prefix_size=processor->rct[i].NameB_size;
				rct_number=i;
				check_RCT=0;
				goto BINGO;

			}
			else
			{
				check_RCT=0;
			}


		}
	}
	if(check_RCT==0)
	{
		return 0;
	}
BINGO:
	{}
	uint8_t NameB_prefix[NameB_prefix_size];
	for(int i=0; i<NameB_prefix_size;i++)
	{
		NameB_prefix[i]=processor->rct[rct_number].NameB[i];
#ifdef LOG_CHECK
		printf("NameB_prefix[%d]\=%x\n", i, NameB_prefix[i]);
#endif

	}


	//make a interest key message

#if 1
	//parse an Interest
	//header, T_INTEREST, InterestLength, T_NAME, NameLength, Name, PAYLOAD_TYPE, PAYLOAD_Length, PAYLOAD

	//make a getname message
	//header, T_INTEREST, new_InterestLength, MS1_T_NAME, MS1_NameLength, MS1_Name, T_GETNAME, GetnameLength, new_Name

	PARCEventBuffer *buff = parcEventBuffer_Create();


	int interestMessage_length = parcEventBuffer_GetLength(interestMessage->messageBytes);

	uint8_t interest_from_consumer[interestMessage_length];

	for(int i=0; i<interestMessage_length;i++)
	{
		interest_from_consumer[i]=interestMessage->messageHead[i];

	}
#ifdef LOG_CHECK
	printf("Copy interestMessage to interest_from_consumer\n\n");

	for(int i=0; i<interestMessage_length;i++)
	{
		printf("%x ", interest_from_consumer[i]);
	}
	printf("\n\n");

#endif
	// additional field length(name type, name field, keyname type)
	int keyname_message_num=interestMessage_length+8+NameB_prefix_size+NameA_Command_size; // length of key type fields(Name A) and name type fileds is 8

	uint8_t keyname_message[keyname_message_num];

	//packet header
	for(int i=0; i<3;i++)
	{
		keyname_message[i]=interest_from_consumer[i];
	}

	//packet header size
	keyname_message[3]=(uint8_t)keyname_message_num;

	for(int i=4; i<8;i++)
	{
		keyname_message[i]=interest_from_consumer[i];
	}

	//ccnx Message header
	for(int i=8; i<11;i++)
	{
		keyname_message[i]=interest_from_consumer[i];
	}

	//ccnx Message size, original size + (keyname Type field + NameB fields) size
	keyname_message[11]=(uint8_t)(interest_from_consumer[11]+NameB_prefix_size+NameA_Command_size+8);


	//MS1(/X/hello/1/2) name field
	//      uint8_t ms_namefield[]={0x00, 0x00, 0x00, 0x18,0x00, 0x01, 0x00, 0x01, 0x58, 0x00, 0x01, 0x00,0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x00, 0x01,0x00, 0x01, 0x31, 0x00, 0x01, 0x00, 0x01, 0x32};

	//      int ms_namefield_num=sizeof(ms_namefield);
#ifdef LOG_CHECK
	printf("##### size of Name B fields : %d\n\n", NameB_prefix_size + NameA_Command_size);
#endif

	//name Type
	keyname_message[12]=0x00;
	keyname_message[13]=0x00;

	//name field size
	keyname_message[14]=0x00;
	keyname_message[15]=(uint8_t)(NameB_prefix_size+NameA_Command_size);


	for(int i=0; i<NameB_prefix_size; i++)
	{
		keyname_message[16+i]=NameB_prefix[i];
	}

	for(int i=0; i<NameA_Command_size; i++)
	{
		keyname_message[16+NameB_prefix_size+i]=NameA_Command[i];
	}

	//Keyname Type
	keyname_message[16+NameB_prefix_size+NameA_Command_size]=0x01;
	keyname_message[17+NameB_prefix_size+NameA_Command_size]=0x13;

	//Keyname field size
	keyname_message[18+NameB_prefix_size+NameA_Command_size]=0x00;
	keyname_message[19+NameB_prefix_size+NameA_Command_size]=(uint8_t)((interestMessage->name->memoryLength)+4);

	// name type of keyname field
	keyname_message[20+NameB_prefix_size+NameA_Command_size]=0x00;
	keyname_message[21+NameB_prefix_size+NameA_Command_size]=0x00;
	keyname_message[22+NameB_prefix_size+NameA_Command_size]=0x00;
	keyname_message[23+NameB_prefix_size+NameA_Command_size]=(uint8_t)(interestMessage->name->memoryLength);


	//name field of getname
	for(int i=0; i<interestMessage->name->memoryLength; i++)
	{
		keyname_message[24+NameB_prefix_size+NameA_Command_size+i]=interestMessage->name->memory[i];
	}
#ifdef LOG_CHECk
	printf("keyname_message_num= %d, sizeof(keyname_message) = %d\n\n ", keyname_message_num, sizeof(keyname_message));

	printf("memoryLength: %d \n\n", interestMessage->name->memoryLength);

	for(int i=0; i<interestMessage->name->memoryLength; i++)
	{
		printf("%x ",  interestMessage->name->memory[i]);
	}
	printf("\n\n");

	printf("############### keyname_message ######\n\n");
	for(int i=0; i<keyname_message_num; i++)
	{
		printf("%x ", keyname_message[i]);
	}
	printf("\n\n");
#endif
	//  uint8_t metisTestDataV1_Interest_AllFields[]={0x31, 0x32};
	// name: /X/hello/1/2 getname: /com/google/d3512
	uint8_t metisTestDataV1_Interest_AllFields[]={0x01, 0x00, 0x00, 0x4a, 0xff, 0x00, 0x00, 0x08,
		0x00, 0x01, 0x00, 0x3e, 0x00, 0x00, 0x00, 0x18,
		0x00, 0x01, 0x00, 0x01, 0x58, 0x00, 0x01, 0x00,
		0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x00, 0x01,
		0x00, 0x01, 0x31, 0x00, 0x01, 0x00, 0x01, 0x32,
		0x01, 0x11, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x1a,
		0x00, 0x01, 0x00, 0x03, 0x63, 0x6f, 0x6d, 0x00,
		0x01, 0x00, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
		0x65, 0x00, 0x01, 0x00, 0x05, 0x64, 0x33, 0x35,
		0x31, 0x32,};
	//  parcEventBuffer_Append(buff, metisTestDataV1_Interest_AllFields, sizeof(metisTestDataV1_Interest_AllFields));
	parcEventBuffer_Append(buff, keyname_message, sizeof(keyname_message));
	PARCLogReporter *reporter = parcLogReporterTextStdout_Create();
	MetisLogger *logger = metisLogger_Create(reporter, parcClock_Wallclock());
	parcLogReporter_Release(&reporter);
	MetisMessage *message = metisMessage_CreateFromBuffer(1, 2, buff, logger);
	//  MetisMessage *message = parcMemory_AllocateAndClear(sizeof(MetisMessage));
	metisLogger_Release(&logger);




	MetisTlvName *tlvName=metisMessage_GetName(interestMessage);
#ifdef LOG_CHECK
	printf("interestMessage_length is %d\n\n", interestMessage_length);


	for(int i=0; i<interestMessage_length;i++)
	{
		printf("%x ", message->messageHead[i]);
	}
	printf("\n\n");
#endif

	//  int result = metisMessage_Append(interestMessage->messageHead, message);

#endif


	processor->stats.countInterestsReceived++;


	if (!metisMessageProcessor_CheckAndDecrementHopLimitOnIngress(processor, message)) {
		metisMessageProcessor_Drop(processor, message);
		return true;
	}

	// (1) Try to aggregate in PIT
	if (metisMessageProcessor_AggregateInterestInPit(processor, message)) {
		// done

		//by wschoi
#ifdef LOG_CHECK
		printf("metisMessageProcessor_AggregateInterestInPit()\n\n");
#endif

		return true;
	}

	// At this point, we just created a PIT entry.  If we don't forward the interest, we need
	// to remove the PIT entry.

	// (2) Try to satisfy from content store
	if (_satisfyFromContentStore(processor, message)) {
		// done
		// If we found a content object in the CS, metisMessageProcess_SatisfyFromContentStore already
		// cleared the PIT state

		//by wschoi
#ifdef LOG_CHECK
		printf("_satisfyFromContentStore()\n\n");
#endif


		return true;
	}

	//by wschoi
#if 1
	// (3) Try to forward it
	if (metisMessageProcessor_ForwardViaFib(processor, message)) {
		// done


		//by wschoi
#ifdef LOG_CHECK
		printf("metisMessageProcessor_ForwardViaFib()\n\n");
#endif

		return true;
	}



#endif

}



//by wschoi


	static void
metisMessageProcessor_ReceiveInterestGetname(MetisMessageProcessor *processor, MetisMessage *interestMessage)
{
	processor->stats.countInterestsReceived++;

#if 1

	//################## Change packet fields to Name A/MS1 from MS1/Name A for I-Get####################

	int interestMessage_length = parcEventBuffer_GetLength(interestMessage->messageBytes);

	uint8_t interestGet_from_consumer[interestMessage_length];

	for(int i=0; i<interestMessage_length;i++)
	{
		interestGet_from_consumer[i]=interestMessage->messageHead[i];

	}
#ifdef LOG_CHECK
	printf("Copy interestMessage to interest_from_consumer\n\n");

	for(int i=0; i<interestMessage_length;i++)
	{
		printf("%x ", interestGet_from_consumer[i]);
	}
	printf("\n\n");
#endif

	//create Packet header and interest header. it is fixed size.
	uint8_t interestGet_PH_IH[12];
	int PH_IH_end_point=0;
	for(int i=0; i < 12; i++)
	{
		interestGet_PH_IH[i]=interestGet_from_consumer[i];
		PH_IH_end_point++;
#ifdef LOG_CHECK
		printf("interestGet_PH_IH_%d: %x \n", i, interestGet_PH_IH[i]);
#endif
	}

	//create MS name with name type fields. MS name's size array is fixed field.
	uint8_t interestGet_MS_Name[interestGet_from_consumer[15]+4];
	int MS_end_point=PH_IH_end_point;
	for (int i=0; i<(interestGet_from_consumer[15]+4); i++)
	{
		interestGet_MS_Name[i]=interestGet_from_consumer[MS_end_point];
#ifdef LOG_CHECK
		printf("interestGet_MS_Name_%d: %x \n", i, interestGet_MS_Name[i]);
#endif
		MS_end_point++;
	}

	//create I-Get type
	uint8_t interestGet_GetType[4];
	int GetType_end_point=MS_end_point;
	for(int i=0; i<4; i++)
	{
		interestGet_GetType[i]=interestGet_from_consumer[GetType_end_point];
#ifdef LOG_CHECK
		printf("interestGet_GetType_%d: %x \n", i, interestGet_GetType[i]);
#endif
		GetType_end_point++;
	}

	//create I-Get Name with name type fields. I-Get name's size array is fixed field.

	uint8_t interestGet_GetName[interestGet_from_consumer[GetType_end_point+3]+4];
	int GetName_end_point=GetType_end_point;
	for(int i=0; i<interestGet_from_consumer[GetType_end_point+3]+4; i++)
	{
		interestGet_GetName[i]=interestGet_from_consumer[GetName_end_point];
#ifdef LOG_CHECK
		printf("interestGet_GetName_%d: %x \n", i, interestGet_GetName[i]);
#endif
		GetName_end_point++;
	}
#ifdef LOG_CHECK
	printf("end_point: %d\n", GetName_end_point);
#endif


	// change name fields
	uint8_t interestGet_changed[interestMessage_length];
	//add Packet Header and Interest Header
	PH_IH_end_point=0;
	for(int i=0; i < 12; i++)
	{
		interestGet_changed[i]=interestGet_PH_IH[i];
#ifdef LOG_CHECK
		printf("interestGet_changed_%d: %x \n", i, interestGet_changed[i]);
#endif
		PH_IH_end_point++;
	}
	//add I-Get Name with name type fields
	GetName_end_point=PH_IH_end_point;
	for (int i=0; i<(interestGet_GetName[3]+4); i++)
	{
		interestGet_changed[i+PH_IH_end_point]=interestGet_GetName[i];
#ifdef LOG_CHECK
		printf("interestGet_changed_%d: %x \n", i+PH_IH_end_point,interestGet_changed[i+PH_IH_end_point]);
#endif
		GetName_end_point++;
	}

	//add I-Get type fields

	GetType_end_point=GetName_end_point;

	for(int i=0; i<4; i++)
	{
		interestGet_changed[i+GetName_end_point]=interestGet_GetType[i];

		//update value of GetType size field.
		if(i==3)
		{
			//	interestGet_changed[i+GetName_end_point]=sizeof(interestGet_MS_Name);
			interestGet_changed[i+GetName_end_point]=interestGet_MS_Name[i]+4;
		}
#ifdef LOG_CHECK
		printf("interestGet_changed_%d: %x \n", i+GetName_end_point, interestGet_changed[i+GetName_end_point]);
#endif

		GetType_end_point++;
	}

	//add MS Name with name type fields

	MS_end_point=GetType_end_point;
	for (int i=0; i<(interestGet_MS_Name[3]+4); i++)
	{
		interestGet_changed[i+GetType_end_point]=interestGet_MS_Name[i];
#ifdef LOG_CHECK
		printf("interestGet_changed_%d: %x \n", i+GetType_end_point, interestGet_changed[i+GetType_end_point]);
#endif
		MS_end_point++;
	}

#endif


#if 1
	PARCEventBuffer *buff = parcEventBuffer_Create();
	//  uint8_t metisTestDataV1_Interest_AllFields[]={0x31, 0x32};
	// name: /com/google/d3512  getname: /X/hello/1/2
	uint8_t metisTestDataV1_Interest_AllFields[]={
		0x01, 0x00, 0x00, 0x4a, //Header
		0xff, 0x00, 0x00, 0x08,

		0x00, 0x01, 0x00, 0x3e, //INTEREST Header

		0x00, 0x00, 0x00, 0x1a, // NAME Header
		0x00, 0x01, 0x00, 0x03, // /com/google/d3512
		0x63, 0x6f, 0x6d, 0x00,
		0x01, 0x00, 0x06, 0x67,
		0x6f, 0x6f, 0x67, 0x6c,
		0x65, 0x00, 0x01, 0x00,
		0x05, 0x64, 0x33, 0x35,
		0x31, 0x32,
		0x01, 0x11, 0x00, 0x1c, //T_GETNAME Header
		0x00, 0x00, 0x00, 0x18, // NAME Header
		0x00, 0x01, 0x00, 0x01, // /X/hello/1/2
		0x58, 0x00, 0x01, 0x00,
		0x05, 0x68, 0x65, 0x6c, 
		0x6c, 0x6f, 0x00, 0x01, 
		0x00, 0x01, 0x31, 0x00,
		0x01, 0x00, 0x01, 0x32
	};



	//parcEventBuffer_Append(buff, metisTestDataV1_Interest_AllFields, sizeof(metisTestDataV1_Interest_AllFields));
	parcEventBuffer_Append(buff, interestGet_changed, sizeof(interestGet_changed));
	PARCLogReporter *reporter = parcLogReporterTextStdout_Create();
	MetisLogger *logger = metisLogger_Create(reporter, parcClock_Wallclock());
	parcLogReporter_Release(&reporter);
	MetisMessage *message = metisMessage_CreateFromBuffer(1, 2, buff, logger);
	//MetisMessage *message = parcMemory_AllocateAndClear(sizeof(MetisMessage));
	metisLogger_Release(&logger);
	message->ingressConnectionId=interestMessage->ingressConnectionId;

#endif

	//by wschoi
#ifdef LOG_CHECK
	printf("in metisMessageProcessor_ReceiveInterestGetname(), hasGetname=%d\n\n", interestMessage->hasGetname);
#endif


	unsigned ingressId_interestMessage = metisMessage_GetIngressConnectionId(interestMessage);
	unsigned ingressId_message = metisMessage_GetIngressConnectionId(message);
#ifdef LOG_CHECK
	printf("ingressId_interestMessage= %d, ingressId_message= %d\n\n", ingressId_interestMessage, ingressId_message);
#endif

	/*
	   if (!metisMessageProcessor_CheckAndDecrementHopLimitOnIngress(processor, interestMessage)) {
	   metisMessageProcessor_Drop(processor, interestMessage);
	   return;
	   }
	 */
	// (1) Try to aggregate in PIT
	if (metisMessageProcessor_AggregateInterestInPit(processor, message)) {
		// done
		return;
	}

	// At this point, we just created a PIT entry.  If we don't forward the interest, we need
	// to remove the PIT entry.
	/*
	// (2) Try to satisfy from content store
	if (_satisfyFromContentStore(processor, interestMessage)) {
	// done
	// If we found a content object in the CS, metisMessageProcess_SatisfyFromContentStore already
	// cleared the PIT state
	return;
	}
	 */
	// (3) Try to forward it
	if (metisMessageProcessor_ForwardViaFib_Getname(processor, interestMessage, message)) {
		// done
		return;
	}

	// Remove the PIT entry?
	processor->stats.countDroppedNoRoute++;

	if (metisLogger_IsLoggable(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug)) {
		metisLogger_Log(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug, __func__,
				"Message %p did not match FIB, no route (count %u)",
				(void *) interestMessage,
				processor->stats.countDroppedNoRoute);
	}
	//by wschoi
#ifdef LOG_CHECK
	printf("metisMessageProcessor_Drop() will be execute in metisMessageProcessor_ReceiveInterest(). \n\n");
#endif
	metisMessageProcessor_Drop(processor, interestMessage);
}




//by wschoi

	static void
metisMessageProcessor_ReceiveInterestKeyname(MetisMessageProcessor *processor, MetisMessage *interestMessage)
{
	//by wschoi
#ifdef LOG_CHECK
	printf("metisMessageProcessor_ReceiveInterestKeyname()\n\n");
#endif
	processor->stats.countInterestsReceived++;


#if 1

	//################## Change packet fields to Name A/Name B from Name B/Name A for I-Key####################

	int interestMessage_length = parcEventBuffer_GetLength(interestMessage->messageBytes);

	uint8_t interestKey_Get_from_consumer[interestMessage_length];

	for(int i=0; i<interestMessage_length;i++)
	{
		interestKey_Get_from_consumer[i]=interestMessage->messageHead[i];

	}
#ifdef LOG_CHECK
	printf("Copy interestMessage to interestKey_from_consumer\n\n");

	for(int i=0; i<interestMessage_length;i++)
	{
		printf("%x ", interestKey_Get_from_consumer[i]);
	}
	printf("\n\n");

#endif
	//create Packet header and interest header. it is fixed size.
	uint8_t interestKey_PH_IH[12];
	int PH_IH_end_point=0;
	for(int i=0; i < 12; i++)
	{
		interestKey_PH_IH[i]=interestKey_Get_from_consumer[i];
		PH_IH_end_point++;
#ifdef LOG_CHECK
		printf("interestKey_PH_IH_%d: %x \n", i, interestKey_PH_IH[i]);
#endif
	}

	//create NameB(Value name) name with name type fields. NameB name's size array is fixed field.
	uint8_t interestKey_NameB_Name[interestKey_Get_from_consumer[15]+4];
	int NameB_end_point=PH_IH_end_point;
	for (int i=0; i<(interestKey_Get_from_consumer[15]+4); i++)
	{
		interestKey_NameB_Name[i]=interestKey_Get_from_consumer[NameB_end_point];
#ifdef LOG_CHECK
		printf("interestKey_NameB_Name_%d: %x \n", i, interestKey_NameB_Name[i]);
#endif
		NameB_end_point++;
	}

	//create I-Key type
	uint8_t interestKey_KeyType[4];
	int KeyType_end_point=NameB_end_point;
	for(int i=0; i<4; i++)
	{
		interestKey_KeyType[i]=interestKey_Get_from_consumer[KeyType_end_point];
#ifdef LOG_CHECK
		printf("interestKey_KeyType_%d: %x \n", i, interestKey_KeyType[i]);
#endif
		KeyType_end_point++;

	}

	//create NameA(Key name) with name type fields. NameA name's size array is fixed field.

	uint8_t interestKey_NameA_Name[interestKey_Get_from_consumer[KeyType_end_point+3]+4];
	int NameA_end_point=KeyType_end_point;
	for(int i=0; i<interestKey_Get_from_consumer[KeyType_end_point+3]+4; i++)
	{
		interestKey_NameA_Name[i]=interestKey_Get_from_consumer[NameA_end_point];
#ifdef LOG_CHECK
		printf("interestKey_NAmeA_Name_%d: %x \n", i, interestKey_NameA_Name[i]);
#endif
		NameA_end_point++;
	}
#ifdef LOG_CHECK
	printf("NameA_end_point: %d\n", NameA_end_point);
#endif




	// change name fields
	uint8_t interestKey_changed[interestMessage_length];

	//add Packet Header and Interest Header
	PH_IH_end_point=0;
	for(int i=0; i < 12; i++)
	{
		interestKey_changed[i]=interestKey_PH_IH[i];
#ifdef LOG_CHECK
		printf("interestKey_changed_%d: %x \n", i, interestKey_changed[i]);
#endif
		PH_IH_end_point++;
	}

	//add NameA Name with name type fields
	NameA_end_point=PH_IH_end_point;
	for (int i=0; i<(interestKey_NameA_Name[3]+4); i++)
	{
		interestKey_changed[i + PH_IH_end_point]=interestKey_NameA_Name[i];
#ifdef LOG_CHECK
		printf("interestKey_changed_%d: %x \n", i + PH_IH_end_point, interestKey_changed[i + PH_IH_end_point]);
#endif
		NameA_end_point++;
	}

	//add I-Key type fields

	KeyType_end_point=NameA_end_point;

	for(int i=0; i<4; i++)
	{
		interestKey_changed[i + NameA_end_point]=interestKey_KeyType[i];

		//update value of KeyType size field.
		if(i==3)
		{
			//  interestGet_changed[i+GetName_end_point]=sizeof(interestGet_MS_Name);
			interestKey_changed[i + NameA_end_point]=interestKey_NameB_Name[i]+4;
		}
#ifdef LOG_CHECK
		printf("interestKey_changed_%d: %x \n", i + NameA_end_point, interestKey_changed[i + NameA_end_point]);
#endif

		KeyType_end_point++;
	}

	//add NameB Name with name type fields

	NameB_end_point=KeyType_end_point;
	for (int i=0; i<(interestKey_NameB_Name[3]+4); i++)
	{
		interestKey_changed[i + KeyType_end_point]=interestKey_NameB_Name[i];
#ifdef LOG_CHECK
		printf("interestKey_changed_%d: %x \n", i + KeyType_end_point, interestKey_changed[i + KeyType_end_point]);
#endif
		NameB_end_point++;
	}

#endif


#if 1
	PARCEventBuffer *buff = parcEventBuffer_Create();
	//  uint8_t metisTestDataV1_Interest_AllFields[]={0x31, 0x32};
	// name: /com/google/d3512  getname: /X/hello/1/2
	/*  uint8_t metisTestDataV1_Interest_AllFields[]={
	    0x01, 0x00, 0x00, 0x2a, //Header
	    0xff, 0x00, 0x00, 0x08,

	    0x00, 0x01, 0x00, 0x1e, //INTEREST Header

	    0x00, 0x00, 0x00, 0x1a, // NAME Header
	    0x00, 0x01, 0x00, 0x03, // /com/google/d3512
	    0x63, 0x6f, 0x6d, 0x00,
	    0x01, 0x00, 0x06, 0x67,
	    0x6f, 0x6f, 0x67, 0x6c,
	    0x65, 0x00, 0x01, 0x00,
	    0x05, 0x64, 0x33, 0x35,
	    0x31, 0x32,
	    };
	 */


	uint8_t metisTestDataV1_Interest_AllFields[]={
		0x01, 0x00, 0x00, 0x2a, //Header
		0xff, 0x00, 0x00, 0x08,

		0x00, 0x01, 0x00, 0x1e, //INTEREST Header

		0x00, 0x00, 0x00, 0x1a, // NAME Header
		0x00, 0x01, 0x00, 0x03, // /com/google/d3512
		0x63, 0x6f, 0x6d, 0x00,
		0x01, 0x00, 0x06, 0x67,
		0x6f, 0x6f, 0x67, 0x6c,
		0x65, 0x00, 0x01, 0x00,
		0x05, 0x64, 0x33, 0x35,
		0x31, 0x32,
	};

	//parcEventBuffer_Append(buff, metisTestDataV1_Interest_AllFields, sizeof(metisTestDataV1_Interest_AllFields));
	//parcEventBuffer_Append(buff, interestKey_Get_from_consumer, sizeof(interestKey_Get_from_consumer));
	parcEventBuffer_Append(buff, interestKey_changed, sizeof(interestKey_changed));
	PARCLogReporter *reporter = parcLogReporterTextStdout_Create();
	MetisLogger *logger = metisLogger_Create(reporter, parcClock_Wallclock());
	parcLogReporter_Release(&reporter);
	MetisMessage *message = metisMessage_CreateFromBuffer(1, 2, buff, logger);
	//MetisMessage *message = parcMemory_AllocateAndClear(sizeof(MetisMessage));
	metisLogger_Release(&logger);
	message->ingressConnectionId=interestMessage->ingressConnectionId;

#endif
#if 1
	//by wschoi
#ifdef LOG_CHECk
	printf("in metisMessageProcessor_ReceiveInterestKeyname(), hasKeyname=%d\n\n", interestMessage->hasKeyname);
#endif


	unsigned ingressId_interestMessage = metisMessage_GetIngressConnectionId(interestMessage);
	unsigned ingressId_message = metisMessage_GetIngressConnectionId(message);
#ifdef LOG_CHECK
	printf("ingressId_interestMessage= %d, ingressId_message= %d\n\n", ingressId_interestMessage, ingressId_message);
#endif

	/*
	   if (!metisMessageProcessor_CheckAndDecrementHopLimitOnIngress(processor, interestMessage)) {
	   metisMessageProcessor_Drop(processor, interestMessage);
	   return;
	   }
	 */
	// (1) Try to aggregate in PIT
	if (metisMessageProcessor_AggregateInterestInPit(processor, message)) {
		// done
		return;

	}
	// At this point, we just created a PIT entry.  If we don't forward the interest, we need
	// to remove the PIT entry.

	// (2) Try to satisfy from content store
	if (_satisfyFromContentStore(processor, message)) {
		// done
		// If we found a content object in the CS, metisMessageProcess_SatisfyFromContentStore already
		// cleared the PIT state
		return;
	}

	// (3) Try to forward it
	if (metisMessageProcessor_ForwardViaFib_Keyname(processor, interestMessage, message)) {
		// done
		return;
	}


	// Remove the PIT entry?
	processor->stats.countDroppedNoRoute++;

	if (metisLogger_IsLoggable(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug)) {
		metisLogger_Log(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug, __func__,
				"Message %p did not match FIB, no route (count %u)",
				(void *) interestMessage,
				processor->stats.countDroppedNoRoute);
	}
	//by wschoi
#ifdef LOG_CHECk
	printf("metisMessageProcessor_Drop() will be execute in metisMessageProcessor_ReceiveInterestKeyname(). \n\n");
#endif
	metisMessageProcessor_Drop(processor, interestMessage);
#endif

}


//by wschoi
// for MS
//REGISTRATION
//reg
        static void
metisMessageProcessor_ReceiveInterestRegistrationMS(MetisMessageProcessor *processor, MetisMessage *interestMessage)
{
        processor->stats.countInterestsReceived++;


#ifdef LOG_CHECK
        printf("metisMessageProcessor_ReceiveInterestRegistrationMS()\n");
        printf("interestMessage->Regname->memoryLength= %d\n",interestMessage->Regname->memoryLength);
        for(int i=0; i<interestMessage->Regname->memoryLength;i++)
        {
                printf("interestMessage->Regname->memory= %x\n",interestMessage->Regname->memory[i]);
        }

#endif
        //make message for PIT registration
        //PH, IH, Name type, keyname

        //make key name
        int Key_name_length=interestMessage->Regname->memoryLength;
        uint8_t *Key_name=interestMessage->Regname->memory;

        int Key_name_length_with_nametypefields=Key_name_length+4;
        uint8_t Key_name_with_nametypefields[Key_name_length_with_nametypefields];





//make Name key type fields
        Key_name_with_nametypefields[0]=0x00;
        Key_name_with_nametypefields[1]=0x00;
        Key_name_with_nametypefields[2]=0x00;
        Key_name_with_nametypefields[3]=Key_name_length;
        for(int i=0; i<Key_name_length; i++)
        {
                Key_name_with_nametypefields[i+4]=Key_name[i];
        }

#ifdef LOG_CHECK
        printf("metisMessageProcessor_ReceiveInterestRegistrationMS(), Key_name_with_nametypefields\n");
        for(int i=0; i<Key_name_length_with_nametypefields; i++)
        {
                printf("%x\n", Key_name_with_nametypefields[i]);
        }

#endif



        //create Packet header and interest header. it is fixed size.
        uint8_t interestReg_PH_IH[12];
        for(int i=0; i < 12; i++)
        {
                interestReg_PH_IH[i]=interestMessage->messageHead[i];
        }

        //make Reg packet
        int interestReg_length=12   //header and interest type fileds length
                +Key_name_length_with_nametypefields;

        uint8_t interestReg[interestReg_length];

        int PH_IH_end_point=0;
        int Key_name_end_point=0;

        for(int i=0; i<12;i++)
        {
                interestReg[i]=interestReg_PH_IH[i];
                PH_IH_end_point++;
        }


        for(int i=0; i<Key_name_length_with_nametypefields;i++)
        {
                interestReg[i+PH_IH_end_point]=Key_name_with_nametypefields[i];
                Key_name_end_point++;
        }
        Key_name_end_point=Key_name_end_point+PH_IH_end_point;



        //change packet and interest lengh value
        interestReg[3]=Key_name_end_point;
        interestReg[11]=Key_name_length_with_nametypefields;

#ifdef LOG_CHECK
        printf("interestReg_length= %d\n", interestReg_length);
        printf("Key_name_end_point= %d\n", Key_name_end_point);
        for(int i=0; i<interestReg_length; i++)
        {

                printf("interestReg %x\n", interestReg[i]);
        }

#endif


#if 1
        //by wschoi
        PARCEventBuffer *buff = parcEventBuffer_Create();
        parcEventBuffer_Append(buff, interestReg, interestReg_length);
        PARCLogReporter *reporter = parcLogReporterTextStdout_Create();
        MetisLogger *logger = metisLogger_Create(reporter, parcClock_Wallclock());
        parcLogReporter_Release(&reporter);
        MetisMessage *message = metisMessage_CreateFromBuffer(1, 2, buff, logger);
        metisLogger_Release(&logger);
        message->ingressConnectionId=interestMessage->ingressConnectionId;



        // (1) Try to aggregate in PIT
        if (metisMessageProcessor_AggregateInterestInPit(processor, message)) {
                // done
                return;
        }

        // At this point, we just created a PIT entry.  If we don't forward the interest, we need
        // to remove the PIT entry.

        // (2) Try to satisfy from content store
        if (_satisfyFromContentStore(processor, interestMessage)) {
                // done
                // If we found a content object in the CS, metisMessageProcess_SatisfyFromContentStore already
                // cleared the PIT state
                return;
        }
  // (3) Try to forward it
        if (metisMessageProcessor_ForwardViaFib_RegtoMS(processor, interestMessage, message)) {
                // done
                return;
        }

        // Remove the PIT entry?

        if (metisLogger_IsLoggable(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug)) {
                metisLogger_Log(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug, __func__,
                                "Message %p did not match FIB, no route (count %u)",
                                (void *) interestMessage,
                                processor->stats.countDroppedNoRoute);
        }
        metisMessageProcessor_Drop(processor, interestMessage);
#endif
}

//by wschoi
//for MS
//add
    static void
metisMessageProcessor_ReceiveInterestRegistrationMS_add(MetisMessageProcessor *processor, MetisMessage *interestMessage)
{
        processor->stats.countInterestsReceived++;


#ifdef LOG_CHECK
        printf("metisMessageProcessor_ReceiveInterestRegistrationMS_add()\n");
        printf("interestMessage->Reg_addname->memoryLength= %d\n",interestMessage->Reg_addname->memoryLength);
        for(int i=0; i<interestMessage->Reg_addname->memoryLength;i++)
        {
                printf("interestMessage->Reg_addname->memory= %x\n",interestMessage->Reg_addname->memory[i]);
        }

#endif
        //make message for PIT registration

//PH, IH, Name type, keyname

        //make key name
        int Key_name_length=interestMessage->Reg_addname->memoryLength;
        uint8_t *Key_name=interestMessage->Reg_addname->memory;

        int Key_name_length_with_nametypefields=Key_name_length+4;
        uint8_t Key_name_with_nametypefields[Key_name_length_with_nametypefields];

        //make Name key type fields
        Key_name_with_nametypefields[0]=0x00;
        Key_name_with_nametypefields[1]=0x00;
        Key_name_with_nametypefields[2]=0x00;
        Key_name_with_nametypefields[3]=Key_name_length;
        for(int i=0; i<Key_name_length; i++)
        {
                Key_name_with_nametypefields[i+4]=Key_name[i];
        }

#ifdef LOG_CHECK
        printf("metisMessageProcessor_ReceiveInterestRegistrationMS_add(), Key_name_with_nametypefields\n");
        for(int i=0; i<Key_name_length_with_nametypefields; i++)
        {
                printf("%x\n", Key_name_with_nametypefields[i]);
        }

#endif



        //create Packet header and interest header. it is fixed size.
        uint8_t interestReg_PH_IH[12];
        for(int i=0; i < 12; i++)
        {
                interestReg_PH_IH[i]=interestMessage->messageHead[i];
        }

        //make Reg packet
        int interestReg_length=12   //header and interest type fileds length
                +Key_name_length_with_nametypefields;

        uint8_t interestReg[interestReg_length];

        int PH_IH_end_point=0;
        int Key_name_end_point=0;

        for(int i=0; i<12;i++)
        {
                interestReg[i]=interestReg_PH_IH[i];
                PH_IH_end_point++;
        }


        for(int i=0; i<Key_name_length_with_nametypefields;i++)
        {
                interestReg[i+PH_IH_end_point]=Key_name_with_nametypefields[i];
                Key_name_end_point++;
        }
        Key_name_end_point=Key_name_end_point+PH_IH_end_point;

        //change packet and interest lengh value
        interestReg[3]=Key_name_end_point;
        interestReg[11]=Key_name_length_with_nametypefields;

#ifdef LOG_CHECK
        printf("interestReg_length= %d\n", interestReg_length);
        printf("Key_name_end_point= %d\n", Key_name_end_point);
        for(int i=0; i<interestReg_length; i++)
        {

                printf("interestReg %x\n", interestReg[i]);
        }

#endif

#if 1
        //by wschoi
        PARCEventBuffer *buff = parcEventBuffer_Create();
        parcEventBuffer_Append(buff, interestReg, interestReg_length);
        PARCLogReporter *reporter = parcLogReporterTextStdout_Create();
        MetisLogger *logger = metisLogger_Create(reporter, parcClock_Wallclock());
        parcLogReporter_Release(&reporter);
        MetisMessage *message = metisMessage_CreateFromBuffer(1, 2, buff, logger);
        metisLogger_Release(&logger);
        message->ingressConnectionId=interestMessage->ingressConnectionId;

        // (1) Try to aggregate in PIT
        if (metisMessageProcessor_AggregateInterestInPit(processor, message)) {
                // done
                return;
        }

        // At this point, we just created a PIT entry.  If we don't forward the interest, we need
        // to remove the PIT entry.

        // (2) Try to satisfy from content store
        if (_satisfyFromContentStore(processor, interestMessage)) {
                // done
                // If we found a content object in the CS, metisMessageProcess_SatisfyFromContentStore already
                // cleared the PIT state
                return;
        }

        // (3) Try to forward it
        if (metisMessageProcessor_ForwardViaFib_RegtoMS(processor, interestMessage, message)) {
                // done
                return;
        }

        // Remove the PIT entry?

        if (metisLogger_IsLoggable(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug)) {
                metisLogger_Log(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug, __func__,
                                "Message %p did not match FIB, no route (count %u)",
                                (void *) interestMessage,
                                processor->stats.countDroppedNoRoute);
        }
        metisMessageProcessor_Drop(processor, interestMessage);
#endif
}


//by wschoi
//for MS
//del
        static void
metisMessageProcessor_ReceiveInterestRegistrationMS_del(MetisMessageProcessor *processor, MetisMessage *interestMessage)
{
        processor->stats.countInterestsReceived++;


#ifdef LOG_CHECK
        printf("metisMessageProcessor_ReceiveInterestRegistrationMS_del()\n");
        printf("interestMessage->Reg_delname->memoryLength= %d\n",interestMessage->Reg_delname->memoryLength);
        for(int i=0; i<interestMessage->Reg_delname->memoryLength;i++)
        {
                printf("interestMessage->Reg_delname->memory= %x\n",interestMessage->Reg_delname->memory[i]);
        }

#endif
 //make message for PIT registration
        //PH, IH, Name type, keyname

        //make key name
        int Key_name_length=interestMessage->Reg_delname->memoryLength;
        uint8_t *Key_name=interestMessage->Reg_delname->memory;

        int Key_name_length_with_nametypefields=Key_name_length+4;
        uint8_t Key_name_with_nametypefields[Key_name_length_with_nametypefields];

        //make Name key type fields
        Key_name_with_nametypefields[0]=0x00;
        Key_name_with_nametypefields[1]=0x00;
        Key_name_with_nametypefields[2]=0x00;
        Key_name_with_nametypefields[3]=Key_name_length;
        for(int i=0; i<Key_name_length; i++)
        {
                Key_name_with_nametypefields[i+4]=Key_name[i];
        }


#ifdef LOG_CHECK
        printf("metisMessageProcessor_ReceiveInterestRegistrationMS_del(), Key_name_with_nametypefields\n");
        for(int i=0; i<Key_name_length_with_nametypefields; i++)
        {
                printf("%x\n", Key_name_with_nametypefields[i]);
        }

#endif



        //create Packet header and interest header. it is fixed size.
        uint8_t interestReg_PH_IH[12];
        for(int i=0; i < 12; i++)
        {
                interestReg_PH_IH[i]=interestMessage->messageHead[i];
        }

        //make Reg packet
        int interestReg_length=12   //header and interest type fileds length
                +Key_name_length_with_nametypefields;

        uint8_t interestReg[interestReg_length];

        int PH_IH_end_point=0;
        int Key_name_end_point=0;

        for(int i=0; i<12;i++)
        {
                interestReg[i]=interestReg_PH_IH[i];
                PH_IH_end_point++;
        }


        for(int i=0; i<Key_name_length_with_nametypefields;i++)
        {
                interestReg[i+PH_IH_end_point]=Key_name_with_nametypefields[i];
                Key_name_end_point++;
        }
        Key_name_end_point=Key_name_end_point+PH_IH_end_point;



        //change packet and interest lengh value
        interestReg[3]=Key_name_end_point;
        interestReg[11]=Key_name_length_with_nametypefields;

#ifdef LOG_CHECK
        printf("interestReg_length= %d\n", interestReg_length);
        printf("Key_name_end_point= %d\n", Key_name_end_point);
        for(int i=0; i<interestReg_length; i++)
        {

                printf("interestReg %x\n", interestReg[i]);
        }

#endif

#if 1
        //by wschoi
        PARCEventBuffer *buff = parcEventBuffer_Create();
        parcEventBuffer_Append(buff, interestReg, interestReg_length);
        PARCLogReporter *reporter = parcLogReporterTextStdout_Create();
        MetisLogger *logger = metisLogger_Create(reporter, parcClock_Wallclock());
        parcLogReporter_Release(&reporter);
        MetisMessage *message = metisMessage_CreateFromBuffer(1, 2, buff, logger);
        metisLogger_Release(&logger);
        message->ingressConnectionId=interestMessage->ingressConnectionId;



        // (1) Try to aggregate in PIT
        if (metisMessageProcessor_AggregateInterestInPit(processor, message)) {
                // done
                return;
        }

        // At this point, we just created a PIT entry.  If we don't forward the interest, we need
        // to remove the PIT entry.

        // (2) Try to satisfy from content store
        if (_satisfyFromContentStore(processor, interestMessage)) {
                // done
                // If we found a content object in the CS, metisMessageProcess_SatisfyFromContentStore already
                // cleared the PIT state
                return;
        }
 // (3) Try to forward it
        if (metisMessageProcessor_ForwardViaFib_RegtoMS(processor, interestMessage, message)) {
                // done
                return;
        }

        // Remove the PIT entry?

        if (metisLogger_IsLoggable(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug)) {
                metisLogger_Log(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug, __func__,
                                "Message %p did not match FIB, no route (count %u)",
                                (void *) interestMessage,
                                processor->stats.countDroppedNoRoute);
        }
        metisMessageProcessor_Drop(processor, interestMessage);
#endif
}



//by wschoi
//for MS
//dereg
        static void
metisMessageProcessor_ReceiveInterestRegistrationMS_dereg(MetisMessageProcessor *processor, MetisMessage *interestMessage)
{
        processor->stats.countInterestsReceived++;


#ifdef LOG_CHECK
        printf("metisMessageProcessor_ReceiveInterestRegistrationMS_dereg()\n");
        printf("interestMessage->Reg_deregname->memoryLength= %d\n",interestMessage->Reg_deregname->memoryLength);
        for(int i=0; i<interestMessage->Reg_deregname->memoryLength;i++)
        {
                printf("interestMessage->Reg_deregname->memory= %x\n",interestMessage->Reg_deregname->memory[i]);
        }

#endif
        //make message for PIT registration
        //PH, IH, Name type, keyname

        //make key name
        int Key_name_length=interestMessage->Reg_deregname->memoryLength;
        uint8_t *Key_name=interestMessage->Reg_deregname->memory;

        int Key_name_length_with_nametypefields=Key_name_length+4;
        uint8_t Key_name_with_nametypefields[Key_name_length_with_nametypefields];

        //make Name key type fields
        Key_name_with_nametypefields[0]=0x00;
        Key_name_with_nametypefields[1]=0x00;
        Key_name_with_nametypefields[2]=0x00;
        Key_name_with_nametypefields[3]=Key_name_length;
 for(int i=0; i<Key_name_length; i++)
        {
                Key_name_with_nametypefields[i+4]=Key_name[i];
        }

#ifdef LOG_CHECK
        printf("metisMessageProcessor_ReceiveInterestRegistrationMS_dereg(), Key_name_with_nametypefields\n");
        for(int i=0; i<Key_name_length_with_nametypefields; i++)
        {
                printf("%x\n", Key_name_with_nametypefields[i]);
        }

#endif



        //create Packet header and interest header. it is fixed size.
        uint8_t interestReg_PH_IH[12];
        for(int i=0; i < 12; i++)
        {
                interestReg_PH_IH[i]=interestMessage->messageHead[i];
        }

        //make Reg packet
        int interestReg_length=12   //header and interest type fileds length
                +Key_name_length_with_nametypefields;

        uint8_t interestReg[interestReg_length];

        int PH_IH_end_point=0;
 int Key_name_end_point=0;

        for(int i=0; i<12;i++)
        {
                interestReg[i]=interestReg_PH_IH[i];
                PH_IH_end_point++;
        }


        for(int i=0; i<Key_name_length_with_nametypefields;i++)
        {
                interestReg[i+PH_IH_end_point]=Key_name_with_nametypefields[i];
                Key_name_end_point++;
        }
        Key_name_end_point=Key_name_end_point+PH_IH_end_point;



        //change packet and interest lengh value
        interestReg[3]=Key_name_end_point;
        interestReg[11]=Key_name_length_with_nametypefields;

#ifdef LOG_CHECK
        printf("interestReg_length= %d\n", interestReg_length);
        printf("Key_name_end_point= %d\n", Key_name_end_point);
        for(int i=0; i<interestReg_length; i++)
        {

                printf("interestReg %x\n", interestReg[i]);
        }

#endif

#if 1
        //by wschoi
        PARCEventBuffer *buff = parcEventBuffer_Create();
        parcEventBuffer_Append(buff, interestReg, interestReg_length);
        PARCLogReporter *reporter = parcLogReporterTextStdout_Create();
        MetisLogger *logger = metisLogger_Create(reporter, parcClock_Wallclock());
        parcLogReporter_Release(&reporter);
        MetisMessage *message = metisMessage_CreateFromBuffer(1, 2, buff, logger);
        metisLogger_Release(&logger);
        message->ingressConnectionId=interestMessage->ingressConnectionId;



        // (1) Try to aggregate in PIT
        if (metisMessageProcessor_AggregateInterestInPit(processor, message)) {
                // done
                return;
        }

        // At this point, we just created a PIT entry.  If we don't forward the interest, we need
        // to remove the PIT entry.

        // (2) Try to satisfy from content store
        if (_satisfyFromContentStore(processor, interestMessage)) {
                // done
                // If we found a content object in the CS, metisMessageProcess_SatisfyFromContentStore already
                // cleared the PIT state
                return;
        }

        // (3) Try to forward it
        if (metisMessageProcessor_ForwardViaFib_RegtoMS(processor, interestMessage, message)) {
                // done
                return;
        }

        // Remove the PIT entry?

        if (metisLogger_IsLoggable(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug)) {
                metisLogger_Log(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug, __func__,
                                "Message %p did not match FIB, no route (count %u)",
                                (void *) interestMessage,
                                processor->stats.countDroppedNoRoute);
        }
        metisMessageProcessor_Drop(processor, interestMessage);
#endif
}






//by wschoi
//REGISTRATION
//reg
	static void
metisMessageProcessor_ReceiveInterestRegistration(MetisMessageProcessor *processor, MetisMessage *interestMessage)
{
	processor->stats.countInterestsReceived++;


#ifdef LOG_CHECK
	printf("metisMessageProcessor_ReceiveInterestRegistration()\n");
#endif

	//fetch MS name from MSname.txt
	FILE *fp_MSname;

/*****Warning****
* This file_path should be changed by your own path installing 'sb-forwarder' 
* end of path */

	fp_MSname = fopen("/home/nrs/CICN/sb-forwarder/metis/config/MSname.txt","r");
	char MSname[256];
	fscanf(fp_MSname, "%s", MSname);

	int MSname_size=0;

	while(MSname[MSname_size] != '\0')
	{
		MSname_size++;
	}
#ifdef LOG_CHECK
	printf("fetch MS name from MSname.txt: %s, size: %d\n", MSname, MSname_size);

#endif
	fclose(fp_MSname);


	//make MS1 name fields with Name type field

#if 1


	int slash_check = 0;

	int j = 0;
	int k = 4;
	char MS_hex_name[128];
	int MS_hex_name_size = 0;
	int MS_name_size_with_typefields = 0;

	MS_hex_name[0] = 0x00; //name type 1
	MS_hex_name[1] = 0x00; //name type 2

	for(int i=0; i<(MSname_size);i++)
	{
		if(MSname[j]=='/')
		{
			MS_hex_name[k] = 0x00; // slash
			k++;

			MS_hex_name[k] = 0x01;
			k++;

			MS_hex_name[k] = 0x00;
			k++;

			MS_hex_name[k] = 0x00; //size
			slash_check = k;
			k++;
		}
		else
		{

			MS_hex_name[k] = MSname[j];
			MS_hex_name[slash_check]= MS_hex_name[slash_check]+0x01;
			k++;

		}
		j++;
	}

	MS_name_size_with_typefields = k;//with name type and length fields
	MS_hex_name_size=MS_name_size_with_typefields - 4; //without name type and length fields
	MS_hex_name[k] = '\0';
	MS_hex_name[2] = 0x00; //name filed size 1
	MS_hex_name[3] = 0x01 * (MS_hex_name_size); //without name and fields





#ifdef LOG_CHECK
	printf("MS_hex_name_size= %d\n", MS_hex_name_size);

	for(int i=0;i<MS_hex_name_size;i++)
		printf("MS_hex_name 0x%x\n", MS_hex_name[i]);
#endif
	char MS_hex_name_without_type[MS_hex_name_size];
	for(int i=0; i<MS_hex_name_size;i++)
		MS_hex_name_without_type[i]=MS_hex_name[i+4];

	int compare_size = 0;
	if(MS_hex_name_size>interestMessage->name->memoryLength)
	{
		compare_size=interestMessage->name->memoryLength;
	}
	else
	{
		compare_size=MS_hex_name_size;
	}
	int compare_size_result = 0;
	for(int i = 0; i < compare_size; i++)
	{
		if(MS_hex_name_without_type[i]==interestMessage->name->memory[i])
		{
			compare_size_result++;

		}
	}

	if(compare_size_result==compare_size)
	{
#ifdef LOG_CHECK
		printf("MS_hex_name_without_type == interestMessage->name->memory \n");
#endif
		metisMessageProcessor_ReceiveInterestRegistrationMS(processor, interestMessage);
		return;
	}


#ifdef LOG_CHECK

			printf("message->name, in metisMessageProcessor_ReceiveReg()\n\n");
			for(int i=0;  i<interestMessage->name->memoryLength;i++)
			{
				printf("%x\n", interestMessage->name->memory[i]);
			}
			printf("\n\n");
#endif


#endif


#ifdef LOG_CHECK
	int message_length = parcEventBuffer_GetLength(interestMessage->messageBytes);
	for(int i= 0 ; i<message_length; i++)
	{
		printf("interestMessage->memory[%d] = %x \n", i, interestMessage->messageHead[i]) ;
	}
#endif

	//make key name
	int Key_name_length = interestMessage->Regname->memoryLength;
	uint8_t *Key_name = interestMessage->Regname->memory;

	int Key_name_length_with_typefields=Key_name_length + 8; //key type and name type
	uint8_t Key_name_with_typefields[Key_name_length_with_typefields];

	//make Reg key type fields
	Key_name_with_typefields[0] = 0x01;
	Key_name_with_typefields[1] = 0x14;
	Key_name_with_typefields[2] = 0x00;
	Key_name_with_typefields[3] = Key_name_length + 4;

	//make Reg key name type fields
	Key_name_with_typefields[4] = 0x00;
	Key_name_with_typefields[5] = 0x00;
	Key_name_with_typefields[6] = 0x00;
	Key_name_with_typefields[7] = Key_name_length;

	for(int i=0; i < Key_name_length; i++)
	{
		Key_name_with_typefields[i + 8] = Key_name[i];
	}

#ifdef LOG_CHECK
	printf("metisMessageProcessor_ReceiveInterestRegistration(), Key_name_with_typefields\n");

	for(int i=0; i<Key_name_length_with_typefields; i++)
	{
		printf("key_name_with_typefields = %x\n", Key_name_with_typefields[i]);
	}

#endif

#if 1

/*****Warning****
* This file_path should be changed by your own path installing 'sb-forwarder' 
* end of path */

	//fetch Value name from ValueName.txt
	FILE *fp_ValueName;
	fp_ValueName = fopen("/home/nrs/CICN/ccnxReg-Client/config/ValueName.txt","r");

	char ValueName[256];
	fscanf(fp_ValueName, "%s", ValueName);

	int ValueName_size = 0;

	while(ValueName[ValueName_size] != '\0')
	{
		ValueName_size++;
	}
#ifdef LOG_CHECK
	printf("fetch Value name from ValueName.txt: %s, size: %d\n", ValueName, ValueName_size);

#endif
	fclose(fp_ValueName);
#endif
	//make value hex name

		//reset check parameter
		slash_check = 0;
	j = 0;
	k = 4;
	char Value_name_with_nametypefields[128];
	int Value_name_length_with_nametypefields = 0;
	int Value_hex_name_size = 0 ;
	Value_name_with_nametypefields[0] = 0x00; //name type 1
	Value_name_with_nametypefields[1] = 0x00; //name type 2

	for(int i=0; i<(ValueName_size);i++)
	{
		if(ValueName[j] == '/')
		{
			Value_name_with_nametypefields[k] = 0x00; // slash
			k++;

			Value_name_with_nametypefields[k] = 0x01;
			k++;

			Value_name_with_nametypefields[k] = 0x00;
			k++;

			Value_name_with_nametypefields[k] = 0x00; //size
			slash_check=k;
			k++;
		}
		else
		{

			Value_name_with_nametypefields[k] = ValueName[j];
			Value_name_with_nametypefields[slash_check]= Value_name_with_nametypefields[slash_check] + 0x01;
			k++;

		}
		j++;
	}

	Value_name_length_with_nametypefields = k;//with name type and length fields
	Value_hex_name_size = Value_name_length_with_nametypefields - 4; //without name type and length fields
	Value_name_with_nametypefields[k] = '\0';
	Value_name_with_nametypefields[2] = 0x00; //name filed size 1
	Value_name_with_nametypefields[3] = 0x01 * (MS_hex_name_size); //without name and fields


#ifdef LOG_CHECK
	printf("Value_hex_name_size= %d\n", Value_hex_name_size);

	for(int i=0;i<Value_name_length_with_nametypefields;i++)
		printf("Value_hex_name 0x%x\n", Value_name_with_nametypefields[i]);
#endif

	int Value_name_length_with_typefields=Value_name_length_with_nametypefields+4;
	uint8_t Value_name_with_typefields[Value_name_length_with_typefields];

	//make Reg value type fields
	Value_name_with_typefields[0] = 0x01;
	Value_name_with_typefields[1] = 0x15;
	Value_name_with_typefields[2] = 0x00;
	Value_name_with_typefields[3] = Value_name_length_with_nametypefields;


	for(int i=0; i<Value_name_length_with_nametypefields; i++)
	{
		Value_name_with_typefields[i + 4] = Value_name_with_nametypefields[i];
	}
#ifdef LOG_CHECK
	printf("Value_name_length_with_nametypefields= %d\n", Value_name_length_with_nametypefields);

	for(int i=0;i<Value_name_length_with_typefields;i++)
		printf("Value_name_with_typefields 0x%x\n", Value_name_with_typefields[i]);
#endif


	//create Packet header and interest header. it is fixed size.
	uint8_t interestReg_PH_IH[12];
	for(int i=0; i < 12; i++)
	{
		interestReg_PH_IH[i] = interestMessage->messageHead[i];
	}

	//make Reg packet
	int interestReg_length = 12 //header and interest type fileds length
		+ MS_name_size_with_typefields
		+ Key_name_length_with_typefields
		+ Value_name_length_with_typefields;

	uint8_t interestReg[interestReg_length];

	int PH_IH_end_point = 0;
	int MS_name_end_point = 0;
	int Key_name_end_point = 0;
	int Value_name_end_point = 0;

	for(int i = 0; i < 12;i++)
	{
		interestReg[i] = interestReg_PH_IH[i];
		PH_IH_end_point++;
	}

	for(int i=0; i < MS_name_size_with_typefields; i++)
	{
		interestReg[i+PH_IH_end_point] = MS_hex_name[i];
		MS_name_end_point++;
	}
	MS_name_end_point = MS_name_end_point + PH_IH_end_point;

	for(int i=0; i<Key_name_length_with_typefields;i++)
	{
		interestReg[i+MS_name_end_point] = Key_name_with_typefields[i];
		Key_name_end_point++;
	}
	Key_name_end_point = Key_name_end_point + MS_name_end_point;


	for(int i=0; i<Value_name_length_with_typefields;i++)
	{
		interestReg[i + Key_name_end_point] = Value_name_with_typefields[i];
		Value_name_end_point++;
	}
	Value_name_end_point = Value_name_end_point + Key_name_end_point;

	//change packet and interest lengh value
	interestReg[3] = Value_name_end_point;
	interestReg[11] = MS_name_size_with_typefields
		+ Key_name_length_with_typefields
		+ Value_name_length_with_typefields;

#ifdef LOG_CHECK

	printf("interestReg_length = %d\n", interestReg_length);
	printf("Value_name_end_point = %d\n", Value_name_end_point);

	for(int i=0; i < interestReg_length; i++)
	{

		printf("interestReg %x\n", interestReg[i]);
	}

#endif
#if 1
		//by wschoi
		PARCEventBuffer *buff = parcEventBuffer_Create();
	parcEventBuffer_Append(buff, interestReg, interestReg_length);
	PARCLogReporter *reporter = parcLogReporterTextStdout_Create();
	MetisLogger *logger = metisLogger_Create(reporter, parcClock_Wallclock());
	parcLogReporter_Release(&reporter);
	MetisMessage *message = metisMessage_CreateFromBuffer(1, 2, buff, logger);
	metisLogger_Release(&logger);
	message->ingressConnectionId = interestMessage->ingressConnectionId;

	//make pit_interest
	int pit_interest_length = 12 + Key_name_length + 4;
	uint8_t pit_interest[pit_interest_length];

	//make PH and IH
	for(int i=0; i<12;i++)
	{
		pit_interest[i] = interestReg_PH_IH[i];
	}

	//make name fields
	pit_interest[12] = 0x00;
	pit_interest[13] = 0x00;
	pit_interest[14] = 0x00;
	pit_interest[15] = Key_name_length;

	for(int i=16; i < pit_interest_length;i++)
	{
		pit_interest[i] = Key_name[i - 16];
	}

	//change packet and interest lengh value
	pit_interest[3] = pit_interest_length;
	pit_interest[11] = Key_name_length+4;

#ifdef LOG_CHECK
	for(int i=0;  i < pit_interest_length;i++)
	{
		printf("pit_interest[%d]: %x\n", i, pit_interest[i]);
	}


#endif

	PARCEventBuffer *buff_pit_interest = parcEventBuffer_Create();
	parcEventBuffer_Append(buff_pit_interest, pit_interest, pit_interest_length);
	PARCLogReporter *reporter_pit_interest = parcLogReporterTextStdout_Create();
	MetisLogger *logger_pit_interest = metisLogger_Create(reporter_pit_interest, parcClock_Wallclock());
	parcLogReporter_Release(&reporter_pit_interest);
	MetisMessage *message_pit_interest = metisMessage_CreateFromBuffer(1, 2, buff_pit_interest, logger_pit_interest);
	metisLogger_Release(&logger_pit_interest);
	message_pit_interest->ingressConnectionId=interestMessage->ingressConnectionId;




	// (1) Try to aggregate in PIT
	if (metisMessageProcessor_AggregateInterestInPit(processor, message_pit_interest)) {
		// done
		return;
	}

	// At this point, we just created a PIT entry.  If we don't forward the interest, we need
	// to remove the PIT entry.

	// (2) Try to satisfy from content store
	if (_satisfyFromContentStore(processor, interestMessage)) {
		// done
		// If we found a content object in the CS, metisMessageProcess_SatisfyFromContentStore already
		// cleared the PIT state
		return;
	}

	// (3) Try to forward it
	if (metisMessageProcessor_ForwardViaFib_Reg(processor, message_pit_interest, message)) {
		// done
		return;
	}

	// Remove the PIT entry?
	processor->stats.countDroppedNoRoute++;


	if (metisLogger_IsLoggable(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug)) {
		metisLogger_Log(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug, __func__,
				"Message %p did not match FIB, no route (count %u)",
				(void *) interestMessage,
				processor->stats.countDroppedNoRoute);
	}
	metisMessageProcessor_Drop(processor, interestMessage);
#endif

}

//by wschoi
//add

	static void
metisMessageProcessor_ReceiveInterestRegistration_add(MetisMessageProcessor *processor, MetisMessage *interestMessage)
{
	processor->stats.countInterestsReceived++;


#ifdef LOG_CHECK
	printf("metisMessageProcessor_ReceiveInterestRegistration_add()\n");
#endif

/*****Warning****
* This file_path should be changed by your own path installing 'sb-forwarder' 
* end of path */

	//fetch MS name from MSname.txt
	FILE *fp_MSname;
	fp_MSname = fopen("/home/nrs/CICN/sb-forwarder/metis/config/MSname.txt","r");

	char MSname[256];
	fscanf(fp_MSname, "%s", MSname);

	int MSname_size=0;

	while(MSname[MSname_size] != '\0')
	{
		MSname_size++;
	}
#ifdef LOG_CHECK
	printf("fetch MS name from MSname.txt: %s, size: %d\n", MSname, MSname_size);

#endif
	fclose(fp_MSname);



	//make MS1 name fields with Name type field

#if 1


	int slash_check = 0;

	int j = 0;
	int k = 4;
	char MS_hex_name[128];
	int MS_hex_name_size = 0;
	int MS_name_size_with_typefields = 0;

	MS_hex_name[0] = 0x00; //name type 1
	MS_hex_name[1] = 0x00; //name type 2

	for(int i=0; i<(MSname_size);i++)
	{
		if(MSname[j] == '/')
		{
			MS_hex_name[k] = 0x00; // slash
			k++;

			MS_hex_name[k] = 0x01;
			k++;

			MS_hex_name[k] = 0x00;
			k++;

			MS_hex_name[k] = 0x00; //size
			slash_check=k;
			k++;
		}
		else
		{

			MS_hex_name[k] = MSname[j];
			MS_hex_name[slash_check]= MS_hex_name[slash_check] + 0x01;
			k++;

		}
		j++;
	}

	MS_name_size_with_typefields = k;//with name type and length fields
	MS_hex_name_size=MS_name_size_with_typefields - 4; //without name type and length fields
	MS_hex_name[k] = '\0';
	MS_hex_name[2] = 0x00; //name filed size 1
	MS_hex_name[3] = 0x01 * (MS_hex_name_size); //without name and fields





#ifdef LOG_CHECK
	printf("MS_hex_name_size= %d\n", MS_hex_name_size);

	for(int i=0;i<MS_hex_name_size;i++)
		printf("MS_hex_name 0x%x\n", MS_hex_name[i]);
#endif



#endif

	char MS_hex_name_without_type[MS_hex_name_size];
	for(int i=0; i<MS_hex_name_size;i++)
	{
		MS_hex_name_without_type[i]=MS_hex_name[i+4];
	}

	int compare_size = 0;
	if(MS_hex_name_size>interestMessage->name->memoryLength)
	{
		compare_size=interestMessage->name->memoryLength;
	}
	else
	{
		compare_size=MS_hex_name_size;
	}
	int compare_size_result = 0;
	for(int i = 0; i < compare_size; i++)
	{
		if(MS_hex_name_without_type[i]==interestMessage->name->memory[i])
		{
			compare_size_result++;

		}
	}

	if(compare_size_result==compare_size)
	{
#ifdef LOG_CHECK
		printf("MS_hex_name_without_type == interestMessage->name->memory \n");
#endif
		metisMessageProcessor_ReceiveInterestRegistrationMS_add(processor, interestMessage);
		return;
	}


#ifdef LOG_CHECK
	int message_length = parcEventBuffer_GetLength(interestMessage->messageBytes);
	for(int i= 0 ; i<message_length; i++)
	{
		printf("interestMessage->memory[%d] = %x \n", i, interestMessage->messageHead[i]) ;
	}
#endif


	//make key name
	int Key_name_length=interestMessage->Reg_addname->memoryLength;
	uint8_t *Key_name=interestMessage->Reg_addname->memory;

	int Key_name_length_with_typefields=Key_name_length+8; //key type and name type
	uint8_t Key_name_with_typefields[Key_name_length_with_typefields];

	//make Reg add key type fields
	Key_name_with_typefields[0] = 0x01;
	Key_name_with_typefields[1] = 0x17;
	Key_name_with_typefields[2] = 0x00;
	Key_name_with_typefields[3] = Key_name_length+4;

	//make Reg key name type fields
	Key_name_with_typefields[4] = 0x00;
	Key_name_with_typefields[5] = 0x00;
	Key_name_with_typefields[6] = 0x00;
	Key_name_with_typefields[7] = Key_name_length;

	for(int i=0; i<Key_name_length; i++)
	{
		Key_name_with_typefields[i + 8] = Key_name[i];
	}




#ifdef LOG_CHECK
	printf("metisMessageProcessor_ReceiveInterestRegistration_add(), Key_name_with_typefields\n");

	for(int i=0; i<Key_name_length_with_typefields; i++)
	{
		printf("key_name_with_typefields = %x\n", Key_name_with_typefields[i]);
	}

#endif



#if 1

/*****Warning****
* This file_path should be changed by your own path installing 'sb-forwarder' 
* end of path */

	//fetch Value name from ValueName.txt
	FILE *fp_ValueName;
	fp_ValueName = fopen("/home/nrs/CICN/ccnxReg-Client/config/ValueName.txt","r");

	char ValueName[256];
	fscanf(fp_ValueName, "%s", ValueName);

	int ValueName_size = 0;

	while(ValueName[ValueName_size] != '\0')
	{
		ValueName_size++;
	}
#ifdef LOG_CHECK
	printf("fetch Value name from ValueName.txt: %s, size: %d\n", ValueName, ValueName_size);
#endif

	fclose(fp_ValueName);
#endif

	//make value hex name
	//reset check parameter
	slash_check=0;
	j=0;
	k=4;
	char Value_name_with_nametypefields[128];
	int Value_name_length_with_nametypefields = 0;
	int Value_hex_name_size = 0;
	Value_name_with_nametypefields[0] = 0x00; //name type 1
	Value_name_with_nametypefields[1] = 0x00; //name type 2

	for(int i=0; i<(ValueName_size);i++)
	{
		if(ValueName[j] == '/')
		{
			Value_name_with_nametypefields[k] = 0x00; // slash
			k++;

			Value_name_with_nametypefields[k] = 0x01;
			k++;

			Value_name_with_nametypefields[k] = 0x00;
			k++;

			Value_name_with_nametypefields[k] = 0x00; //size
			slash_check = k;
			k++;
		}
		else
		{
			Value_name_with_nametypefields[k] = ValueName[j];
			Value_name_with_nametypefields[slash_check] = Value_name_with_nametypefields[slash_check] + 0x01;
			k++;


		}
		j++;
	}

	Value_name_length_with_nametypefields = k;//with name type and length fields
	Value_hex_name_size = Value_name_length_with_nametypefields - 4; //without name type and length fields
	Value_name_with_nametypefields[k] = '\0';
	Value_name_with_nametypefields[2] = 0x00; //name filed size 1
	Value_name_with_nametypefields[3] = 0x01 * (MS_hex_name_size); //without name and fields


#ifdef LOG_CHECK
	printf("Value_hex_name_size= %d\n", Value_hex_name_size);

	for(int i=0; i<Value_name_length_with_nametypefields; i++)
		printf("Value_hex_name 0x%x\n", Value_name_with_nametypefields[i]);
#endif

	int Value_name_length_with_typefields=Value_name_length_with_nametypefields+4;
	uint8_t Value_name_with_typefields[Value_name_length_with_typefields];




	//make Reg add value type fields
	Value_name_with_typefields[0] = 0x01;
	Value_name_with_typefields[1] = 0x18;
	Value_name_with_typefields[2] = 0x00;
	Value_name_with_typefields[3] = Value_name_length_with_nametypefields;


	for(int i=0; i<Value_name_length_with_nametypefields; i++)
	{
		Value_name_with_typefields[i+4] = Value_name_with_nametypefields[i];
	}
#ifdef LOG_CHECK
	printf("Value_name_length_with_nametypefields= %d\n", Value_name_length_with_nametypefields);

	for(int i=0;i<Value_name_length_with_typefields;i++)
		printf("Value_name_with_typefields 0x%x\n", Value_name_with_typefields[i]);
#endif


	//create Packet header and interest header. it is fixed size.
	uint8_t interestReg_PH_IH[12];
	for(int i=0; i < 12; i++)
	{
		interestReg_PH_IH[i]=interestMessage->messageHead[i];
	}




	//make Reg packet
	int interestReg_length = 12     //header and interest type fileds length
		+ MS_name_size_with_typefields
		+ Key_name_length_with_typefields
		+ Value_name_length_with_typefields;
	uint8_t interestReg[interestReg_length];

	int PH_IH_end_point = 0;
	int MS_name_end_point = 0;
	int Key_name_end_point = 0;
	int Value_name_end_point = 0;

	for(int i=0; i<12;i++)
	{
		interestReg[i] = interestReg_PH_IH[i];
		PH_IH_end_point++;
	}

	for(int i=0; i<MS_name_size_with_typefields;i++)
	{
		//              interestReg[i + PH_IH_end_point]=MS_name[i];
		interestReg[i + PH_IH_end_point]=MS_hex_name[i];
		MS_name_end_point++;
	}
	MS_name_end_point = MS_name_end_point + PH_IH_end_point;


	for(int i=0; i<Key_name_length_with_typefields;i++)
	{
		interestReg[i + MS_name_end_point] = Key_name_with_typefields[i];
		Key_name_end_point++;
	}
	Key_name_end_point =Key_name_end_point + MS_name_end_point;


	for(int i=0; i<Value_name_length_with_typefields;i++)
	{
		interestReg[i + Key_name_end_point]=Value_name_with_typefields[i];
		Value_name_end_point++;
	}
	Value_name_end_point = Value_name_end_point + Key_name_end_point;

	//change packet and interest lengh value
	interestReg[3] = Value_name_end_point;
	interestReg[11] = MS_name_size_with_typefields
		+ Key_name_length_with_typefields
		+ Value_name_length_with_typefields;

#ifdef LOG_CHECK
	printf("interestReg_length= %d\n", interestReg_length);
	printf("Value_name_end_point= %d\n", Value_name_end_point);
	for(int i=0; i<interestReg_length; i++)
	{

		printf("interestReg %x\n", interestReg[i]);
	}

#endif


#if 1
	//by wschoi
	PARCEventBuffer *buff = parcEventBuffer_Create();
	parcEventBuffer_Append(buff, interestReg, interestReg_length);
	PARCLogReporter *reporter = parcLogReporterTextStdout_Create();
	MetisLogger *logger = metisLogger_Create(reporter, parcClock_Wallclock());
	parcLogReporter_Release(&reporter);
	MetisMessage *message = metisMessage_CreateFromBuffer(1, 2, buff, logger);
	metisLogger_Release(&logger);
	message->ingressConnectionId=interestMessage->ingressConnectionId;


	//make pit_interest
	int pit_interest_length = 12 + Key_name_length + 4;
	uint8_t pit_interest[pit_interest_length];

	//make PH and IH
	for(int i=0; i<12;i++)
	{
		pit_interest[i] = interestReg_PH_IH[i];
	}
	//make name fields
	pit_interest[12] = 0x00;
	pit_interest[13] = 0x00;
	pit_interest[14] = 0x00;
	pit_interest[15] = Key_name_length;

	for(int i=16; i<pit_interest_length;i++)
	{
		pit_interest[i] = Key_name[i - 16];
	}


	//change packet and interest lengh value
	pit_interest[3] = pit_interest_length;
	pit_interest[11] = Key_name_length + 4;

#ifdef LOG_CHECK
	for(int i=0; i<pit_interest_length;i++)
	{
		printf("pit_interest[%d]: %x\n", i, pit_interest[i]);
	}


#endif

	PARCEventBuffer *buff_pit_interest = parcEventBuffer_Create();
	parcEventBuffer_Append(buff_pit_interest, pit_interest, pit_interest_length);
	PARCLogReporter *reporter_pit_interest = parcLogReporterTextStdout_Create();
	MetisLogger *logger_pit_interest = metisLogger_Create(reporter_pit_interest, parcClock_Wallclock());
	parcLogReporter_Release(&reporter_pit_interest);
	MetisMessage *message_pit_interest = metisMessage_CreateFromBuffer(1, 2, buff_pit_interest, logger_pit_interest);
	metisLogger_Release(&logger_pit_interest);
	message_pit_interest->ingressConnectionId=interestMessage->ingressConnectionId;


	// (1) Try to aggregate in PIT
	if (metisMessageProcessor_AggregateInterestInPit(processor, message_pit_interest)) {
		// done
		return;
	}

	// At this point, we just created a PIT entry.  If we don't forward the interest, we need
	// to remove the PIT entry.

	// (2) Try to satisfy from content store
	if (_satisfyFromContentStore(processor, interestMessage)) {
		// done
		// If we found a content object in the CS, metisMessageProcess_SatisfyFromContentStore already
		// cleared the PIT state
		return;
	}

	// (3) Try to forward it
	if (metisMessageProcessor_ForwardViaFib_Reg(processor, message_pit_interest, message)) {
		// done
		return;
	}

	// Remove the PIT entry?
	processor->stats.countDroppedNoRoute++;



	if (metisLogger_IsLoggable(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug)) {
		metisLogger_Log(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug, __func__,
				"Message %p did not match FIB, no route (count %u)",
				(void *) interestMessage,
				processor->stats.countDroppedNoRoute);
	}
	metisMessageProcessor_Drop(processor, interestMessage);
#endif

}




//by wschoi
//del

	static void
metisMessageProcessor_ReceiveInterestRegistration_del(MetisMessageProcessor *processor, MetisMessage *interestMessage)
{
	processor->stats.countInterestsReceived++;


#ifdef LOG_CHECK
	printf("metisMessageProcessor_ReceiveInterestRegistration_del()\n");
#endif

/*****Warning****
* This file_path should be changed by your own path installing 'sb-forwarder' 
* end of path */
	//fetch MS name from MSname.txt
	FILE *fp_MSname;
	fp_MSname = fopen("/home/nrs/CICN/sb-forwarder/metis/config/MSname.txt","r");

	char MSname[256];
	fscanf(fp_MSname, "%s", MSname);

	int MSname_size=0;

	while(MSname[MSname_size] != '\0')
	{
		MSname_size++;
	}
#ifdef LOG_CHECK
	printf("fetch MS name from MSname.txt: %s, size: %d\n", MSname, MSname_size);

#endif


	fclose(fp_MSname);


	//make MS1 name fields with Name type field


	int slash_check = 0;

	int j = 0;
	int k = 4;
	char MS_hex_name[128];
	int MS_hex_name_size = 0;
	int MS_name_size_with_typefields = 0;

	MS_hex_name[0] = 0x00; //name type 1
	MS_hex_name[1] = 0x00; //name type 2

	for(int i=0; i<(MSname_size);i++)
	{
		if(MSname[j]=='/')
		{
			MS_hex_name[k] = 0x00; // slash
			k++;

			MS_hex_name[k] = 0x01;
			k++;

			MS_hex_name[k] = 0x00;
			k++;

			MS_hex_name[k] = 0x00; //size
			slash_check=k;
			k++;
		}
		else
		{
			MS_hex_name[k] = MSname[j];
			MS_hex_name[slash_check]= MS_hex_name[slash_check]+0x01;
			k++;

		}
		j++;
	}

	MS_name_size_with_typefields=k;//with name type and length fields
	MS_hex_name_size=MS_name_size_with_typefields-4; //without name type and length fields
	MS_hex_name[k] = '\0';
	MS_hex_name[2] = 0x00; //name filed size 1
	MS_hex_name[3] = 0x01 * (MS_hex_name_size); //without name and fields





#ifdef LOG_CHECK
	printf("MS_hex_name_size= %d\n", MS_hex_name_size);

	for(int i=0;i<MS_hex_name_size;i++)
		printf("MS_hex_name 0x%x\n", MS_hex_name[i]);
#endif


	char MS_hex_name_without_type[MS_hex_name_size];
	for(int i=0; i<MS_hex_name_size;i++)
	{
		MS_hex_name_without_type[i]=MS_hex_name[i+4];
	}
	int compare_size = 0;
	if(MS_hex_name_size>interestMessage->name->memoryLength)
	{
		compare_size=interestMessage->name->memoryLength;
	}
	else
	{
		compare_size=MS_hex_name_size;
	}
	int compare_size_result = 0;
	for(int i = 0; i < compare_size; i++)
	{
		if(MS_hex_name_without_type[i]==interestMessage->name->memory[i])
		{
			compare_size_result++;

		}
	}

	if(compare_size_result==compare_size)
	{
#ifdef LOG_CHECK
		printf("MS_hex_name_without_type == interestMessage->name->memory \n");
#endif
		metisMessageProcessor_ReceiveInterestRegistrationMS_del(processor, interestMessage);
		return;
	}


#ifdef LOG_CHECK
	int message_length = parcEventBuffer_GetLength(interestMessage->messageBytes);
	for(int i= 0 ; i<message_length; i++)
	{
		printf("interestMessage->memory[%d] = %x \n", i, interestMessage->messageHead[i]) ;
	}
#endif



	//make key name

	int Key_name_length = interestMessage->Reg_delname->memoryLength;
	uint8_t *Key_name = interestMessage->Reg_delname->memory;

	int Key_name_length_with_typefields = Key_name_length + 8; //key type and name type
	uint8_t Key_name_with_typefields[Key_name_length_with_typefields];

	//make Reg del key type fields
	Key_name_with_typefields[0] = 0x01;
	Key_name_with_typefields[1] = 0x20;
	Key_name_with_typefields[2] = 0x00;
	Key_name_with_typefields[3] = Key_name_length + 4;

	//make Reg key name type fields
	Key_name_with_typefields[4] = 0x00;
	Key_name_with_typefields[5] = 0x00;
	Key_name_with_typefields[6] = 0x00;
	Key_name_with_typefields[7] = Key_name_length;

	for(int i=0; i<Key_name_length; i++)
	{
		Key_name_with_typefields[i + 8] = Key_name[i];
	}

#ifdef LOG_CHECK
	printf("metisMessageProcessor_ReceiveInterestRegistration_del(), Key_name_with_typefields\n");

	for(int i=0; i<Key_name_length_with_typefields; i++)
	{
		printf("key_name_with_typefields = %x\n", Key_name_with_typefields[i]);
	}

#endif

/*****Warning****
* This file_path should be changed by your own path installing 'sb-forwarder' 
* end of path */
	//fetch Value name from ValueName.txt
	FILE *fp_ValueName;
	fp_ValueName = fopen("/home/nrs/CICN/ccnxReg-Client/config/ValueName.txt","r");

	char ValueName[256];
	fscanf(fp_ValueName, "%s", ValueName);

	int ValueName_size=0;

	while(ValueName[ValueName_size] != '\0')
	{
		ValueName_size++;
	}

#ifdef LOG_CHECK
	printf("fetch Value name from ValueName.txt: %s, size: %d\n", ValueName, ValueName_size);

#endif
	fclose(fp_ValueName);

	//make value hex name

	//reset check parameter
	slash_check = 0;
	j = 0;
	k = 4;
	char Value_name_with_nametypefields[128];
	int Value_name_length_with_nametypefields = 0;
	int Value_hex_name_size = 0;
	Value_name_with_nametypefields[0] = 0x00; //name type 1
	Value_name_with_nametypefields[1] = 0x00; //name type 2

	for(int i=0; i<(ValueName_size);i++)
	{
		if(ValueName[j] == '/')
		{
			Value_name_with_nametypefields[k] = 0x00; // slash
			k++;

			Value_name_with_nametypefields[k] = 0x01;
			k++;

			Value_name_with_nametypefields[k] = 0x00;
			k++;

			Value_name_with_nametypefields[k] = 0x00; //size
			slash_check=k;
			k++;
		}
		else
		{

			Value_name_with_nametypefields[k] = ValueName[j];
			Value_name_with_nametypefields[slash_check] = Value_name_with_nametypefields[slash_check] + 0x01;
			k++;

		}
		j++;
	}

	Value_name_length_with_nametypefields=k;//with name type and length fields
	Value_hex_name_size=Value_name_length_with_nametypefields - 4; //without name type and length fields
	Value_name_with_nametypefields[k] = '\0';
	Value_name_with_nametypefields[2] = 0x00; //name filed size 1
	Value_name_with_nametypefields[3] = 0x01 * (MS_hex_name_size); //without name and fields


#ifdef LOG_CHECK
	printf("Value_hex_name_size= %d\n", Value_hex_name_size);

	for(int i=0;i<Value_name_length_with_nametypefields;i++)
		printf("Value_hex_name 0x%x\n", Value_name_with_nametypefields[i]);
#endif
	int Value_name_length_with_typefields=Value_name_length_with_nametypefields+4;
	uint8_t Value_name_with_typefields[Value_name_length_with_typefields];

	//make Reg value type fields
	Value_name_with_typefields[0] = 0x01;
	Value_name_with_typefields[1] = 0x21;
	Value_name_with_typefields[2] = 0x00;
	Value_name_with_typefields[3] = Value_name_length_with_nametypefields;


	for(int i=0; i<Value_name_length_with_nametypefields; i++)
	{
		Value_name_with_typefields[i+4] = Value_name_with_nametypefields[i];
	}
#ifdef LOG_CHECK
	printf("Value_name_length_with_nametypefields= %d\n", Value_name_length_with_nametypefields);

	for(int i=0;i<Value_name_length_with_typefields;i++)
		printf("Value_name_with_typefields 0x%x\n", Value_name_with_typefields[i]);
#endif


	//create Packet header and interest header. it is fixed size.
	uint8_t interestReg_PH_IH[12];
	for(int i=0; i < 12; i++)
	{
		interestReg_PH_IH[i] = interestMessage->messageHead[i];
	}

	//make Reg packet
	int interestReg_length = 12 //header and interest type fileds length
		+ MS_name_size_with_typefields
		+ Key_name_length_with_typefields
		+ Value_name_length_with_typefields;
	uint8_t interestReg[interestReg_length];

	int PH_IH_end_point = 0;
	int MS_name_end_point = 0;
	int Key_name_end_point = 0;
	int Value_name_end_point = 0;

	for(int i=0; i<12;i++)
	{
		interestReg[i] = interestReg_PH_IH[i];
		PH_IH_end_point++;
	}

	for(int i=0; i<MS_name_size_with_typefields;i++)
	{
		interestReg[i+PH_IH_end_point] = MS_hex_name[i];
		MS_name_end_point++;
	}
	MS_name_end_point = MS_name_end_point + PH_IH_end_point;
	for(int i=0; i<Key_name_length_with_typefields;i++)
	{
		interestReg[i+MS_name_end_point] = Key_name_with_typefields[i];
		Key_name_end_point++;
	}
	Key_name_end_point = Key_name_end_point + MS_name_end_point;


	for(int i=0; i<Value_name_length_with_typefields; i++)
	{
		interestReg[i+Key_name_end_point] = Value_name_with_typefields[i];
		Value_name_end_point++;
	}
	Value_name_end_point = Value_name_end_point + Key_name_end_point;

	//change packet and interest lengh value
	interestReg[3] = Value_name_end_point;
	interestReg[11] = MS_name_size_with_typefields
		+ Key_name_length_with_typefields
		+ Value_name_length_with_typefields;

#ifdef LOG_CHECK
	printf("interestReg_length= %d\n", interestReg_length);
	printf("Value_name_end_point= %d\n", Value_name_end_point);

	for(int i=0; i<interestReg_length; i++)
	{

		printf("interestReg %x\n", interestReg[i]);
	}

#endif
#if 1
	//by wschoi
	PARCEventBuffer *buff = parcEventBuffer_Create();
	parcEventBuffer_Append(buff, interestReg, interestReg_length);
	PARCLogReporter *reporter = parcLogReporterTextStdout_Create();
	MetisLogger *logger = metisLogger_Create(reporter, parcClock_Wallclock());
	parcLogReporter_Release(&reporter);
	MetisMessage *message = metisMessage_CreateFromBuffer(1, 2, buff, logger);
	metisLogger_Release(&logger);
	message->ingressConnectionId=interestMessage->ingressConnectionId;


	//make pit_interest
	int pit_interest_length = 12 + Key_name_length + 4;
	uint8_t pit_interest[pit_interest_length];

	//make PH and IH
	for(int i=0; i<12;i++)
	{
		pit_interest[i] = interestReg_PH_IH[i];
	}

	//make name fields
	pit_interest[12] = 0x00;
	pit_interest[13] = 0x00;
	pit_interest[14] = 0x00;
	pit_interest[15] = Key_name_length;

	for(int i=16; i < pit_interest_length;i++)
	{
		pit_interest[i] = Key_name[i-16];
	}

	//change packet and interest lengh value
	pit_interest[3] = pit_interest_length;
	pit_interest[11] = Key_name_length+4;


#ifdef LOG_CHECK
	for(int i=0; i<pit_interest_length;i++)
	{
		printf("pit_interest[%d]: %x\n", i, pit_interest[i]);
	}


#endif

	PARCEventBuffer *buff_pit_interest = parcEventBuffer_Create();
	parcEventBuffer_Append(buff_pit_interest, pit_interest, pit_interest_length);
	PARCLogReporter *reporter_pit_interest = parcLogReporterTextStdout_Create();
	MetisLogger *logger_pit_interest = metisLogger_Create(reporter_pit_interest, parcClock_Wallclock());
	parcLogReporter_Release(&reporter_pit_interest);
	MetisMessage *message_pit_interest = metisMessage_CreateFromBuffer(1, 2, buff_pit_interest, logger_pit_interest);
	metisLogger_Release(&logger_pit_interest);
	message_pit_interest->ingressConnectionId=interestMessage->ingressConnectionId;

	// (1) Try to aggregate in PIT
	if (metisMessageProcessor_AggregateInterestInPit(processor, message_pit_interest)) {
		// done
		return;
	}

	// At this point, we just created a PIT entry.  If we don't forward the interest, we need
	// to remove the PIT entry.
	// (2) Try to satisfy from content store
	if (_satisfyFromContentStore(processor, interestMessage)) {
		// done
		// If we found a content object in the CS, metisMessageProcess_SatisfyFromContentStore already
		// cleared the PIT state
		return;
	}

	// (3) Try to forward it
	if (metisMessageProcessor_ForwardViaFib_Reg(processor, message_pit_interest, message)) {
		// done
		return;
	}

	// Remove the PIT entry?
	processor->stats.countDroppedNoRoute++;

	if (metisLogger_IsLoggable(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug)) {
		metisLogger_Log(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug, __func__,
				"Message %p did not match FIB, no route (count %u)",
				(void *) interestMessage,
				processor->stats.countDroppedNoRoute);
	}
	metisMessageProcessor_Drop(processor, interestMessage);
#endif

}


//dereg
	static void
metisMessageProcessor_ReceiveInterestRegistration_dereg(MetisMessageProcessor *processor, MetisMessage *interestMessage)
{
	processor->stats.countInterestsReceived++;


#ifdef LOG_CHECK
	printf("metisMessageProcessor_ReceiveInterestRegistration_dereg()\n");
#endif

/*****Warning****
* This file_path should be changed by your own path installing 'sb-forwarder' 
* end of path */
	//fetch MS name from MSname.txt
	FILE *fp_MSname;
	fp_MSname = fopen("/home/nrs/CICN/sb-forwarder/metis/config/MSname.txt","r");

	char MSname[256];
	fscanf(fp_MSname, "%s", MSname);

	int MSname_size=0;

	while(MSname[MSname_size] != '\0')
	{
		MSname_size++;
	}
#ifdef LOG_CHECK
	printf("fetch MS name from MSname.txt: %s, size: %d\n", MSname, MSname_size);

#endif
	fclose(fp_MSname);

	//make MS1 name fields with Name type field

#if 1


	int slash_check=0;

	int j = 0;
	int k = 4;
	char MS_hex_name[128];
	int MS_hex_name_size = 0;
	int MS_name_size_with_typefields = 0;

	MS_hex_name[0] = 0x00; //name type 1
	MS_hex_name[1] = 0x00; //name type 2

	for(int i=0; i<(MSname_size);i++)
	{
		if(MSname[j] == '/')
		{
			MS_hex_name[k] = 0x00; // slash
			k++;

			MS_hex_name[k] = 0x01;
			k++;

			MS_hex_name[k] = 0x00;
			k++;

			MS_hex_name[k] = 0x00; //size
			slash_check = k;
			k++;
		}
		else
		{

			MS_hex_name[k] = MSname[j];
			MS_hex_name[slash_check]= MS_hex_name[slash_check] + 0x01;
			k++;

		}
		j++;
	}

	MS_name_size_with_typefields = k;//with name type and length fields
	MS_hex_name_size = MS_name_size_with_typefields - 4; //without name type and length fields
	MS_hex_name[k] = '\0';
	MS_hex_name[2] = 0x00; //name filed size 1
	MS_hex_name[3] = 0x01 * (MS_hex_name_size); //without name and fields





#ifdef LOG_CHECK
	printf("MS_hex_name_size= %d\n", MS_hex_name_size);

	for(int i=0;i<MS_hex_name_size;i++)
		printf("MS_hex_name 0x%x\n", MS_hex_name[i]);
#endif


#endif

	char MS_hex_name_without_type[MS_hex_name_size];
	for(int i=0; i<MS_hex_name_size;i++)
	{
		MS_hex_name_without_type[i]=MS_hex_name[i+4];
	}
	int compare_size = 0;
	if(MS_hex_name_size>interestMessage->name->memoryLength)
	{
		compare_size=interestMessage->name->memoryLength;
	}
	else
	{
		compare_size=MS_hex_name_size;
	}
	int compare_size_result = 0;
	for(int i = 0; i < compare_size; i++)
	{
		if(MS_hex_name_without_type[i]==interestMessage->name->memory[i])
		{
			compare_size_result++;

		}
	}

	if(compare_size_result==compare_size)
	{
#ifdef LOG_CHECK
		printf("MS_hex_name_without_type == interestMessage->name->memory \n");
#endif
		metisMessageProcessor_ReceiveInterestRegistrationMS_dereg(processor, interestMessage);
		return;
	}

	#ifdef LOG_CHECK
		int message_length = parcEventBuffer_GetLength(interestMessage->messageBytes);
	for(int i= 0 ; i<message_length; i++)
	{
		printf("interestMessage->memory[%d] = %x \n", i, interestMessage->messageHead[i]) ;
	}
#endif


	//make key name
	int Key_name_length = interestMessage->Reg_deregname->memoryLength;
	uint8_t *Key_name = interestMessage->Reg_deregname->memory;

	int Key_name_length_with_typefields = Key_name_length + 8; //key type and name type
	uint8_t Key_name_with_typefields[Key_name_length_with_typefields];

	//make Reg key type fields
	Key_name_with_typefields[0] = 0x01;
	Key_name_with_typefields[1] = 0x23;
	Key_name_with_typefields[2] = 0x00;
	Key_name_with_typefields[3] = Key_name_length + 4;

	//make Reg key name type fields
	Key_name_with_typefields[4] = 0x00;
	Key_name_with_typefields[5] = 0x00;
	Key_name_with_typefields[6] = 0x00;
	Key_name_with_typefields[7] = Key_name_length;

	for(int i=0; i<Key_name_length; i++)
	{
		Key_name_with_typefields[i + 8] = Key_name[i];
	}


#ifdef LOG_CHECK
	printf("metisMessageProcessor_ReceiveInterestRegistration_dereg(), Key_name_with_typefields\n");

	for(int i=0; i < Key_name_length_with_typefields; i++)
	{
		printf("key_name_with_typefields = %x\n", Key_name_with_typefields[i]);
	}

#endif


	//without value fields
	//create Packet header and interest header. it is fixed size.
	uint8_t interestReg_PH_IH[12];
	for(int i=0; i < 12; i++)
	{
		interestReg_PH_IH[i] = interestMessage->messageHead[i];
	}

	//make Reg packet
	int interestReg_length = 12 //header and interest type fileds length
		+ MS_name_size_with_typefields
		+ Key_name_length_with_typefields;
	uint8_t interestReg[interestReg_length];

	int PH_IH_end_point = 0;
	int MS_name_end_point = 0;
	int Key_name_end_point = 0;

	for(int i=0; i<12;i++)
	{
		interestReg[i] = interestReg_PH_IH[i];
		PH_IH_end_point++;
	}
	for(int i=0; i<MS_name_size_with_typefields;i++)
	{
		interestReg[i+PH_IH_end_point] = MS_hex_name[i];
		MS_name_end_point++;
	}
	MS_name_end_point = MS_name_end_point + PH_IH_end_point;

	for(int i=0; i<Key_name_length_with_typefields;i++)
	{
		interestReg[i + MS_name_end_point] = Key_name_with_typefields[i];
		Key_name_end_point++;
	}
	Key_name_end_point = Key_name_end_point + MS_name_end_point;

	//change packet and interest lengh value
	interestReg[3] = Key_name_end_point;
	interestReg[11] = MS_name_size_with_typefields
		+ Key_name_length_with_typefields;

#ifdef LOG_CHECK
	printf("interestReg_length= %d\n", interestReg_length);
	printf("Key_name_end_point= %d\n", Key_name_end_point);
	for(int i=0; i<interestReg_length; i++)
	{

		printf("interestReg %x\n", interestReg[i]);
	}

#endif

#if 1
	//by wschoi
	PARCEventBuffer *buff = parcEventBuffer_Create();
	parcEventBuffer_Append(buff, interestReg, interestReg_length);
	PARCLogReporter *reporter = parcLogReporterTextStdout_Create();
	MetisLogger *logger = metisLogger_Create(reporter, parcClock_Wallclock());
	parcLogReporter_Release(&reporter);
	MetisMessage *message = metisMessage_CreateFromBuffer(1, 2, buff, logger);
	metisLogger_Release(&logger);
	message->ingressConnectionId=interestMessage->ingressConnectionId;


	//make pit_interest
	int pit_interest_length= 12 + Key_name_length + 4;
	uint8_t pit_interest[pit_interest_length];
	//make PH and IH
	for(int i = 0; i < 12;i++)
	{
		pit_interest[i] = interestReg_PH_IH[i];
	}
	//make name fields
	pit_interest[12] = 0x00;
	pit_interest[13] = 0x00;
	pit_interest[14] = 0x00;
	pit_interest[15] = Key_name_length;

	for(int i = 16;  i <pit_interest_length;i++)
	{
		pit_interest[i]=Key_name[i - 16];
	}
	//change packet and interest lengh value
	pit_interest[3] = pit_interest_length;
	pit_interest[11] = Key_name_length+4;

#ifdef LOG_CHECK
	for(int i = 0; i < pit_interest_length;i++)
	{
		printf("pit_interest[%d]: %x\n", i, pit_interest[i]);
	}


#endif

	PARCEventBuffer *buff_pit_interest = parcEventBuffer_Create();
	parcEventBuffer_Append(buff_pit_interest, pit_interest, pit_interest_length);
	PARCLogReporter *reporter_pit_interest = parcLogReporterTextStdout_Create();
	MetisLogger *logger_pit_interest = metisLogger_Create(reporter_pit_interest, parcClock_Wallclock());
	parcLogReporter_Release(&reporter_pit_interest);
	MetisMessage *message_pit_interest = metisMessage_CreateFromBuffer(1, 2, buff_pit_interest, logger_pit_interest);
	metisLogger_Release(&logger_pit_interest);
	message_pit_interest->ingressConnectionId=interestMessage->ingressConnectionId;




	// (1) Try to aggregate in PIT
	if (metisMessageProcessor_AggregateInterestInPit(processor, message_pit_interest)) {
		// done
		return;
	}

	// At this point, we just created a PIT entry.  If we don't forward the interest, we need
	// to remove the PIT entry.

	// (2) Try to satisfy from content store
	if (_satisfyFromContentStore(processor, interestMessage)) {
		// done
		// If we found a content object in the CS, metisMessageProcess_SatisfyFromContentStore already
		// cleared the PIT state
		return;
	}

	// (3) Try to forward it
	if (metisMessageProcessor_ForwardViaFib_Reg(processor, message_pit_interest, message)) {
		// done
		return;
	}

	// Remove the PIT entry?
	processor->stats.countDroppedNoRoute++;

	if (metisLogger_IsLoggable(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug)) {
		metisLogger_Log(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug, __func__,
				"Message %p did not match FIB, no route (count %u)",
				(void *) interestMessage,
				processor->stats.countDroppedNoRoute);
	}
	metisMessageProcessor_Drop(processor, interestMessage);
#endif

}






//by wschoi
	static bool
metisMessageProcessor_SendGetname(MetisMessageProcessor *processor, MetisMessage *interestMessage)
{

	//by wschoi
#ifdef LOG_CHECK
	printf("metisMessageProcessor_SendGetname()\n\n");

	for(int i=0; i<interestMessage->name->memoryLength; i++)
	{
		printf("##MSname[%d]= %x, %c, size=%d\n", i, interestMessage->name->memory[i], interestMessage->name->memory[i],interestMessage->name->memoryLength);
	}

#endif
	//except local/dcr/anchor
	if(interestMessage->name->memory[3] == 5 && interestMessage->name->memory[4] == 'l' && interestMessage->name->memory[5] == 'o' && interestMessage->name->memory[6] == 'c' && interestMessage->name->memory[7] == 'a' && interestMessage->name->memory[8] == 'l')
	{
#ifdef LOG_CHECK
		printf("metisMessageProcessor_SendGetname-return()\n\n");
#endif
		return;

	}

	// packet modification test
	//parse an Interest
	//header, T_INTEREST, InterestLength, T_NAME, NameLength, Name, PAYLOAD_TYPE, PAYLOAD_Length, PAYLOAD

	//make a getname message
	//header, T_INTEREST, new_InterestLength, MS1_T_NAME, MS1_NameLength, MS1_Name, T_GETNAME, GetnameLength, new_Name

	PARCEventBuffer *buff = parcEventBuffer_Create();



	//################## make get name message ####################

	int interestMessage_length = parcEventBuffer_GetLength(interestMessage->messageBytes);

	uint8_t interest_from_consumer[interestMessage_length];

	for(int i=0; i<interestMessage_length;i++)
	{
		interest_from_consumer[i]=interestMessage->messageHead[i];

	}

#ifdef LOG_CHECk
	printf("Copy interestMessage to interest_from_consumer\n\n");
	for(int i=0; i<interestMessage_length;i++)
	{
		printf("%x ", interest_from_consumer[i]);
	}
	printf("\n\n");
#endif

	// 31 is additional field length(MS name type, name field, getname type)
	int getname_message_num=interestMessage_length+32;

	uint8_t getname_message[getname_message_num];

	//packet header
	for(int i=0; i<3;i++)
	{
		getname_message[i]=interest_from_consumer[i];
	}

	//packet header size
	getname_message[3]=(uint8_t)getname_message_num;

	for(int i=4; i<8;i++)
	{
		getname_message[i]=interest_from_consumer[i];
	}

	//ccnx Message header
	for(int i=8; i<11;i++)
	{
		getname_message[i]=interest_from_consumer[i];
	}


	//ccnx Message size, original size + (Getname Type field + MS1 name field) size
	getname_message[11]=(uint8_t)(interest_from_consumer[11]+32);

/*****Warning****
* This file_path should be changed by your own path installing 'sb-forwarder' 
* end of path */
	//fetch MS name from MSname.txt
		FILE *fp_MSname;
	fp_MSname = fopen("/home/nrs/CICN/sb-forwarder/metis/config/MSname.txt","r");
	char MSname[256];
	fscanf(fp_MSname, "%s", MSname);

	int MSname_size=0;

	while(MSname[MSname_size] != '\0')
	{
		MSname_size++;
	}
#ifdef LOG_CHECK
	printf("fetch MS name from MSname.txt: %s, size: %d\n", MSname, MSname_size);

#endif
	    fclose(fp_MSname);


		//make MS1 name fields with Name type field

#if 1


		int slash_check = 0;

		int j = 0;
		int k = 4;
		char MS_hex_name[128];
		int MS_hex_name_size = 0;
		int MS_name_size_with_typefields = 0;

		MS_hex_name[0] = 0x00; //name type 1
		MS_hex_name[1] = 0x00; //name type 2

		for(int i=0; i<(MSname_size);i++)
		{
			if(MSname[j]=='/')
			{
				MS_hex_name[k] = 0x00; // slash
				k++;

				MS_hex_name[k] = 0x01;
				k++;

				MS_hex_name[k] = 0x00;
				k++;

				MS_hex_name[k] = 0x00; //size
				slash_check = k;
				k++;
			}

			else
			{

				MS_hex_name[k] = MSname[j];
				MS_hex_name[slash_check]= MS_hex_name[slash_check]+0x01;
				k++;

			}
			j++;
		}

		MS_name_size_with_typefields = k;//with name type and length fields
		MS_hex_name_size=MS_name_size_with_typefields - 4; //without name type and length fields
		MS_hex_name[k] = '\0';
		MS_hex_name[2] = 0x00; //name filed size 1
		MS_hex_name[3] = 0x01 * (MS_hex_name_size); //without name and fields




#if 0

	//MS1(/X/hello/1/2) name field
	uint8_t ms_namefield[]={0x00, 0x00, 0x00, 0x18,0x00, 0x01, 0x00, 0x01, 0x58, 0x00, 0x01, 0x00,0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x00, 0x01,0x00, 0x01, 0x31, 0x00, 0x01, 0x00, 0x01, 0x32};

	int ms_namefield_num=sizeof(ms_namefield);

	printf("##### ms_namefield_num: %d\n\n", ms_namefield_num);


	for(int i=0; i<ms_namefield_num; i++)
	{
		getname_message[12+i]=ms_namefield[i];


	}
#else

	int ms_namefield_num=MS_name_size_with_typefields;
#ifdef LOG_CHECK
	printf("##### ms_namefield_num: %d\n\n", ms_namefield_num);
#endif


	for(int i=0; i<ms_namefield_num; i++)
	{
		getname_message[12+i]=MS_hex_name[i];


	}
#endif



	//Getname Type
	getname_message[12+ms_namefield_num]=0x01;
	getname_message[13+ms_namefield_num]=0x11;

	//Getname field size
	getname_message[14+ms_namefield_num]=0x00;
	getname_message[15+ms_namefield_num]=(uint8_t)((interestMessage->name->memoryLength)+4);

	// name type of getname field
	getname_message[16+ms_namefield_num]=0x00;
	getname_message[17+ms_namefield_num]=0x00;
	getname_message[18+ms_namefield_num]=0x00;
	getname_message[19+ms_namefield_num]=(uint8_t)(interestMessage->name->memoryLength);


	//name field of getname
	for(int i=0; i<interestMessage->name->memoryLength; i++)
	{
		getname_message[20+ms_namefield_num+i]=interestMessage->name->memory[i];
	}
#ifdef LOG_CHECK
	printf("getname_message_num= %d, sizeof(getname_message) = %d\n\n ", getname_message_num, sizeof(getname_message));

	printf("memoryLength: %d \n\n", interestMessage->name->memoryLength);

	for(int i=0; i<interestMessage->name->memoryLength; i++)
	{
		printf("%x ",  interestMessage->name->memory[i]);
	}
	printf("\n\n");

	printf("############### getname_message ######\n\n");
	for(int i=0; i<20+ms_namefield_num+interestMessage->name->memoryLength; i++)
	{
		printf("%x ", getname_message[i]);
	}
	printf("\n\n");

#endif
	//  uint8_t metisTestDataV1_Interest_AllFields[]={0x31, 0x32};
	// name: /X/hello/1/2 getname: /com/google/d3512
	uint8_t metisTestDataV1_Interest_AllFields[]={0x01, 0x00, 0x00, 0x4a, 0xff, 0x00, 0x00, 0x08,
		0x00, 0x01, 0x00, 0x3e, 0x00, 0x00, 0x00, 0x18,
		0x00, 0x01, 0x00, 0x01, 0x58, 0x00, 0x01, 0x00,
		0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x00, 0x01,
		0x00, 0x01, 0x31, 0x00, 0x01, 0x00, 0x01, 0x32,
		0x01, 0x11, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x1a,
		0x00, 0x01, 0x00, 0x03, 0x63, 0x6f, 0x6d, 0x00,
		0x01, 0x00, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
		0x65, 0x00, 0x01, 0x00, 0x05, 0x64, 0x33, 0x35,
		0x31, 0x32,};
	//  parcEventBuffer_Append(buff, metisTestDataV1_Interest_AllFields, sizeof(metisTestDataV1_Interest_AllFields));
	parcEventBuffer_Append(buff, getname_message, sizeof(getname_message));
	PARCLogReporter *reporter = parcLogReporterTextStdout_Create();
	MetisLogger *logger = metisLogger_Create(reporter, parcClock_Wallclock());
	parcLogReporter_Release(&reporter);
	MetisMessage *message = metisMessage_CreateFromBuffer(1, 2, buff, logger);
	//  MetisMessage *message = parcMemory_AllocateAndClear(sizeof(MetisMessage));
	metisLogger_Release(&logger);




	MetisTlvName *tlvName=metisMessage_GetName(interestMessage);
#ifdef LOG_CHECK
	printf("interestMessage_length is %d\n\n", interestMessage_length);

	for(int i=0; i<interestMessage_length;i++)
	{
		printf("%x ", message->messageHead[i]);
	}
	printf("\n\n");

#endif
	//  int result = metisMessage_Append(interestMessage->messageHead, message);

#endif


	processor->stats.countInterestsReceived++;


	if (!metisMessageProcessor_CheckAndDecrementHopLimitOnIngress(processor, message)) {
		metisMessageProcessor_Drop(processor, message);
		return true;
	}

	// (1) Try to aggregate in PIT
	if (metisMessageProcessor_AggregateInterestInPit(processor, message)) {
		// done

		//by wschoi
#ifdef LOG_CHECK
		printf("metisMessageProcessor_AggregateInterestInPit()\n\n");
#endif

		return true;
	}

	// At this point, we just created a PIT entry.  If we don't forward the interest, we need
	// to remove the PIT entry.

	// (2) Try to satisfy from content store
	if (_satisfyFromContentStore(processor, message)) {
		// done
		// If we found a content object in the CS, metisMessageProcess_SatisfyFromContentStore already
		// cleared the PIT state

		//by wschoi
#ifdef LOG_CHECK
		printf("_satisfyFromContentStore()\n\n");
#endif


		return true;
	}


	//by wschoi
#if 1
	// (3) Try to forward it
	if (metisMessageProcessor_ForwardViaFib(processor, message)) {
		// done


		//by wschoi
#ifdef LOG_CHECK
		printf("metisMessageProcessor_ForwardViaFib()\n\n");
#endif

		return true;
	}



#endif

}





/**
 * @function metisMessageProcessor_ReceiveInterest
 * @abstract Receive an interest from the network
 * @discussion
 *   (0) It must have a HopLimit and pass the hoplimit checks
 *   (1) if interest in the PIT, aggregate in PIT
 *   (2) if interest in the ContentStore, reply
 *   (3) if in the FIB, forward
 *   (4) drop
 *
 * @param <#param1#>
 * @return <#return#>
 */
#if 0
	static void
metisMessageProcessor_ReceiveInterest(MetisMessageProcessor *processor, MetisMessage *interestMessage)
{
	processor->stats.countInterestsReceived++;



	//by wschoi
	printf("in metisMessageProcessor_ReceiveInterest(), hasGetname=%d\n\n", interestMessage->hasGetname);


	if (!metisMessageProcessor_CheckAndDecrementHopLimitOnIngress(processor, interestMessage)) {
		metisMessageProcessor_Drop(processor, interestMessage);
		return;
	}

	// (1) Try to aggregate in PIT
	if (metisMessageProcessor_AggregateInterestInPit(processor, interestMessage)) {
		// done
		return;
	}

	// At this point, we just created a PIT entry.  If we don't forward the interest, we need
	// to remove the PIT entry.

	// (2) Try to satisfy from content store
	if (_satisfyFromContentStore(processor, interestMessage)) {
		// done
		// If we found a content object in the CS, metisMessageProcess_SatisfyFromContentStore already
		// cleared the PIT state
		return;
	}

	// (3) Try to forward it
	if (metisMessageProcessor_ForwardViaFib(processor, interestMessage)) {
		// done
		return;
	}

	// Remove the PIT entry?
	processor->stats.countDroppedNoRoute++;

	if (metisLogger_IsLoggable(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug)) {
		metisLogger_Log(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug, __func__,
				"Message %p did not match FIB, no route (count %u)",
				(void *) interestMessage,
				processor->stats.countDroppedNoRoute);
	}
	metisMessageProcessor_Drop(processor, interestMessage);
}
#else



	static void
metisMessageProcessor_ReceiveInterest(MetisMessageProcessor *processor, MetisMessage *interestMessage)
{
	//by wschoi
#ifdef LOG_CHECk
	printf("metisMessageProcessor_ReceiveInterest()\n\n");
#endif

	// packet modification test
#if 1
#if 0
	//parse an Interest
	//header, T_INTEREST, InterestLength, T_NAME, NameLength, Name, PAYLOAD_TYPE, PAYLOAD_Length, PAYLOAD

	//make a getname message
	//header, T_INTEREST, new_InterestLength, MS1_T_NAME, MS1_NameLength, MS1_Name, T_GETNAME, GetnameLength, new_Name

	PARCEventBuffer *buff = parcEventBuffer_Create();
	//  uint8_t metisTestDataV1_Interest_AllFields[]={0x31, 0x32};

	uint8_t metisTestDataV1_Interest_AllFields[]={0x01, 0x00, 0x00, 0x4a, 0xff, 0x00, 0x00, 0x08,
		0x00, 0x01, 0x00, 0x3e, 0x00, 0x00, 0x00, 0x18,
		0x00, 0x01, 0x00, 0x01, 0x58, 0x00, 0x01, 0x00,
		0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x00, 0x01,
		0x00, 0x01, 0x31, 0x00, 0x01, 0x00, 0x01, 0x32,
		0x01, 0x11, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x1a,
		0x00, 0x01, 0x00, 0x03, 0x63, 0x6f, 0x6d, 0x00,
		0x01, 0x00, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
		0x65, 0x00, 0x01, 0x00, 0x05, 0x64, 0x33, 0x35,
		0x31, 0x32,};
	parcEventBuffer_Append(buff, metisTestDataV1_Interest_AllFields, sizeof(metisTestDataV1_Interest_AllFields));
	PARCLogReporter *reporter = parcLogReporterTextStdout_Create();
	MetisLogger *logger = metisLogger_Create(reporter, parcClock_Wallclock());
	parcLogReporter_Release(&reporter);
	MetisMessage *message = metisMessage_CreateFromBuffer(1, 2, buff, logger);
	//MetisMessage *message = parcMemory_AllocateAndClear(sizeof(MetisMessage));
	metisLogger_Release(&logger);


#if 0
	assertNotNull(message, "Got null from metisMessage_CreateFromBuffer");
	assertTrue(message->ingressConnectionId == 1, "IngressConnectionId wrong, expected %d got %u", 1, message->ingressConnectionId);
	assertTrue(message->receiveTime == 2, "receiveTime wrong, expected %u got %" PRIu64, 2, message->receiveTime);

	//metisMessage_Release(&message);

	// adapt value to new message
	message->receiveTime=interestMessage->receiveTime;

	message->ingressConnectionId= interestMessage->ingressConnectionId;
	message->messageBytes = parcEventBuffer_Create();
	message->refcount=interestMessage->refcount;
	message->logger=logger;

	int bytesRead = parcEventBuffer_ReadIntoBuffer(buff, message->messageBytes, 2);

	printf("bytesRead is %d\n\n", bytesRead);





#endif




	MetisTlvName *tlvName=metisMessage_GetName(interestMessage);

	int interestMessage_length = parcEventBuffer_GetLength(message->messageBytes);

	printf("interestMessage_length is %d\n\n", interestMessage_length);


	printf("_readMessage, message->messageHead \n\n");
	for(int i=0; i<interestMessage_length;i++)
	{
		printf("%x ", message->messageHead[i]);
	}
	printf("\n\n");


	//  int result = metisMessage_Append(interestMessage->messageHead, message);
#endif

	int interestMessage_length_after = parcEventBuffer_GetLength(interestMessage->messageBytes);
#ifdef LOG_CHECK
	printf("interestMessage_length_after is %d\n\n", interestMessage_length_after);

	printf("_readMessage, message->messageHead \n\n");
	for(int i=0; i<interestMessage_length_after;i++)
	{
		printf("%x ", interestMessage->messageHead[i]);
	}
	printf("\n\n");
#endif
#endif


	processor->stats.countInterestsReceived++;


	if (!metisMessageProcessor_CheckAndDecrementHopLimitOnIngress(processor, interestMessage)) {
		metisMessageProcessor_Drop(processor, interestMessage);
		return;
	}

	// (1) Try to aggregate in PIT
	if (metisMessageProcessor_AggregateInterestInPit(processor, interestMessage)) {
		// done

		//by wschoi
#ifdef LOG_CHECK
		printf("metisMessageProcessor_AggregateInterestInPit()\n\n");
#endif

		return;
	}

	// At this point, we just created a PIT entry.  If we don't forward the interest, we need
	// to remove the PIT entry.

	// (2) Try to satisfy from content store
	if (_satisfyFromContentStore(processor, interestMessage)) {
		// done
		// If we found a content object in the CS, metisMessageProcess_SatisfyFromContentStore already
		// cleared the PIT state

		//by wschoi
#ifdef LOG_CHECK
		printf("_satisfyFromContentStore()\n\n");
#endif


		return;
	}

	//by wschoi
#if 0
	// (3) Try to forward it
	if (metisMessageProcessor_ForwardViaFib(processor, interestMessage)) {
		// done


		//by wschoi
		printf("metisMessageProcessor_ForwardViaFib()\n\n");

		return;
	}

#else
#if 0

	printf("in metisMessageProcessor_ReceiveInterest(), refcount=%d\n", processor->rct[0].refcount);

	if(processor->rct[0].refcount>0)
	{
		printf("########\n\n");
		printf("########\n\n");
		printf("########\n\n");
		printf("########\n\n");
		printf("########\n\n");
		printf("########\n\n");
		printf("########\n\n");
		printf("########\n\n");
		printf("processor->rct[processor->rct[0].refcount].NameA_size= %d\n", processor->rct[processor->rct[0].refcount].NameA_size);
		printf("processor->rct[0].NameA_size= %d\n", processor->rct[0].NameA_size);
		printf("processor->rct[1].NameA_size= %d\n", processor->rct[1].NameA_size);
		printf("processor->rct[2].NameA_size= %d\n", processor->rct[2].NameA_size);
		printf("processor->rct[3].NameA_size= %d\n", processor->rct[3].NameA_size);
		printf("processor->rct[4].NameA_size= %d\n", processor->rct[4].NameA_size);


		for(int i=0; i<processor->rct[2].NameA_size;i++)
		{
			printf("in metisMessageProcessor_ReceiveInterest(),  processor->rct[processor->rct[0].refcount].NameA[i]=%x, refcount=%d\n", processor->rct[2].NameA[i], processor->rct[0].refcount);
		}
	}

#endif

	//fetch Resolve ON/OFF from Resolve.conf
#if 1

/*****Warning****
* This file_path should be changed by your own path installing 'sb-forwarder' 
* end of path */
	FILE *fp_rct;
	fp_rct = fopen("/home/nrs/CICN/sb-forwarder/metis/config/resolve.conf","r");

	char rct_conf[256];
	fscanf(fp_rct, "%s", rct_conf);

	int rct_conf_size=0;

	while(rct_conf[rct_conf_size] != '\0')
	{
		rct_conf_size++;
	}
#ifdef LOG_CHECK
	printf("fetch Resolve ON/OFF from Resolve.conf: %s, size: %d\n", rct_conf, rct_conf_size);
#endif

	fclose(fp_rct);

	char rct_on[] = "ON";
	//char rct_off[] = "OFF";
	int rct_conf_result = 0;


	if(!strncmp(rct_conf, rct_on, rct_conf_size))
	{
		rct_conf_result = 1;
	}
	else
	{
		rct_conf_result = 0;

	}
#endif
	//for(int i = 0; i < processor->rct[0].NameB_size; i++)
	//{
	//}


	if(rct_conf_result>0)
	{
		// (3) Try to forward it
		if (metisMessageProcessor_ForwardViaFib(processor, interestMessage)) {
			// done


			//by wschoi
#ifdef LOG_CHECK
			printf("metisMessageProcessor_ForwardViaFib()\n\n");
#endif

			return;
		}
		else if(metisMessageProcessor_RctLookup(processor, interestMessage))
		{
#ifdef LOG_CHECK
			printf("metisMessageProcessor_RctLookup() is success\n\n");
#endif
			return;

		}
		else if(metisMessageProcessor_SendGetname(processor, interestMessage))
		{
#ifdef LOG_CHECK
			printf("metisMessageProcessor_SendGetname() is success\n\n");
#endif
			return;

		}
	}
	else
	{
		// (3) Try to forward it
		if (metisMessageProcessor_ForwardViaFib(processor, interestMessage)) {
			// done


			//by wschoi
#ifdef LOG_CHECk
			printf("metisMessageProcessor_ForwardViaFib()\n\n");
#endif

			return;
		}
		else if(metisMessageProcessor_SendGetname(processor, interestMessage))
		{
#ifdef LOG_CHECK
			printf("metisMessageProcessor_SendGetname() is success\n\n");
#endif
			return;

		}
	}


#endif
	// Remove the PIT entry?
	processor->stats.countDroppedNoRoute++;

	if (metisLogger_IsLoggable(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug)) {
		metisLogger_Log(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug, __func__,
				"Message %p did not match FIB, no route (count %u)",
				(void *) interestMessage,
				processor->stats.countDroppedNoRoute);
	}


	//by wschoi
#ifdef LOG_CHECK
	printf("metisMessageProcessor_Drop()\n\n");
#endif

	metisMessageProcessor_Drop(processor, interestMessage);
}

#endif



//by wschoi
	static void
metisMessageProcessor_ReceiveContentObjectPayloadGetname(MetisMessageProcessor *processor, MetisMessage *message)
{
//metisMessageProcessor_ReceiveContentObject(processor, message);
//return;

#if 0
	if (!metisMessageProcessor_ForwardViaFib(processor, message))
	{

		printf("******metisMessageProcessor_ForwardViaFib fail\n");
		printf("metisMessageProcessor_ReceiveContentObjectPayloadGetname()\n\n");

		metisMessageProcessor_ReceiveContentObject(processor, message);
		return;

	}
	else
	{
		printf("******metisMessageProcessor_ForwardViaFib success\n");
		printf("proceed metisMessageProcessor_ReceiveContentObjectPayloadGetname()\n");
	}
#endif

#if 0

	MetisNumberSet *ingressSetUnion_consumer_cr_check = metisPIT_SatisfyInterest(processor->pit, message);

	if (metisNumberSet_Length(ingressSetUnion_consumer_cr_check) == 0) {
		// (1) If it does not match anything in the PIT, drop it

printf("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");
printf("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");
printf("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");
printf("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");
printf("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");
printf("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");
printf("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");
		metisMessageProcessor_Drop(processor, message);
	//					metisMessageProcessor_ReceiveContentObject(processor, message);
	}
	else
	{

printf("*********************************************\n");
printf("*********************************************\n");
printf("*********************************************\n");
printf("*********************************************\n");
printf("*********************************************\n");
printf("*********************************************\n");
printf("*********************************************\n");
// (3) Try to forward it
 if (metisMessageProcessor_ForwardViaFib(processor, message)) 
 {
	 printf("******metisMessageProcessor_ForwardViaFib success\n");
//	 printf("metisMessageProcessor_ForwardViaFib()\n\n");
//	 return true;
 }
 else
 {

	 printf("******metisMessageProcessor_ForwardViaFib fail\n");
metisMessageProcessor_ReceiveContentObject(processor, message);
return;

 }

//unsigned forwardedCopies_result = metisMessageProcessor_ForwardToNexthops(processor, message, ingressSetUnion_consumer_cr_check);

//printf("**********forwardedCopies_result: %d***********************************\n", forwardedCopies_result);

	}
#endif


#if 1
	//for RCT registration
	unsigned newNameA_size=0;
	unsigned newNameB_size=0;
#endif


#if 1

	//################## Change packet fields to Name B/Name A from Name A/Name B for CO-Get####################

	int message_length = parcEventBuffer_GetLength(message->messageBytes);

	uint8_t PayloadGetname_Get_from_MS[message_length];

	for(int i=0; i<message_length;i++)
	{
		PayloadGetname_Get_from_MS[i]=message->messageHead[i];

	}
#ifdef LOG_CHECK
	printf("Copy message to PayloadGetname_Get_from_MS\n\n");

	for(int i=0; i<message_length;i++)
	{
		printf("%x ", PayloadGetname_Get_from_MS[i]);
	}

	printf("\n\n");
#endif
	//create Packet header and CO header. it is fixed size.
	uint8_t CO_Get_PH_CH[12];
	int PH_CH_end_point=0;
	for(int i=0; i < PayloadGetname_Get_from_MS[7]+4; i++)
	{
		CO_Get_PH_CH[i]=PayloadGetname_Get_from_MS[i];
		PH_CH_end_point++;
#ifdef LOG_CHECK
		printf("CO_Get_PH_CH_%d: %x \n", i, CO_Get_PH_CH[i]);
#endif
	}

	//create NameA name with name type fields. NameA name's size array is fixed field.
	uint8_t CO_Get_NameA_Name[PayloadGetname_Get_from_MS[PH_CH_end_point+3]+4];
	int NameA_end_point=PH_CH_end_point;
	for (int i=0; i<(PayloadGetname_Get_from_MS[PH_CH_end_point+3]+4); i++)
	{
		CO_Get_NameA_Name[i]=PayloadGetname_Get_from_MS[NameA_end_point];
#ifdef LOG_CHECK
		printf("CO_Get_NameA_Name_%d: %x \n", i, CO_Get_NameA_Name[i]);
#endif
		NameA_end_point++;
	}

	//make a rct Name A array without Name type fields
	for(int i=4; i<(NameA_end_point-PH_CH_end_point); i++)
	{
		newNameA_size=i-4;
		if(CO_Get_NameA_Name[i]==0x10 && CO_Get_NameA_Name[i+2]==0x00)
		{
			break;
		}
#ifdef LOG_CHECK
		printf("i=%d\n", i);
#endif
	}
#ifdef LOG_CHECk
	printf("processor->rct[0]refcount=%d\n", processor->rct[0].refcount);
#endif
	processor->rct[processor->rct[0].refcount].NameA_size=newNameA_size;

#if 1
	//for RCT registration
	uint8_t newNameA[newNameA_size];

	for(int i = 0; i<newNameA_size;i++)
	{
		newNameA[i]=CO_Get_NameA_Name[i+4];
		processor->rct[processor->rct[0].refcount].NameA[i]=newNameA[i];
#ifdef LOG_CHECk
		printf("newNameA[i]= %x\n", newNameA[i]);
		printf("processor->rct[processor->rct[0].refcount].NameA[i]%x\n", processor->rct[processor->rct[0].refcount].NameA[i]);
#endif
	}
#ifdef LOG_CHECk
	printf("newNameA_size=%d\n", newNameA_size);
#endif

#endif

	//create CO_Payload_Getname type
	uint8_t CO_Get_PayloadGetType[4];
	int PayloadGetType_end_point=NameA_end_point;
	for(int i=0; i<4; i++)
	{
		CO_Get_PayloadGetType[i]=PayloadGetname_Get_from_MS[PayloadGetType_end_point];
#ifdef LOG_CHECK
		printf("CO_Get_PayloadGetType_%d: %x \n", i, CO_Get_PayloadGetType[i]);
#endif
		PayloadGetType_end_point++;
	}

	//create Name B Name with name type fields. Name B name's size array is fixed field.

	uint8_t CO_Get_NameB_Name[PayloadGetname_Get_from_MS[PayloadGetType_end_point+3]+4];
	int NameB_end_point=PayloadGetType_end_point;
	for(int i=0; i<PayloadGetname_Get_from_MS[PayloadGetType_end_point+3]+4; i++)
	{
		CO_Get_NameB_Name[i]=PayloadGetname_Get_from_MS[NameB_end_point];
#ifdef LOG_CHECK
		printf("CO_Get_NameB_Name_%d: %x \n", i, CO_Get_NameB_Name[i]);
#endif
		NameB_end_point++;
	}
#ifdef LOG_CHECK
	printf("end_point: %d\n", NameB_end_point);
#endif

#if 1
	//make a rct Name A array without Name type fields
	for(int i=4; i<(NameB_end_point-PayloadGetType_end_point); i++)
	{
		newNameB_size=i-4;
		if(CO_Get_NameB_Name[i]==0x10 && CO_Get_NameB_Name[i+2]==0x00)
		{
			break;
		}
#ifdef LOG_CHECK
		printf("i=%d\n", i);
#endif
	}

	processor->rct[processor->rct[0].refcount].NameB_size=newNameB_size;
#endif


#if 1
	//for RCT registration
	uint8_t newNameB[newNameB_size];

	for(int i = 0; i<newNameB_size;i++)
	{
		newNameB[i]=CO_Get_NameB_Name[i+4];
		processor->rct[processor->rct[0].refcount].NameB[i]=newNameB[i];
#ifdef LOG_CHECk
		printf("newNameB[i]= %x\n", newNameB[i]);
		printf("processor->rct[processor->rct[0].refcount].NameB[i]=%x, refcount=%d\n", processor->rct[processor->rct[0].refcount].NameB[i], processor->rct[0].refcount);
#endif
	}
#ifdef LOG_CHECK
	printf("newNameB_size=%d\n", newNameB_size);
#endif
	processor->rct[0].refcount++;
	//  printf("refcount=%d\n", processor->rct->refcount);
#endif


#if 1
#ifdef LOG_CHECk
	for(int j =0; j<processor->rct[0].refcount; j++)
	{
		printf("j = processor->rct[0].refcount = %d \n", j);
		printf("\nprocessor Name A: ");
		for(int i = 0; i<processor->rct[j].NameA_size;i++)
			printf(" %c", processor->rct[j].NameA[i]);

		printf("\nprocessor Name B: ");
		for(int i = 0; i<processor->rct[j].NameB_size;i++)
			printf(" %c", processor->rct[j].NameB[i]);
		printf("\n\n");
	}

#endif
#endif


	// change name fields and make interest_KeyType_message
	uint8_t interest_KeyType_message[message_length-(PayloadGetname_Get_from_MS[7]-8)];

	//add Packet Header and make Interest Header
	int PH_IH_end_point=0;
	interest_KeyType_message[0]=0x01; //Packet header
	interest_KeyType_message[1]=0x00;
	interest_KeyType_message[2]=0x00;
	interest_KeyType_message[3]=message_length-(PayloadGetname_Get_from_MS[7]-8); // general interest packet header size is 8 bytes.
	interest_KeyType_message[4]=0xff;
	interest_KeyType_message[5]=0x00;
	interest_KeyType_message[6]=0x00;
	interest_KeyType_message[7]=0x08;

	interest_KeyType_message[8]=0x00;//Interest message Header
	interest_KeyType_message[9]=0x01;
	interest_KeyType_message[10]=0x00;
	interest_KeyType_message[11]=message_length-(PayloadGetname_Get_from_MS[7]+4); //general interest header size is 4 bytes.

	for(int i=0; i < 12; i++)
	{
#ifdef LOG_CHECK
		printf("interest_KeyType_message_%d: %x \n", i, interest_KeyType_message[i]);
#endif
		PH_IH_end_point++;
	}

	int diff_NameA_start_point=PH_CH_end_point-PH_IH_end_point;
#ifdef LOG_CHECK
	printf("diff_NameA_start_point: %d\n", diff_NameA_start_point);
#endif

	//add NameB with name type fields
	NameB_end_point=PH_IH_end_point;
	for (int i=0; i<(CO_Get_NameB_Name[3]+4); i++)
	{
		interest_KeyType_message[i+PH_IH_end_point]=CO_Get_NameB_Name[i];
#ifdef LOG_CHECk
		printf("interest_KeyType_message_%d: %x \n", i+PH_IH_end_point,interest_KeyType_message[i+PH_IH_end_point]);
#endif
		NameB_end_point++;
	}



	//make I_Key(T_KEYNAME) type fields

	int I_KeyType_end_point=NameB_end_point;

	interest_KeyType_message[NameB_end_point+0]=0x01;
	interest_KeyType_message[NameB_end_point+1]=0x13;
	interest_KeyType_message[NameB_end_point+2]=0x00;

	//update value of GetType size field.
	interest_KeyType_message[NameB_end_point+3]=CO_Get_NameA_Name[3]+4;

	for(int i=0; i<4; i++)
	{
#ifdef LOG_CHECK
		printf("interest_KeyType_message_%d: %x \n", i+NameB_end_point, interest_KeyType_message[i+NameB_end_point]);
#endif

		I_KeyType_end_point++;
	}



	//add NameA Name with name type fields

	NameA_end_point=I_KeyType_end_point;
	for (int i=0; i<(CO_Get_NameA_Name[3]+4); i++)
	{
		interest_KeyType_message[i+I_KeyType_end_point]=CO_Get_NameA_Name[i];
#ifdef LOG_CHECk
		printf("interest_KeyType_message_%d: %x \n", i+I_KeyType_end_point, interest_KeyType_message[i+I_KeyType_end_point]);
#endif
		NameA_end_point++;
	}
#ifdef LOG_CHECk
	printf("NameA_end_point: %d\n\n", NameA_end_point);
#endif
#endif

#if 1
	PARCEventBuffer *buff = parcEventBuffer_Create();
	//  uint8_t metisTestDataV1_Interest_AllFields[]={0x31, 0x32};
	// name: /COM/GOOGLE/C3512 , Type: T_KEYNAME,  keyname: /com/google/d3512

	uint8_t metisTestDataV1_Interest_AllFields[]={
		0x01, 0x00, 0x00, 0x45, //Header
		0xff, 0x00, 0x00, 0x08,

		0x00, 0x01, 0x00, 0x39, //INTEREST Header


		0x00, 0x00, 0x00, 0x13, // NAME Header
		0x00, 0x01, 0x00, 0x06, // /COM/GOOGLE/C3512
		0x47, 0x4f, 0x4f, 0x47,
		0x4c, 0x45, 0x00, 0x01,
		0x00, 0x05, 0x43, 0x33,
		0x35, 0x31, 0x32,


		0x01, 0x13, 0x00, 0x1e, //T_KEYNAME Header


		0x00, 0x00, 0x00, 0x1a, // NAME Header
		0x00, 0x01, 0x00, 0x03, // /com/google/d3512
		0x63, 0x6f, 0x6d, 0x00,
		0x01, 0x00, 0x06, 0x67,
		0x6f, 0x6f, 0x67, 0x6c,
		0x65, 0x00, 0x01, 0x00,
		0x05, 0x64, 0x33, 0x35,
		0x31, 0x32

	};

	//parcEventBuffer_Append(buff, metisTestDataV1_Interest_AllFields, sizeof(metisTestDataV1_Interest_AllFields));
	parcEventBuffer_Append(buff, interest_KeyType_message, sizeof(interest_KeyType_message));
	PARCLogReporter *reporter = parcLogReporterTextStdout_Create();
	MetisLogger *logger = metisLogger_Create(reporter, parcClock_Wallclock());
	parcLogReporter_Release(&reporter);
	MetisMessage *interestKeyMessage = metisMessage_CreateFromBuffer(1, 2, buff, logger);
	//MetisMessage *message = parcMemory_AllocateAndClear(sizeof(MetisMessage));
	metisLogger_Release(&logger);
	//  interestKeyMessage->ingressConnectionId=message->ingressConnectionId;

#endif

#if 1
//	if (metisMessageProcessor_ForwardViaFib(processor, interestKeyMessage)==NULL)
	MetisFibEntry *fibEntry_check = metisFIB_Match(processor->fib, interestKeyMessage);
	if(fibEntry_check==NULL)
	{
#ifdef LOG_CHECk
		printf("******metisMessageProcessor_ForwardViaFib fail\n");
		printf("metisMessageProcessor_ReceiveContentObjectPayloadGetname()\n\n");
#endif

		metisMessageProcessor_ReceiveContentObject(processor, message);
		return;

	}
	else
	{
#ifdef LOG_CHECk
		printf("******metisMessageProcessor_ForwardViaFib success\n");
		printf("proceed metisMessageProcessor_ReceiveContentObjectPayloadGetname()\n");
#endif
	}
#endif

	unsigned ingressId_message = metisMessage_GetIngressConnectionId(message);
	unsigned ingressId_interestKeyMessage = metisMessage_GetIngressConnectionId(interestKeyMessage);
#ifdef LOG_CHECk
	printf("ingressId_message= %d, ingressId_interestKeymessage= %d\n\n", ingressId_message, ingressId_interestKeyMessage);
#endif




	int interestKeyMessage_length = parcEventBuffer_GetLength(interestKeyMessage->messageBytes);
#ifdef LOG_CHECK
	printf("interestKeyMessage_length is %d\n\n", interestKeyMessage_length);


	printf(" interestKeyMessage->messageHead, in  metisMessageProcessor_ReceiveContentObjectPayloadGetname()\n\n");
	for(int i=0; i<interestKeyMessage_length;i++)
	{
		printf("%x ", interestKeyMessage->messageHead[i]);
	}
	printf("\n\n");

#endif
	metisMessageProcessor_Receive(processor, interestKeyMessage);
}
















/**
 * @function metisMessageProcessor_ReceiveContentObject
 * @abstract Process an in-bound content object
 * @discussion
 *   (1) If it does not match anything in the PIT, drop it
 *   (2) Add to Content Store
 *   (3) Reverse path forward via PIT entries
 *
 * @param <#param1#>
 */
static void
metisMessageProcessor_ReceiveContentObject(MetisMessageProcessor *processor, MetisMessage *message)
{

	//by wschoi
#ifdef LOG_CHECk
	printf("metisMessageProcessor_ReceiveContentObject()\n\n");
#endif
	int ContentObjectMessage_length = parcEventBuffer_GetLength(message->messageBytes);
#ifdef LOG_CHECK
	printf("ContentObjectMessage_length is %d\n\n", ContentObjectMessage_length);


	printf("message->messageHead, in metisMessageProcessor_ReceiveContentObject() \n\n");
	for(int i=0; i<ContentObjectMessage_length;i++)
	{
		printf("%x ", message->messageHead[i]);
	}
	printf("\n\n");
#endif



    processor->stats.countObjectsReceived++;

    MetisNumberSet *ingressSetUnion = metisPIT_SatisfyInterest(processor->pit, message);

    if (metisNumberSet_Length(ingressSetUnion) == 0) {
        // (1) If it does not match anything in the PIT, drop it
		//by wschoi
#ifdef LOG_CHECK
		printf("metisNumberSet_Length(ingressSetUnion) == 0, (1) If it does not match anything in the PIT, drop it\n\n");
#endif
        processor->stats.countDroppedNoReversePath++;

        if (metisLogger_IsLoggable(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug)) {
            metisLogger_Log(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug, __func__,
                            "Message %p did not match PIT, no reverse path (count %u)",
                            (void *) message,
                            processor->stats.countDroppedNoReversePath);
        }

        metisMessageProcessor_Drop(processor, message);
    } else {
        // (2) Add to Content Store. Store may remove expired content, if necessary, depending on store policy.
        if (processor->store_in_cache) {
            uint64_t currentTimeTicks = metisForwarder_GetTicks(processor->metis);
            metisContentStoreInterface_PutContent(processor->contentStore, message, currentTimeTicks);
        }
        // (3) Reverse path forward via PIT entries

			//by wschoi
#ifdef LOG_CHECK
			printf("message->name, in metisMessageProcessor_ReceiveContentObject()\n\n");
			for(int i=0;  i<message->name->memoryLength;i++)
			{
				printf("%c ", message->name->memory[i]);
			}
			printf("\n\n");
			printf("\n\n");
#endif


        metisMessageProcessor_ForwardToNexthops(processor, message, ingressSetUnion);
    }

    metisNumberSet_Release(&ingressSetUnion);
}

/**
 * @function metisMessageProcessor_ForwardToNexthops
 * @abstract Try to forward to each nexthop listed in the MetisNumberSet
 * @discussion
 *   Will not forward to the ingress connection.
 *
 * @param <#param1#>
 * @return The number of nexthops tried
 */
static unsigned
metisMessageProcessor_ForwardToNexthops(MetisMessageProcessor *processor, MetisMessage *message, const MetisNumberSet *nexthops)
{

	//by wschoi
#ifdef LOG_CHECK
	printf("metisMessageProcessor_ForwardToNexthops()\n\n");
#endif
    unsigned forwardedCopies = 0;

    size_t length = metisNumberSet_Length(nexthops);

	//by wschoi
#ifdef LOG_CHECK
	printf("length = metisNumberSet_Length(nexthops)= %d\n\n", length);
#endif

    unsigned ingressId = metisMessage_GetIngressConnectionId(message);

	
	//by wschoi
#ifdef LOG_CHECK	
	printf("ingressId = %d\n\n ", ingressId); 
#endif


    for (size_t i = 0; i < length; i++) {
        unsigned egressId = metisNumberSet_GetItem(nexthops, i);
#ifdef LOG_CHECK
		printf("egressId = metisNumberSet_GetItem(nexthops, i)= %d, i = %d\n\n", egressId, i);
#endif
        if (egressId != ingressId) {
            forwardedCopies++;
            metisMessageProcessor_ForwardToInterfaceId(processor, message, egressId);
        }
    }
    return forwardedCopies;
}

/**
 * caller has checked that the hop limit is ok.  Try to send out the connection.
 */
static void
metisMessageProcessor_SendWithGoodHopLimit(MetisMessageProcessor *processor, MetisMessage *message, unsigned interfaceId, const MetisConnection *conn)
{
    bool success = metisConnection_Send(conn, message);
    if (success) {
        switch (metisMessage_GetType(message)) {
            case MetisMessagePacketType_Interest:
                processor->stats.countInterestForwarded++;
                break;

            case MetisMessagePacketType_ContentObject:
                processor->stats.countObjectsForwarded++;
                break;

            default:
                break;
        }

        if (metisLogger_IsLoggable(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug)) {
            metisLogger_Log(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug, __func__,
                            "forward message %p to interface %u (int %u, obj %u)",
                            (void *) message,
                            interfaceId,
                            processor->stats.countInterestForwarded,
                            processor->stats.countObjectsForwarded);
        }
    } else {
        processor->stats.countSendFailures++;

        if (metisLogger_IsLoggable(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug)) {
            metisLogger_Log(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug, __func__,
                            "forward message %p to interface %u send failure (count %u)",
                            (void *) message,
                            interfaceId,
                            processor->stats.countSendFailures);
        }
        metisMessageProcessor_Drop(processor, message);
    }
}

/*
 *   If the hoplimit is equal to 0, then we may only forward it to local applications.  Otherwise,
 *   we may forward it off the system.
 *
 */
static void
metisMessageProcessor_ForwardToInterfaceId(MetisMessageProcessor *processor, MetisMessage *message, unsigned interfaceId)
{
    MetisConnectionTable *connectionTable = metisForwarder_GetConnectionTable(processor->metis);
    const MetisConnection *conn = metisConnectionTable_FindById(connectionTable, interfaceId);


    if (conn != NULL) {
        /*
         * We can send the message if:
         * a) If the message does not carry a hop limit (e.g. content object)
         * b) It has a hoplimit and it is positive
         * c) Or if the egress connection is local (i.e. it has a hoplimit and it's 0, but this is ok for a local app)
         */
        if ((!metisMessage_HasHopLimit(message)) || (metisMessage_GetHopLimit(message) > 0) || metisConnection_IsLocal(conn)) {
            metisMessageProcessor_SendWithGoodHopLimit(processor, message, interfaceId, conn);
        } else {
            // To reach here, the message has to have a hop limit, it has to be 0 and and going to a remote target
            processor->stats.countDroppedZeroHopLimitToRemote++;

            if (metisLogger_IsLoggable(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug)) {
                metisLogger_Log(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug, __func__,
                                "forward message %p to interface %u hop limit 0 and not local (count %u)",
                                (void *) message,
                                interfaceId,
                                processor->stats.countDroppedZeroHopLimitToRemote);
            }
        }
    } else {
        processor->stats.countDroppedConnectionNotFound++;

        if (metisLogger_IsLoggable(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug)) {
            metisLogger_Log(processor->logger, MetisLoggerFacility_Processor, PARCLogLevel_Debug, __func__,
                            "forward message %p to interface %u not found (count %u)",
                            (void *) message,
                            interfaceId,
                            processor->stats.countDroppedConnectionNotFound);
        }

        metisMessageProcessor_Drop(processor, message);
    }
}

void
metisMessageProcessor_SetCacheStoreFlag(MetisMessageProcessor *processor, bool val)
{
    processor->store_in_cache = val;
}

bool
metisMessageProcessor_GetCacheStoreFlag(MetisMessageProcessor *processor)
{
    return processor->store_in_cache;
}

void
metisMessageProcessor_SetCacheServeFlag(MetisMessageProcessor *processor, bool val)
{
    processor->serve_from_cache = val;
}

bool
metisMessageProcessor_GetCacheServeFlag(MetisMessageProcessor *processor)
{
    return processor->serve_from_cache;
}
