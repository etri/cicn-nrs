#include <config.h>
#include <stdio.h>

#include <ccnx/forwarder/metis/processor/metis_RCT.h>
//#include <ccnx/forwarder/metis/processor/metis_FIB.h>
#include <ccnx/forwarder/metis/processor/metis_FibEntry.h>
#include <ccnx/forwarder/metis/processor/metis_HashTableFunction.h>
#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_TreeRedBlack.h>

#include <LongBow/runtime.h>

// =====================================================

struct metis_rct {
	// KEY = tlvName, VALUE = FibEntry
	//    PARCHashCodeTable *tableByName;
	uint8_t *NameA;
	uint8_t *NameB;
	uint8_t *length;
	uint8_t *numberOfTable;
	MetisTlvName prefixNameA;
	unsigned refcount;
	unsigned *NameA_size;
	unsigned *NameB_size;

	// KEY = tlvName.  We use a tree for the keys because that
	// has the same average insert and remove time.  The tree
	// is only used by GetEntries, which in turn is used by things
	// that want to enumerate the FIB
	//  PARCTreeRedBlack *tableOfKeys;

	//MetisLogger *logger;

	// If there are no forward paths, we return an emtpy set.  Allocate this
	// once and return a reference to it whenever we need an empty set.
	//    MetisNumberSet *emptySet;
};



//static MetisFibEntry *_metisFIB_CreateFibEntry(MetisFIB *fib, MetisTlvName *tlvName, const char *fwdStrategy);

// =====================================================
// Public API

MetisRCT *
//metisRCT_Create(MetisLogger *logger)
metisRCT_Create()
{
	//    unsigned initialSize = 1024;

	MetisRCT *rct = parcMemory_AllocateAndClear(sizeof(MetisRCT));

	rct->NameA=parcMemory_AllocateAndClear(sizeof(uint8_t) * 16);
	rct->NameA_size=parcMemory_AllocateAndClear(sizeof(unsigned) * 16);
	rct->NameB=parcMemory_AllocateAndClear(sizeof(uint8_t) * 16);
	rct->NameB_size=parcMemory_AllocateAndClear(sizeof(unsigned) * 16);
	rct->length=parcMemory_AllocateAndClear(sizeof(uint8_t) * 16);
	rct->numberOfTable=parcMemory_AllocateAndClear(sizeof(uint8_t) * 16);
	rct->prefixNameA=parcMemory_AllocateAndClear(sizeof(MetisTlvName) * 16);
	rct->refcount=0;

	return rct;
}


/*
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
 */

	MetisRCT *
metisRct_Match(MetisRCT *rct, const uint8_t NameA, const unsigned NameA_size)
{
	unsigned compareResult=0;
	for (size_t i=0; i< rtc->refcount; i++)
	{

		if(rtc[i].NameA_size==NameA_size)
		{
			for(size_t j=0; j<NameA_size;j++)
			{
				if(rtc[i].NameA[j]==NameA[j])
				{
					compareResult++;

				}
			}

			if(NameA_size==compareResult)
			{
				return i; //rtc->refcount;
			}
		}
	}


	//by wschoi
	////////////////////////have to insert comparative context //////////have to consider longest matching


	return NULL;
}

	bool
metisRCT_AddOrUpdate(MetisRCT *rct, const uint8_t *newNameA, const unsigned NameA_size, const uint8_t *newNameB, const unsigned newNameB_size )
{
	rct[refcount].NameA=newNameA;
	rct[refcount].NameA_size=newNameA_size;
	rct[refcount].NameB=newNameB;
	rct[refcount].NameB_size=newNameB_size;



	rct->refcount++;


	return true;
}

/*
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
 */

/*


   size_t
   metisFIB_Length(const MetisFIB *fib)
   {
   assertNotNull(fib, "Parameter fib must be non-null");
   return parcHashCodeTable_Length(fib->tableByName);
   }
 *
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


