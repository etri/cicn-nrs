#ifndef Metis_metis_RCT_h
#define Metis_metis_RCT_h
//by wschoi
#include <ccnx/common/ccnx_Name.h>
#include <ccnx/api/control/cpi_RouteEntry.h>

#include <ccnx/forwarder/metis/core/metis_NumberSet.h>
#include <ccnx/forwarder/metis/core/metis_Message.h>
//#include <ccnx/forwarder/metis/processor/metis_FibEntryList.h>
//#include <ccnx/forwarder/metis/processor/metis_FibEntry.h>
//#include <ccnx/forwarder/metis/core/metis_Logger.h>


struct metis_rct;
typedef struct metis_rct MetisRCT;

//MetisRCT *metisRCT_Create(MetisLogger *logger);
MetisRCT *metisRCT_Create();

bool metisRCT_AddOrUpdate(MetisRCT *rct, const uint8_t *newNameA, const unsinged newNameA_size, const uint8_t *newNameB, const unsinged newNameB_size);

MetisRctEntry *metisRCT_Match(MetisRCT *rct, const uint8_t NameA, const  unsigned NameA_size);

#endif // Metis_metis_RCT_h
