/*
 * from ccnxPingCommon.h
*/

#ifndef ccnxNRSCommon_h
#define ccnxNRSCommon_h

#include <stdint.h>

#include <ccnx/api/ccnx_Portal/ccnx_Portal.h>

/**
 * The `CCNxName` prefix for the server.
 */
#define ccnxNRS_DefaultPrefix "ccnx:/localhost"

/**
 * The default client receive timeout (in microseconds).
 */
extern const size_t ccnxNRS_DefaultReceiveTimeoutInUs;

/**
 * The default size of a content object payload.
 */
extern const size_t ccnxNRS_DefaultPayloadSize;

/**
 * The maximum size of a content object payload.
 * 64KB is the limit imposed by the packet structure
 */
#define ccnxNRS_MaxPayloadSize 64000

/**
 * A default "medium" number of messages to send.
 */
extern const size_t mediumNumberOfPings;

/**
 * A default "small" number of messages to send.
 */
extern const size_t smallNumberOfPings;

/**
 * Initialize and return a new instance of CCNxPortalFactory. A randomly generated identity is
 * used to initialize the factory. The returned instance must eventually be released by calling
 * ccnxPortalFactory_Release().
 *
 * @param [in] keystoreName The name of the file to save the new identity.
 * @param [in] keystorePassword The password of the file holding the identity.
 * @param [in] subjectName The name of the owner of the identity.
 *
 * @return A new instance of a CCNxPortalFactory initialized with a randomly created identity.
 */
CCNxPortalFactory *ccnxNRSCommon_SetupPortalFactory(const char *keystoreName,
                                                     const char *keystorePassword,
                                                     const char *subjectName);




#endif // ccnxNRSCommon_h.h

