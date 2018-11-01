/*
 * from ccnxPing_Common.c
 */
#include <stdio.h>

#include "ccnxNRS_Common.h"

#include <LongBow/runtime.h>

#include <parc/security/parc_Security.h>
#include <parc/security/parc_Pkcs12KeyStore.h>
#include <parc/security/parc_IdentityFile.h>

const size_t ccnxNRS_DefaultReceiveTimeoutInUs = 1000000; // 1 second
const size_t ccnxNRS_DefaultPayloadSize = 4096;
const size_t mediumNumberOfPings = 100;
const size_t smallNumberOfPings = 10;

static PARCIdentity *
_ccnxNRSCommon_CreateAndGetIdentity(const char *keystoreName,
                                     const char *keystorePassword,
                                     const char *subjectName)
{
    parcSecurity_Init();

    unsigned int keyLength = 1024;
    unsigned int validityDays = 30;

    bool success = parcPkcs12KeyStore_CreateFile(keystoreName, keystorePassword, subjectName, keyLength, validityDays);
    assertTrue(success,
               "parcPkcs12KeyStore_CreateFile('%s', '%s', '%s', %d, %d) failed.",
               keystoreName, keystorePassword, subjectName, keyLength, validityDays);

    PARCIdentityFile *identityFile = parcIdentityFile_Create(keystoreName, keystorePassword);
    PARCIdentity *result = parcIdentity_Create(identityFile, PARCIdentityFileAsPARCIdentity);
    parcIdentityFile_Release(&identityFile);

    parcSecurity_Fini();

    return result;
}

CCNxPortalFactory *
ccnxNRSCommon_SetupPortalFactory(const char *keystoreName, const char *keystorePassword, const char *subjectName)
{
    PARCIdentity *identity = _ccnxNRSCommon_CreateAndGetIdentity(keystoreName, keystorePassword, subjectName);
    CCNxPortalFactory *result = ccnxPortalFactory_Create(identity);
    parcIdentity_Release(&identity);

    return result;
}

