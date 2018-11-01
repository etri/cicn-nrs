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
#include <getopt.h>

#include <LongBow/runtime.h>

#include <ccnx/api/ccnx_Portal/ccnx_Portal.h>
#include <ccnx/api/ccnx_Portal/ccnx_PortalRTA.h>

#include <parc/algol/parc_Clock.h>

#include <parc/algol/parc_Object.h>

#include <parc/security/parc_Security.h>
#include <parc/security/parc_IdentityFile.h>
#include <parc/algol/parc_DisplayIndented.h>

#include "ccnxPing_Stats.h"
#include "ccnxPing_Common.h"
//by wschoi
//#define LOG_CHECK


typedef enum {
	CCNxPingClientMode_None = 0,
	CCNxPingClientMode_Flood,
	CCNxPingClientMode_PingPong,
	//by wschoi
	CCNxPingClientMode_Reg,
	CCNxPingClientMode_Add,
	CCNxPingClientMode_Del,
	CCNxPingClientMode_Dereg,
	CCNxPingClientMode_All
} CCNxPingClientMode;

typedef struct ccnx_Ping_client {
	CCNxPortal *portal;
	CCNxPingStats *stats;
	CCNxPingClientMode mode;

	CCNxName *prefix;
	uint8_t *key;

	size_t numberOfOutstanding;
	uint64_t receiveTimeoutInUs;
	int interestCounter;
	int count;
	uint64_t intervalInMs;
	int payloadSize;
	int nonce;
} CCNxPingClient;

/**
 * Create a new CCNxPortalFactory instance using a randomly generated identity saved to
 * the specified keystore.
 *
 * @return A new CCNxPortalFactory instance which must eventually be released by calling ccnxPortalFactory_Release().
 */
	static CCNxPortalFactory *
_setupClientPortalFactory(void)
{
	const char *keystoreName = "client.keystore";
	const char *keystorePassword = "keystore_password";
	const char *subjectName = "client";

	return ccnxPingCommon_SetupPortalFactory(keystoreName, keystorePassword, subjectName);
}

/**
 * Release the references held by the `CCNxPingClient`.
 */
	static bool
_ccnxPingClient_Destructor(CCNxPingClient **clientPtr)
{
	CCNxPingClient *client = *clientPtr;
	if (client->portal != NULL) {
		ccnxPortal_Release(&(client->portal));
	}
	if (client->prefix != NULL) {
		ccnxName_Release(&(client->prefix));
	}
	return true;
}

parcObject_Override(CCNxPingClient, PARCObject,
		.destructor = (PARCObjectDestructor *) _ccnxPingClient_Destructor);

parcObject_ImplementAcquire(ccnxPingClient, CCNxPingClient);
parcObject_ImplementRelease(ccnxPingClient, CCNxPingClient);

/**
 * Create a new empty `CCNxPingClient` instance.
 */
	static CCNxPingClient *
ccnxPingClient_Create(void)
{
	CCNxPingClient *client = parcObject_CreateInstance(CCNxPingClient);

	client->stats = ccnxPingStats_Create();
	client->interestCounter = 100;
	client->prefix = ccnxName_CreateFromCString(ccnxPing_DefaultPrefix);
	client->receiveTimeoutInUs = ccnxPing_DefaultReceiveTimeoutInUs;
	client->count = 10;
	client->intervalInMs = 1000;
	client->nonce = rand();
	client->numberOfOutstanding = 0;

	return client;
}

/**
 * Get the next `CCNxName` to issue. Increment the interest counter
 * for the client.
 */
	static CCNxName *
_ccnxPingClient_CreateNextName(CCNxPingClient *client)
{
	client->interestCounter++;
	char *suffixBuffer = NULL;
	asprintf(&suffixBuffer, "%x", client->nonce);
	CCNxName *name1 = ccnxName_ComposeNAME(ccnxName_Copy(client->prefix), suffixBuffer);
	parcMemory_Deallocate(&suffixBuffer);

	suffixBuffer = NULL;
	asprintf(&suffixBuffer, "%u", client->payloadSize);
	CCNxName *name2 = ccnxName_ComposeNAME(name1, suffixBuffer);
	ccnxName_Release(&name1);

	suffixBuffer = NULL;
	asprintf(&suffixBuffer, "%06lu", (long) client->interestCounter);
	CCNxName *name3 = ccnxName_ComposeNAME(name2, suffixBuffer);
	ccnxName_Release(&name2);

	return name3;
}

/**
 * Convert a timeval struct to a single microsecond count.
 */
	static uint64_t
_ccnxPingClient_CurrentTimeInUs(PARCClock *clock)
{
	struct timeval currentTimeVal;
	parcClock_GetTimeval(clock, &currentTimeVal);
	uint64_t microseconds = currentTimeVal.tv_sec * 1000000 + currentTimeVal.tv_usec;
	return microseconds;
}

/**
 * Run a single ping test.
 */
	static void
_ccnxPingClient_RunPing(CCNxPingClient *client, size_t totalPings, uint64_t delayInUs)
{
	PARCClock *clock = parcClock_Wallclock();

	CCNxPortalFactory *factory = _setupClientPortalFactory();
	client->portal = ccnxPortalFactory_CreatePortal(factory, ccnxPortalRTA_Message);
	ccnxPortalFactory_Release(&factory);

	size_t outstanding = 0;
	bool checkOustanding = client->numberOfOutstanding > 0;

	uint64_t nextPacketSendTime = 0;
	uint64_t currentTimeInUs = 0;
	int key_check=0;
	while(client->key[key_check] != '\0')
	{
#ifdef LOG_CHECK
		printf("client->key[%d]=%c\n", key_check, client->key[key_check]);
#endif
		key_check++;
	}


	//make interest registration messsage using keyname


	int slash_check = 0;
	char key_hex_name[128];
	int key_hex_name_size = 0;
	int str_size = key_check;
	int j = 0;
	int k = 4;


	key_hex_name[0] = 0x00; //name type 1
	key_hex_name[1] = 0x00; //name type 2

	for(int i=0; i<(str_size);i++)
	{
		if(client->key[j]=='/')
		{
			key_hex_name[k] = 0x00; // slash
			k++;

			key_hex_name[k] = 0x01;
			k++;

			key_hex_name[k] = 0x00;
			k++;

			key_hex_name[k] = 0x00; //size
			slash_check = k;
			k++;
		}
		else
		{

			key_hex_name[k] = client -> key[j];
			key_hex_name[slash_check] = key_hex_name[slash_check] + 0x01;
			k++;

		}
		j++;
	}


	int key_hex_name_size_with_name_field = k; //with name type fields
	key_hex_name_size = k - 4; //without name type fields
	key_hex_name[k] = '\0';
	key_hex_name[2] = 0x00; //name filed size 1
	key_hex_name[3] = 0x01 * key_hex_name_size; //without name type fields

#ifdef LOG_CHECK
	printf("key_hex_name_size_with_name_field= %d\n\n", 
			key_hex_name_size_with_name_field);

	for(int i = 0; i < key_hex_name_size_with_name_field; i++)
	{
		printf("key_hex_name 0x%x\n\n", key_hex_name[i]);
	}
#endif









	CCNxName *name = client -> prefix;
	CCNxInterest *interest = ccnxInterest_CreateSimple(name);
	PARCBuffer *payload = parcBuffer_Wrap(key_hex_name, 
			key_hex_name_size_with_name_field, 0, 
			key_hex_name_size_with_name_field);




	//reg
#if 1
	if(client->mode == CCNxPingClientMode_Reg)
	{
		ccnxInterest_SetPayload_reg_key(interest, payload);

#ifdef LOG_CHECK
		ccnxInterest_Display(interest, 0);
#endif
	}
#endif

	//add
#if 1
	else if(client->mode == CCNxPingClientMode_Add)
	{
		ccnxInterest_SetPayload_add_key(interest, payload);
#ifdef LOG_CHECK
		ccnxInterest_Display(interest, 0);
#endif
	}
#endif

	//del
#if 1

	else if(client->mode == CCNxPingClientMode_Del)
	{
		ccnxInterest_SetPayload_del_key(interest, payload);
#ifdef LOG_CHECK
		ccnxInterest_Display(interest, 0);
#endif
	}
#endif

	//Dereg
#if 1

	else if(client->mode == CCNxPingClientMode_Dereg)
	{
		ccnxInterest_SetPayload_dereg_key(interest, payload);
#ifdef LOG_CHECK
		ccnxInterest_Display(interest, 0);
#endif
	}
#endif



	CCNxMetaMessage *message = ccnxMetaMessage_CreateFromInterest(interest);
	if (ccnxPortal_Send(client->portal, message, CCNxStackTimeout_Never)) {
		currentTimeInUs = _ccnxPingClient_CurrentTimeInUs(clock);
		nextPacketSendTime = currentTimeInUs + delayInUs;

		ccnxPingStats_RecordRequest(client->stats, name,
				currentTimeInUs);
	}

	// We're done with pings, so let's wait to see if we have any stragglers
	currentTimeInUs = _ccnxPingClient_CurrentTimeInUs(clock);
	nextPacketSendTime = currentTimeInUs \
						 + client->receiveTimeoutInUs;

	uint64_t receiveDelay = nextPacketSendTime - currentTimeInUs;
	CCNxMetaMessage *response = 
		ccnxPortal_Receive(client->portal, CCNxStackTimeout_Never);

	while (response != NULL) {
#ifdef LOG_CHECK
		printf("into the while loop\n");
#endif
		uint64_t currentTimeInUs = _ccnxPingClient_CurrentTimeInUs(clock);
		if (ccnxMetaMessage_IsContentObject(response)) {
			CCNxContentObject *contentObject =
				ccnxMetaMessage_GetContentObject(response);
#ifdef LOG_CHECK
			printf("_ccnxPingClient_RunPing(), contentObject\n");
			ccnxContentObject_Display(contentObject, 1);
#endif
			printf("REG-ACK OK\n");
			CCNxName *responseName = 
				ccnxContentObject_GetName(contentObject);



			size_t delta = ccnxPingStats_RecordResponse(client->stats,
					responseName, currentTimeInUs, response);

			// Only display output if we're in ping mode
			if (client->mode == CCNxPingClientMode_PingPong) {
				size_t contentSize = 
					parcBuffer_Remaining(ccnxContentObject_GetPayload(contentObject));
				char *nameString = ccnxName_ToString(responseName);
				printf("%zu bytes from %s: time=%zu us\n", contentSize, nameString, delta);
				parcMemory_Deallocate(&nameString);
			}
		}
		ccnxMetaMessage_Release(&response);

		receiveDelay = nextPacketSendTime - currentTimeInUs;

		response = ccnxPortal_Receive(client -> portal, &receiveDelay);
	}
#ifdef LOG_CHECK

	printf("while end\n");
#endif
}

/**
 * Display the usage message.
 */
	static void
_displayUsage(char *progName)
{
	printf("CCNx Simple Ping Performance Test\n");
	printf("   (you must have ccnxPing_Server running)\n");
	printf("\n");
	printf("Usage: %s -p [ -c count ] [ -s size ] [ -i interval ]\n", progName);
	printf("       %s -f [ -c count ] [ -s size ]\n", progName);
	printf("       %s -h\n", progName);
	printf("\n");
	printf("Example:\n");
	printf("    ccnxPing_Client -l ccnx:/some/prefix -g -k /com/google/d3512 \n");
	printf("\n");
	printf("Options:\n");
	printf("     -h (--help) Show this help message\n");
	printf("     -p (--ping) ping mode - \n");
	printf("     -c (--count) Number of count to run\n");
	printf("     -l (--locator) Set the locator for this server. The default is 'ccnx:/locator'. \n");
	//by wschoi
	printf("NAME DB OPTION:\n");
	printf("     -g(--registration)\n");
	printf("     -u(--add)\n");
	printf("     -d(--del)\n");
	printf("     -e(--dereg)\n");
	printf("     -k(--key)\n");

}

/**
 * Parse the command lines to initialize the state of the
 */
	static bool
_ccnxPingClient_ParseCommandline(CCNxPingClient *client, int argc, char *argv[argc])
{
	static struct option longopts[] = {
		{ "ping",        no_argument,       NULL, 'p' },
		{ "count",       required_argument, NULL, 'c' },
		{ "locator",     required_argument, NULL, 'l' },
		{ "outstanding", required_argument, NULL, 'o' },
		{ "help",        no_argument,       NULL, 'h' },
		//by wschoi
		{ "reg",no_argument,       NULL, 'g' },
		{ "add",      no_argument,       NULL, 'a' },
		{ "del",      no_argument,       NULL, 'd' },
		{ "dereg",     no_argument,       NULL, 'e' },
		{ "key",         no_argument,       NULL, 'k' },
		{ NULL,          0,                 NULL, 0   }
	};

	client->payloadSize = ccnxPing_DefaultPayloadSize;

	int c;
	while ((c = getopt_long(argc, argv, "phcgade :k:l:o", longopts, NULL)) != -1) {

		switch (c) {
			case 'p':
				if (client->mode != CCNxPingClientMode_None) {
					return false;
				}
				client->mode = CCNxPingClientMode_PingPong;
				break;


				//by wschoi
			case 'g':
				if (client->mode != CCNxPingClientMode_None) {
					return false;
				}
				client->mode = CCNxPingClientMode_Reg;
				break;

			case 'a':
				if (client->mode != CCNxPingClientMode_None) {
					return false;
				}
				client->mode = CCNxPingClientMode_Add;
				break;

			case 'd':
				if (client->mode != CCNxPingClientMode_None) {
					return false;
				}
				client->mode = CCNxPingClientMode_Del;
				break;

			case 'e':
				if (client->mode != CCNxPingClientMode_None) {
					return false;
				}
				client->mode = CCNxPingClientMode_Dereg;
				break;

			case 'k':
				client->key = optarg;
				break;

			case 'o':
				sscanf(optarg, "%zu", &(client->numberOfOutstanding));
				break;
			case 'l':
				client->prefix = ccnxName_CreateFromCString(optarg);
				break;
			case 'h':
				_displayUsage(argv[0]);
				return false;
			default:
				break;
		}
	}

	if (client->mode == CCNxPingClientMode_None) {
		_displayUsage(argv[0]);
		return false;
	}

	return true;
};

	static void
_ccnxPingClient_DisplayStatistics(CCNxPingClient *client)
{
	bool ableToCompute = ccnxPingStats_Display(client->stats);
	if (!ableToCompute) {
		parcDisplayIndented_PrintLine(0, "No packets were received. Check to make sure the client and server are configured correctly and that the forwarder is running.\n");
	}
}

	static void
_ccnxPingClient_RunPingormanceTest(CCNxPingClient *client)
{
	switch (client->mode) {
		case CCNxPingClientMode_All:
			_ccnxPingClient_RunPing(client, mediumNumberOfPings, 0);
			_ccnxPingClient_DisplayStatistics(client);

			ccnxPingStats_Release(&client->stats);
			client->stats = ccnxPingStats_Create();

			_ccnxPingClient_RunPing(client, smallNumberOfPings, ccnxPing_DefaultReceiveTimeoutInUs);
			_ccnxPingClient_DisplayStatistics(client);
			break;


		case CCNxPingClientMode_Reg:
			_ccnxPingClient_RunPing(client, client->count, 0);
			_ccnxPingClient_DisplayStatistics(client);
			break;
		case CCNxPingClientMode_Add:
			_ccnxPingClient_RunPing(client, client->count, 0);
			_ccnxPingClient_DisplayStatistics(client);
			break;
		case CCNxPingClientMode_Del:
			_ccnxPingClient_RunPing(client, client->count, 0);
			_ccnxPingClient_DisplayStatistics(client);
			break;
		case CCNxPingClientMode_Dereg:
			_ccnxPingClient_RunPing(client, client->count, 0);
			_ccnxPingClient_DisplayStatistics(client);
			break;


		case CCNxPingClientMode_PingPong:
			_ccnxPingClient_RunPing(client, client->count, client->intervalInMs * 1000);
			_ccnxPingClient_DisplayStatistics(client);
			break;
		case CCNxPingClientMode_None:
		default:
			fprintf(stderr, "Error, unknown mode");
			break;
	}
}

	int
main(int argc, char *argv[argc])
{
	parcSecurity_Init();

	CCNxPingClient *client = ccnxPingClient_Create();

	bool runPing = _ccnxPingClient_ParseCommandline(client, argc, argv);
	if (runPing) {
		_ccnxPingClient_RunPingormanceTest(client);
	}

	ccnxPingClient_Release(&client);

	parcSecurity_Fini();

	return EXIT_SUCCESS;
}
