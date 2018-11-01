/**NOTICE*********************************************************************
Mapping table in MS is originally implemented using mysql which is 
under GPL license. However, the source codes using mysql are excluded in this file, 
since this project is distributed under Apache 2 license. 
So, it is required to make a program for the mapping table according to 
the comments in lines in ccnxMS-Server/ccnxReg_Server.c 
in order to make the this project working properly. 
Please contact us if you have any question on this. 
******************************************************************************/

#include <stdio.h>

#include <getopt.h>

#include <LongBow/runtime.h>

#include <parc/algol/parc_Object.h>

#include <parc/security/parc_Security.h>
#include <parc/security/parc_IdentityFile.h>

#include <ccnx/common/ccnx_Name.h>

#include <ccnx/api/ccnx_Portal/ccnx_Portal.h>
#include <ccnx/api/ccnx_Portal/ccnx_PortalRTA.h>

//by wschoi
#include <ccnx/common/codec/ccnxCodec_TlvDecoder.h>

#include "ccnxPing_Common.h"
#include "ccnxNRS_Common.h"
#include <parc/security/parc_Pkcs12KeyStore.h>

#include <stdlib.h>
#include <string.h>



//socket header add
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
//#define LOG_CHECK
#define MAX_LEN_SINGLE_LINE     120

#define ccnxNRS_MaxPayloadSize 64000
#define ccnxNRS_DefaultPrefix "ccnx:/localhost"
								
static char getname_name[100];

typedef struct getname_data{
	int getname_name_size;

	int getname_name_from_ms_size;

} interest_getname_data;

typedef struct ccnx_NRS_server {
	CCNxPortal *portal;
	CCNxName *prefix;
	size_t payloadSize;

	uint8_t generalPayload[ccnxNRS_MaxPayloadSize];
										
	int getname_name_size;
	int getname_name_from_ms_size;

} CCNxNRSServer;

/**
 * Create a new CCNxPortalFactory instance using a randomly generated identity saved to
 * the specified keystore.
 *
 * @return A new CCNxPortalFactory instance which must eventually be released by calling ccnxPortalFactory_Release().
 */
	static CCNxPortalFactory *
_setupServerPortalFactory(void)
{
	const char *keystoreName = "server.keystore";
	const char *keystorePassword = "keystore_password";
	const char *subjectName = "server";

	return ccnxNRSCommon_SetupPortalFactory(keystoreName, keystorePassword, subjectName);
}

/**
 * Release the references held by the `CCNxNRSClient`.
 */
	static bool
_ccnxNRSServer_Destructor(CCNxNRSServer **serverPtr)
{
	CCNxNRSServer *server = *serverPtr;
	if (server->portal != NULL) {
		ccnxPortal_Release(&(server->portal));
	}
	if (server->prefix != NULL) {
		ccnxName_Release(&(server->prefix));
	}
	return true;
}

parcObject_Override(CCNxNRSServer, PARCObject,
		.destructor = (PARCObjectDestructor *) _ccnxNRSServer_Destructor);

parcObject_ImplementAcquire(ccnxNRSServer, CCNxNRSServer);
parcObject_ImplementRelease(ccnxNRSServer, CCNxNRSServer);

/**
 * Create a new empty `CCNxNRSServer` instance.
 */
	static CCNxNRSServer *
ccnxNRSServer_Create(void)
{
	CCNxNRSServer *server = parcObject_CreateInstance(CCNxNRSServer);

	server->prefix = ccnxName_CreateFromCString(ccnxNRS_DefaultPrefix);
	server->payloadSize = ccnxNRS_DefaultPayloadSize;

	return server;
}


/***************Warning*****************************************
*In this function, It is required to complete code to lookup DB by using 
*DBMS, for example, mysql
* Pseudo code is included as belows
***************************************************************/
static int Lookup_name_DB(CCNxNRSServer *server)														   															 
{
	char find_name_T_GETNAME_str_1[server->getname_name_size+1];
	char *find_name_T_GETNAME_str;
	int find_name_T_GETNAME_str_1_size=server->getname_name_size;
	for(int i=0; i<find_name_T_GETNAME_str_1_size;i++)
	{
		find_name_T_GETNAME_str_1[i]=getname_name[i];
#ifdef LOG_CHECK
		printf("%c", find_name_T_GETNAME_str_1[i]);
#endif
	}
	find_name_T_GETNAME_str_1[server->getname_name_size]=NULL;
#ifdef LOG_CHECK
	printf("\n\n%s\n\n",find_name_T_GETNAME_str_1);

	printf("\n\n%d\n\n",sizeof(find_name_T_GETNAME_str_1));

	printf("\n\n$$$$$$$$Lookup_name_DB\n\n\n");
#endif

/***********************Warning**********************************
*	connect and lookup DBMS e.g., mysql-server 
* 	below code is written by pseudo code
*	So you have to input real code
***************************************************************
*	DBMS *myconnection;
*	DBMS_RESULT *result;
*	DBMS_ROW row;
*	char query[1024];
*	myconnection = my_dbms_init();
*	//Establishes DBMS connection
*	if(!mydbms_connection(myconnection, hostname, id, passwd, db_name,))
*	{
*
*		printf(stderr,"%s\n",dbms_error(conn));
*		return 0;
*	}
*	else
*	{
*#ifdef LOG_CHECK
*		printf("mydbms_connection is success!\n");
*#endif
*
*	}
*
*	sprintf(query,"SELECT * FROM `my_db_name` WHERE `name1` = '%s'", find_name_T_GETNAME_str_1);
#if 0
*
*	// procedd lookup by using query
*	if(!mydbms_query(myconnnection,query))
*	{
*
*		printf("MS1 lookup is success\n");
*	}
*	else
*	{
*	
*		printf("MS1 lookup is failure\n");
*	}
*
*       // matching work
*	result = mydbmsl_use_result(myconnection);
*	while((row = mydbms_fetch_row(result)) != NULL)
*	{
*		printf("%s\n",row[1]);
*		printf("%s\n",row[2]);
*		find_name_T_GETNAME_str=row[2];
*		printf("name exist in MY DB\n");
*		printf("%s, find_name_T_GETNAME_str size: %d\n", *find_name_T_GETNAME_str, sizeof(find_name_T_GETNAME_str));
*	}
* end of pseudo code */
	int k=0;
	while(find_name_T_GETNAME_str[k]!=NULL)
	{
		getname_name[k]=find_name_T_GETNAME_str[k];
		k++;
	}
	server->getname_name_from_ms_size=k;

	return 1;
#else

/***************Warning***************************
*	// error check
*	if(mydbms_query(myconnection,query))
*	{
*		printf("Write DB error\n");
*	}
*	res = mydbms_use_result(conn);
*
*
*	row = mydbms_fetch_row(res);
* end of pseudo code*/

	if(row != NULL)
	{
		find_name_T_GETNAME_str=row[2];
		int k=0;
		while(find_name_T_GETNAME_str[k]!=NULL)
		{
			getname_name[k]=find_name_T_GETNAME_str[k];
			k++;
		}
		server->getname_name_from_ms_size=k;

		return 1;
	}
	else
	{
		return 0;
	}


#endif


}

	int sock;
	struct sockaddr_in serv_addr;
	int str_len;

	sock = socket(PF_INET, SOCK_STREAM, 0);
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
	if(sock == -1)
	{
		printf("In client loop, socket() error\n");
	}
	else
	{
#ifdef LOG_CHECK
		printf("In client loop, socket() success\n");
#endif
	}

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;

	//MS2 or DNS IP address  from name.txt
	FILE *fp_root_ip;
	fp_root_ip = fopen("./ccnxMS-Server/config/NRS_IP.txt","r");
	char root_ip[256];
	fscanf(fp_root_ip, "%s", root_ip);

	int root_ip_length=0;
	while(root_ip[root_ip_length] != '\0')
	{
		root_ip_length++;
	}
	fclose(fp_root_ip);
#ifdef LOG_CHECK
    printf("fetch root ip addr. from NRS_IP.txt: %s, size: %d\n", root_ip, root_ip_length);
#endif


	if(connect(sock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) == -1)
	{
		printf("In client loop, connect() error\n");
	}
	else
	{
#ifdef LOG_CHECK
		printf("In client loop, connect() success\n");
#endif
	}


	write(sock,message_to_ms2,sizeof(message_to_ms2));
	close(sock);
											
#endif

#if 1
	int serv_sock;
	int clnt_sock;
	struct sockaddr_in serv_addr1;
	int clnt_addr_size;
	struct sockaddr_in clnt_addr;
	char message[50];

	serv_sock = socket(PF_INET, SOCK_STREAM, 0);    

	setsockopt(serv_sock, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
	if(serv_sock == -1)
	{
		printf("In server loop, socket() error\n");            
	}
	else
	{
#ifdef LOG_CHECK
		printf("In server loop, socket() success\n");
#endif
	}

	memset(&serv_addr1, 0, sizeof(serv_addr1));       
	serv_addr1.sin_family = AF_INET;                    
	serv_addr1.sin_addr.s_addr = htonl(INADDR_ANY);    
	serv_addr1.sin_port = htons(12346);      


	if(bind(serv_sock, (struct sockaddr *) &serv_addr1, sizeof(serv_addr1)) == -1)
	{
		printf("In server loop, bind() error\n");
	}
	else
	{
#ifdef LOG_CHECK
		printf("In server loop, bind() success\n");
#endif

	}



	if(listen(serv_sock, 5) == -1)
	{
		printf("In server loop, listen() error\n");
	}
	else
	{
#ifdef LOG_CHECK
		printf("In server loop, listen() success\n");
#endif
	}

	clnt_addr_size = sizeof(clnt_addr);


	clnt_sock = accept(serv_sock, (struct sockaddr *) &clnt_addr, &clnt_addr_size);
	if(clnt_sock == -1)
	{
		printf("In server loop, accept() error\n");
	}
	else 
	{
#ifdef LOG_CHECK
		printf("In server loop, accept() success\n");
#endif
	}



	str_len=read(clnt_sock,message,sizeof(message)-1);
	if(str_len==-1)
	{
		printf("in server loop, read() error\n");
	}
	else
	{
#ifdef LOG_CHECK
		printf("In server loop, read() success\n");
#endif
	}
	  
	message[str_len]=0;
#ifdef LOG_CHECK
	printf("Message From MS2 : %s\n",message);
#endif

	close(clnt_sock);   
	close(serv_sock);
												  
					  

#endif
																	 
#ifdef LOG_CHECK
	printf("Recived message, %s message,### %d\n\n ", message, str_len);
#endif
												
	  

	int k=0;
	while(message[k]!=NULL)
	{
		getname_name[k]=message[k];
		k++;
	}
	server->getname_name_from_ms_size=k;

				
#ifdef LOG_CHECK
	printf("#$$$$$$$$$$$$message, %s message,### %d$$$$$k=%d\n\n ", message, str_len, k);

	for(int i=0;i<k;i++)
	{
		printf("%c", getname_name[i]);
	 
												

	}
	printf("\n\n");
#endif


}


/**
 * Create a `PARCBuffer` payload of the server-configured size.
 */
	PARCBuffer *
_ccnxNRSServer_MakePayload(CCNxNRSServer *server, int size)
{
	PARCBuffer *payload = parcBuffer_Wrap(server->generalPayload, size, 0, size);
	return payload;
}




static void
_ccnxNRSServer_Run_lookup(CCNxNRSServer *server, CCNxInterest *interest)
 
{

	CCNxName *interestName = ccnxInterest_GetName(interest);
	PARCBuffer *payload_lookup = ccnxInterest_GetPayload_lookup(interest);

	PARCBuffer *payload_lookup_clone = parcBuffer_Copy(payload_lookup);
	PARCBuffer *payload_lookup_clone_size = parcBuffer_Copy(payload_lookup);


	parcBuffer_Mark(payload_lookup_clone_size);
	parcBuffer_Resize(payload_lookup_clone_size, 4);
	uint8_t *actual_array_size = parcBuffer_ToString(payload_lookup_clone_size);

	int  payload_clone_resize_value = actual_array_size[3]+4;
#ifdef LOG_CHECK
	printf("#####Mark%d\n\n", payload_clone_resize_value);
#endif
	parcBuffer_Mark(payload_lookup_clone);
#ifdef LOG_CHECK
	parcBuffer_Display(payload_lookup_clone, 3);
#endif
#ifdef LOG_CHECK
	printf("#####resize\n\n");
#endif
	parcBuffer_Resize(payload_lookup_clone, payload_clone_resize_value);
#ifdef LOG_CHECK
	parcBuffer_Display(payload_lookup_clone, 3);
#endif

	CCNxCodecTlvDecoder *outerDecoder_lookup = ccnxCodecTlvDecoder_Create(payload_lookup);

	//Payload type
	uint16_t type_lookup = ccnxCodecTlvDecoder_GetType(outerDecoder_lookup);

	//T_GETNAME length
	unsigned length = ccnxCodecTlvDecoder_GetLength(outerDecoder_lookup);
#ifdef LOG_CHECK
	printf("##############actual_array display \n\n");
	parcBuffer_Display(payload_lookup_clone, 3);
#endif

	uint8_t *actual_array = parcBuffer_ToString(payload_lookup_clone);
										 

	parcBuffer_Release(&payload_lookup);
	parcBuffer_Release(&payload_lookup_clone);
	parcBuffer_Release(&payload_lookup_clone_size);

										   

#if 1

										 

	// Make a string Name from GETNAME 
	int actual_array_name_size=(int)actual_array[3];
	char actual_array_trans[actual_array_name_size];
	int k=0, n=0;
	int actual_array_trans_size=0;
	char command_array[128];
	int command_array_size=0;
	int command_array_each_size[128];
	int command_array_each_size_i=0;
	int command_start_point=4;
	int command_actual_array_size=0;

#ifdef LOG_CHECK
	printf("##############actual_array_name_size: %d \n\n", actual_array_name_size);
#endif
															
#ifdef LOG_CHECK
	for(int i=0; i<56; i++)
	{
		printf("actual_array: %c\n", actual_array[i]);

	}
#endif
						  

	for(int i=4; i<actual_array_name_size+4;i++)
	{
		if(actual_array[i]==0x00 && actual_array[i+1]==0x01 && actual_array[i+2]==0x00)
		{
			actual_array_trans[k]='/';
#ifdef LOG_CHECK
			printf("actual_array_trans: %c\n", actual_array_trans[k]);
#endif
			k++;
			command_start_point= command_start_point +4+actual_array[i+3];

			for (int j=0; j<actual_array[i+3];j++)
			{
				actual_array_trans[k]=actual_array[i+4+j];
#ifdef LOG_CHECK
				printf("actual_array_trans: %c\n", actual_array_trans[k]);
#endif
				k++;
				actual_array_trans_size++;
			}			
			actual_array_trans_size++;
				
	  
		}
		else if(actual_array[i]==0x10 && actual_array[i+2]==0x00)
	 
		{
											   
												

			command_array[n]='/';
#ifdef LOG_CHECK
			printf("command_array: %c\n", command_array[n]);
#endif
			n++;
			command_array_each_size[command_array_each_size_i]=actual_array[i+3];
			command_array_each_size_i++;


			for (int j=0; j<actual_array[i+3];j++)
			{
				command_array[n]=actual_array[i+4+j];
#ifdef LOG_CHECK
				printf("command_array: %c\n", command_array[n]);
#endif
				n++;
				command_array_size++;
			}			
			command_array_size++;
		}

		else if(actual_array[i]==0x00 && actual_array[i+1]==0x10 && actual_array[i+2]==0x00)
		{
			break;
		}

	}

	command_actual_array_size= 4+actual_array_name_size-command_start_point;
#ifdef LOG_CHECK
	printf("#####################command_start_point: %d, command_actual_array_size: %d\n\n", command_start_point, command_actual_array_size);
	printf("command_array_each_size1: %d, command_array_each_size2: %d, command_array_size: %d\n\n", command_array_each_size[0],command_array_each_size[1], command_array_size);
#endif		
	char command_tow_dimension[command_array_each_size_i][128];
	int m=0;
	for(int i=0; i<command_array_each_size_i;i++)
	{
		for(int j=0; j<command_array_each_size[i];j++)
		{
			if(command_array[m]!='/')
			{
				command_tow_dimension[i][j]=command_array[m];
#ifdef LOG_CHECK
				printf("#####################ccommand_array %c\n", command_array[m]);
				printf("#####################command_tow_dimension %c, i=%d, j=%d\n", command_tow_dimension[i][j], i, j);
#endif
				if(j==command_array_each_size[i]-1)
				{
					command_tow_dimension[i][command_array_each_size[i]]=NULL;
				}

			}
			else
			{
				j--;
			}
			m++;

		}
	}
#ifdef LOG_CHECK
	printf("command1: %s\n\n", command_tow_dimension[0]);
	printf("command2: %s\n\n", command_tow_dimension[1]);
	printf("check command2: %c, %c, %c, %c, %c\n", command_tow_dimension[1][0], command_tow_dimension[1][1], command_tow_dimension[1][2], command_tow_dimension[1][3]);
#endif
							
	PARCBuffer *commandBuffer;
	PARCBuffer *filenameBuffer;
	PARCBuffer *chunknumberBuffer;

	CCNxNameSegment *commandSegment;
	CCNxNameSegment *filenameSegment;
	CCNxNameSegment *chunknumberSegment;
	uint8_t chunkNumber[1];

	if(command_array_each_size_i==2)						
	{
		commandBuffer= parcBuffer_WrapCString(command_tow_dimension[0]);
#ifdef LOG_CHECK
		parcBuffer_Display(commandBuffer, 0);
#endif
		commandSegment = ccnxNameSegment_CreateTypeValue(CCNxNameLabelType_App(0x0000), commandBuffer);
#ifdef LOG_CHECK
		ccnxNameSegment_Display(commandSegment, 10);
#endif
	   

		filenameBuffer = parcBuffer_WrapCString(command_tow_dimension[1]);
#ifdef LOG_CHECK
		parcBuffer_Display(filenameBuffer, 0);
#endif
		filenameSegment = ccnxNameSegment_CreateTypeValue(CCNxNameLabelType_App(0x0001), filenameBuffer);
#ifdef LOG_CHECK
		ccnxNameSegment_Display(filenameSegment, 10);
#endif
									  

		chunkNumber[0]=actual_array[actual_array_name_size+3];
#ifdef LOG_CHECK
		printf("########################## actual_array[actual_array_name_size+4]= %x, actual_array_name_size=%d\n\n", actual_array[actual_array_name_size+1], actual_array_name_size);
#endif
		chunknumberBuffer = parcBuffer_Wrap(chunkNumber, 1, 0, 1);
																		   
		chunknumberSegment = ccnxNameSegment_CreateTypeValue(CCNxNameLabelType_CHUNK, chunknumberBuffer);
#ifdef LOG_CHECK
		ccnxNameSegment_Display(chunknumberSegment, 10);
#endif
			

	}
	else
	{

		commandBuffer= parcBuffer_WrapCString(command_tow_dimension[0]);
#ifdef LOG_CHECK
		parcBuffer_Display(commandBuffer, 0);
#endif
		commandSegment = ccnxNameSegment_CreateTypeValue(CCNxNameLabelType_NAME, commandBuffer);
#ifdef LOG_CHECK
		ccnxNameSegment_Display(commandSegment, 10);
#endif
	}
									   
#endif

	//################################ lookup to DB
	//################################ lookup loop
																		   
	for(int i=0; i<actual_array_trans_size;i++)
	{
		getname_name[i]=actual_array_trans[i];
	}

	server->getname_name_size=actual_array_trans_size;
				

	if(Lookup_name_DB(server))
	{

	}
	else
	{
#ifdef LOG_CHECK
		printf("into MS2 loop\n");
#endif
		//send to MS2
		request_to_MS2(server);

	}
				

	int new_name_T_GETNAME_str_size=server->getname_name_from_ms_size;
	char new_name_T_GETNAME_str[new_name_T_GETNAME_str_size];
	for(int i=0; i<new_name_T_GETNAME_str_size;i++)
	{
		new_name_T_GETNAME_str[i]=getname_name[i];
	}

	  

	//##########################make payload for PAYLOAD_GETNAME
	//##########################make payload for PAYLOAD_GETNAME
	//##########################make payload for PAYLOAD_GETNAME
#if 0
	char payload_getname[new_name_T_GETNAME_str_size];
	 
	int getname_j=0;
	int getname_k=4;
	int getname_slash_check=0;
	int getname_str_name_size=0;

	payload_getname[0]=0x00; //name type1
	payload_getname[1]=0x00; //name type2


	for(int i=0; i<(new_name_T_GETNAME_str_size);i++)
	{
		if(new_name_T_GETNAME_str[getname_j]=='/')
		{
			payload_getname[getname_k] = 0x00; // slash
			getname_k++;

			payload_getname[getname_k] = 0x01;
			getname_k++;

			payload_getname[getname_k] = 0x00;
			getname_k++;

			payload_getname[getname_k] = 0x00; //size
			getname_slash_check=getname_k;
			getname_k++;
		}
		else
		{

			payload_getname[getname_k] = new_name_T_GETNAME_str[getname_j];
			payload_getname[getname_slash_check]= payload_getname[getname_slash_check]+0x01;
			getname_k++;

											   
		}
		getname_j++;
	  
				
												 
	  
	}
				
												

	getname_str_name_size=getname_k-4; //name type, length ?„ë“œ  ?œì™¸
	payload_getname[getname_k] = NULL;
	payload_getname[2] = 0x00; //name filed size 1
	payload_getname[3] = 0x01 * getname_str_name_size; //name filed size 2

	printf("########## str_name_size %d\n\n", getname_str_name_size);
	/*
	   for(int i=0;i<getname_str_name_size+4;i++)
	   {	
	   printf("########## 0x%x\n\n", payload_getname[i]);
	   }
	 */
#else

	int payload_size=0;
	for(int i = 0; i<new_name_T_GETNAME_str_size; i++)
	{
		if(new_name_T_GETNAME_str[i]=='/')
			payload_size= payload_size+4;
		else
			payload_size++;
	}
#ifdef LOG_CHECK
	printf("sizeof(new_name_T_GETNAME_str)= %d, payload_size= %d\n\n", sizeof(new_name_T_GETNAME_str), payload_size);
#endif

	//	char payload_getname[new_name_T_GETNAME_str_size+command_actual_array_size+4];

	//	char payload_getname[payload_size+command_actual_array_size+4];
	int payload_getname_total_size=payload_size+command_actual_array_size+4;
	  
									 
	  

	char payload_getname[payload_getname_total_size];

	int getname_j=0;
	int getname_k=4;
	int getname_slash_check=0;
	int getname_str_name_size=0;

	payload_getname[0]=0x00; //name type1
	payload_getname[1]=0x00; //name type2
#ifdef LOG_CHECK
	printf("new_name_T_GETNAME_str_size=: %d, command_actual_array_size: %d\n\n", new_name_T_GETNAME_str_size, command_actual_array_size);
#endif
	//for(int i=0; i<(new_name_T_GETNAME_str_size);i++)
	for(int i=0; i<(new_name_T_GETNAME_str_size);i++)
	{
		if(new_name_T_GETNAME_str[getname_j]=='/')
		{
			payload_getname[getname_k] = 0x00; // slash
			getname_k++;

			payload_getname[getname_k] = 0x01;
			getname_k++;


			payload_getname[getname_k] = 0x00;
			getname_k++;
	  

			payload_getname[getname_k] = 0x00; //size
			getname_slash_check=getname_k;
			getname_k++;
		
								   
		}
		else
		{
				
			payload_getname[getname_k] = new_name_T_GETNAME_str[getname_j];
			payload_getname[getname_slash_check]= payload_getname[getname_slash_check]+0x01;
			getname_k++;

		}
		getname_j++;
	}

	getname_str_name_size=getname_k-4; //name type, length ?„ë“œ  ?œì™¸
	payload_getname[getname_k] = NULL;
	payload_getname[2] = 0x00; //name filed size 1
	payload_getname[3] = 0x01 * getname_str_name_size+command_actual_array_size; //name filed size 2
	   
												  
#ifdef LOG_CHECK
	printf("########## str_name_size %d\n\n", getname_str_name_size);


	for(int i =0 ; i<payload_size+4; i++)
		printf("@#@#%d,  %x\n",i, payload_getname[i]);
#endif

	//add command to GETNAME_PAYLOAD
	for(int i=0; i<command_actual_array_size;i++)
	{
		payload_getname[i + payload_size+4]= actual_array[i+command_start_point];
														   
#ifdef LOG_CHECK
		printf("@#@#%d,  %x\n",i, actual_array[i+command_start_point]);
#endif
	}

#endif

		 

	//  make a ccnxName of name1 for GETNAME/GETNAME_PAYLOAD format
			
#if 1
		

	char actural_array_trans_add_domain_str[128]="ccnx:";
	actual_array_trans[actual_array_trans_size]='\0';
#ifdef LOG_CHECK
	printf("actual_array_trans[%d]:%c\n\n",actual_array_trans_size,	actual_array_trans[actual_array_trans_size]);
	printf("actual_array_trans:%s\n\n",actual_array_trans);
#endif
																								
												 

	strcat(actural_array_trans_add_domain_str, actual_array_trans);
	CCNxName *ContentObjectName_Getname= ccnxName_CreateFromCString(actural_array_trans_add_domain_str);

	//##############add command
#if 1
	if(command_array_each_size_i==2)
	{
		ccnxName_Append(ContentObjectName_Getname, commandSegment);
		ccnxName_Append(ContentObjectName_Getname, filenameSegment);
		ccnxName_Append(ContentObjectName_Getname, chunknumberSegment);
	}
	else
	{
		ccnxName_Append(ContentObjectName_Getname, commandSegment);
	}
#endif
																																 
		 
#ifdef LOG_CHECK 
	printf("###########ContentObjectName_Getname\n\n");
	ccnxName_Display(ContentObjectName_Getname, 10);
#endif



#endif



#if 0
	//send contentobject message.  (MS1 name)/(Value) formant
	printf("##################Sending Content Object message in Server###################\n\n");
									
									
									
									
									
									
									
									
								   
								   
									
									
									
									
									
																  


	PARCBuffer *payload_lookup_content = parcBuffer_Wrap(payload_getname, getname_str_name_size+4, 0, getname_str_name_size+4);
		
	 
						 

						  

	CCNxContentObject *contentObject_lookup_content = ccnxContentObject_CreateWithNameAndPayload_lookup(interestName, payload_lookup_content);
	 
						 
																	
																								 

															   
											
																 

	CCNxMetaMessage *message_lookup_content = ccnxMetaMessage_CreateFromContentObject(contentObject_lookup_content);
																								
																				   

	printf("############################\n");
	ccnxContentObject_Display(contentObject_lookup_content, 3);
	printf("############################\n");
	ccnxPortal_Send(server->portal, message_lookup_content, CCNxStackTimeout_Never);

				
																													  
																																				 
	  

	sleep(1);
	ccnxMetaMessage_Release(&message_lookup_content);
				 

											
																		 
				   
	  
												 
	  
#else
	  
												   
	  

	//send contentobject message.  (NAME1)/(Value) formant
#ifdef LOG_CHECK
	printf("##################Sending Content Object message in Server###################\n\n");
#endif			
															  

	//PARCBuffer *payload_lookup_content = parcBuffer_Wrap(payload_getname, getname_str_name_size+4, 0, getname_str_name_size+4);
	PARCBuffer *payload_lookup_content = parcBuffer_Wrap(payload_getname, payload_getname_total_size, 0, payload_getname_total_size);


	//add command
#if 0
	printf("###########ContentObjectName_Getname_add command\n\n");
	ccnxName_Append(payload_lookup_content, commandSegment);
	parcBuffer_Display(payload_lookup_content, 5);
	//ccnxName_Display(ContentObjectName_Getname, 10);
#endif

	CCNxContentObject *contentObject_lookup_content = ccnxContentObject_CreateWithNameAndPayload_lookup(ContentObjectName_Getname, payload_lookup_content);
				   

	CCNxMetaMessage *message_lookup_content = ccnxMetaMessage_CreateFromContentObject(contentObject_lookup_content);
						
	  
#ifdef LOG_CHECK
	printf("############################\n");
	ccnxContentObject_Display(contentObject_lookup_content, 3);
	printf("############################\n");
#endif
	ccnxPortal_Send(server->portal, message_lookup_content, CCNxStackTimeout_Never);

													
									
	sleep(1);
	ccnxMetaMessage_Release(&message_lookup_content);
	  
											   
	  
		 
	  
												 

	  

#endif

}


/**************Warning*******************************************
*In this function, It is required to complete code to running DBMS server
* by using any other DBMS, for example, mysql
* Pseudo code is included as belows
***************************************************************/

/**
 * Run the `CCNxNRSServer` indefinitely.
 */
	static void
_ccnxNRSServer_Run(CCNxNRSServer *server)
{

	CCNxPortalFactory *factory = _setupServerPortalFactory();
	server->portal = ccnxPortalFactory_CreatePortal(factory, ccnxPortalRTA_Message);
	ccnxPortalFactory_Release(&factory);

	size_t yearInSeconds = 60 * 60 * 24 * 365;

	size_t sizeIndex = ccnxName_GetSegmentCount(server->prefix) + 1;

	if (ccnxPortal_Listen(server->portal, server->prefix, yearInSeconds, CCNxStackTimeout_Never)) {
		while (true) {
			CCNxMetaMessage *request = ccnxPortal_Receive(server->portal, CCNxStackTimeout_Never);

			// This should never happen.
			if (request == NULL) {
				break;
			}

			CCNxInterest *interest = ccnxMetaMessage_GetInterest(request);
			if (interest != NULL) {
				CCNxName *interestName = ccnxInterest_GetName(interest);

				// Extract the size of the payload response from the client
				// CCNxNameSegment *sizeSegment = ccnxName_GetSegment(interestName, sizeIndex);
				// char *segmentString = ccnxNameSegment_ToString(sizeSegment);
				// int size = atoi(segmentString);
				int size = 4;
				// size = size > ccnxPing_MaxPayloadSize ? ccnxPing_MaxPayloadSize : size;

				//define socket message type
				char message_type_to_MS2[256];
				int message_length_to_MS2=0;

				PARCBuffer *get_key=NULL;

				//extract reg_key name

				PARCBuffer *reg_key = ccnxInterest_GetPayload_reg_key(interest);
				PARCBuffer *add_key = ccnxInterest_GetPayload_add_key(interest);
				PARCBuffer *del_key = ccnxInterest_GetPayload_del_key(interest);
				PARCBuffer *dereg_key = ccnxInterest_GetPayload_dereg_key(interest);
				//extract lookup															 
				PARCBuffer *payload_lookup = ccnxInterest_GetPayload_lookup(interest);


				if(payload_lookup!=NULL)
				{
					_ccnxNRSServer_Run_lookup(server, interest);
					//return;
				}
				else
				{
				if(reg_key!=NULL)
				{
					message_length_to_MS2=sizeof("IP-reg");
					strncpy(message_type_to_MS2, "IP-reg", message_length_to_MS2);
					get_key=reg_key;
#ifdef LOG_CHECK
					printf("message_type_to_MS2: %s, size: %ld\n", message_type_to_MS2, sizeof("IP-reg"));
#endif
				}
				else if(add_key!=NULL)
				{
					message_length_to_MS2=sizeof("IP-add");
					strncpy(message_type_to_MS2, "IP-add", message_length_to_MS2);
					get_key=add_key;
#ifdef LOG_CHECK
					printf("message_type_to_MS2: %s, size: %ld\n", message_type_to_MS2, sizeof("IP-add"));
#endif
				}
				else if(del_key!=NULL)
				{
					message_length_to_MS2=sizeof("IP-del");
					strncpy(message_type_to_MS2, "IP-del", message_length_to_MS2);
					get_key=del_key;
#ifdef LOG_CHECK
					printf("message_type_to_MS2: %s, size: %ld\n", message_type_to_MS2, sizeof("IP-del"));
#endif
				}
				else if(dereg_key!=NULL)
				{
					message_length_to_MS2=sizeof("IP-dereg");
					strncpy(message_type_to_MS2, "IP-dereg", message_length_to_MS2);
					get_key=dereg_key;
#ifdef LOG_CHECK
					printf("message_type_to_MS2: %s, size: %ld\n", message_type_to_MS2, sizeof("IP-dereg"));
#endif
				}





#ifdef LOG_CHECK

				printf("reg_key\n");
				parcBuffer_Display(reg_key, 0);
				printf("add_key\n");
				parcBuffer_Display(add_key, 0);
				printf("del_key\n");
				parcBuffer_Display(del_key, 0);
				printf("dereg_key\n");
				parcBuffer_Display(dereg_key, 0);
#endif

				PARCBuffer *payload_key_clone = parcBuffer_Copy(get_key);
#ifdef LOG_CHECK
				printf("payload_key_clone\n");
				parcBuffer_Display(payload_key_clone, 0);
#endif
				PARCBuffer *payload_key_clone_size = parcBuffer_Copy(get_key);
#ifdef LOG_CHECK
				printf("payload_key_clone_size\n");
				parcBuffer_Display(payload_key_clone_size, 0);
#endif

				parcBuffer_Mark(payload_key_clone_size);

#ifdef LOG_CHECK
				printf("Mark of payload_key_clone_size\n");
				parcBuffer_Display(payload_key_clone_size, 0);
#endif
				parcBuffer_Resize(payload_key_clone_size, 4);
#ifdef LOG_CHECK
				printf("Resize of payload_key_clone_size\n");
				parcBuffer_Display(payload_key_clone_size, 0);
#endif
				uint8_t *actual_key_array_size = parcBuffer_ToString(payload_key_clone_size);
#ifdef LOG_CHECK
				for(int i=0; i<4; i++)
					printf("actual_key_array_size = %x\n", actual_key_array_size[i]);

#endif
				int  payload_key_clone_resize_value = actual_key_array_size[3]+4;

#ifdef LOG_CHECK
				printf("payload_key_clone_resize_value= %d\n", payload_key_clone_resize_value);
#endif

				parcBuffer_Mark(payload_key_clone);
#ifdef LOG_CHECK
				printf("Mark of payload_key_clone_size\n");
				parcBuffer_Display(payload_key_clone_size, 0);
#endif

				parcBuffer_Resize(payload_key_clone, payload_key_clone_resize_value);
#ifdef LOG_CHECK
				printf("payload_key_clone\n");
				parcBuffer_Display(payload_key_clone, 0);
#endif
				uint8_t *actual_key_array = parcBuffer_ToString(payload_key_clone);

#ifdef LOG_CHECK


				for(int i=0; i<payload_key_clone_resize_value; i++)
				{
					printf("actual_key_array is reg key: %x\n", actual_key_array[i]);
				}
#endif
				parcBuffer_Release(&payload_key_clone);
				parcBuffer_Release(&payload_key_clone_size);



				// Make a string Name from keyname
				int actual_key_array_name_size=(int)actual_key_array[3]+1;
				char actual_key_array_trans[actual_key_array_name_size];

				actual_key_array_trans[actual_key_array_name_size];

				int k_key=0, n_key=0;
				int actual_key_array_trans_size=0;
				char command_key_array[128];
				int command_key_array_size=0;
				int command_key_array_each_size[128];
				int command_key_array_each_size_i=0;
				int command_key_start_point=4;
				int command_key_actual_array_size=0;

				for(int i=4; i<actual_key_array_name_size+4;i++)
				{
					if(actual_key_array[i]==0x00 && actual_key_array[i+1]==0x01 && actual_key_array[i+2]==0x00)
					{
						actual_key_array_trans[k_key]='/';
#ifdef LOG_CHECK
						printf("actual_key_array_trans: %c\n", actual_key_array_trans[k]);
#endif
						k_key++;
						command_key_start_point= command_key_start_point +4+actual_key_array[i+3];

						for (int j=0; j<actual_key_array[i+3];j++)
						{
							actual_key_array_trans[k_key]=actual_key_array[i+4+j];
#ifdef LOG_CHECK
							printf("actual_key_array_trans: %c\n", actual_key_array_trans[k_key]);
#endif
							k_key++;
							actual_key_array_trans_size++;
						}
						actual_key_array_trans_size++;
					}
					else if(actual_key_array[i]==0x10 && actual_key_array[i+2]==0x00)
					{

						command_key_array[n_key]='/';
#ifdef LOG_CHECK
						printf("command_key_array: %c\n", command_key_array[n]);
#endif
						n_key++;
						command_key_array_each_size[command_key_array_each_size_i]=actual_key_array[i+3];
						command_key_array_each_size_i++;


						for (int j=0; j<actual_key_array[i+3];j++)
						{
							command_key_array[n_key]=actual_key_array[i+4+j];
#ifdef LOG_CHECK
							printf("command_key_array: %c\n", command_key_array[n]);
#endif
							n_key++;
							command_key_array_size++;
						}
						command_key_array_size++;
					}

					else if(actual_key_array[i]==0x00 && actual_key_array[i+1]==0x10 && actual_key_array[i+2]==0x00)
					{
						break;
					}

				}
#ifdef LOG_CHECK
				for(int i=0; i<actual_key_array_trans_size; i++)
				{
					printf("actual_key_array_trans[%d]=%c\n", i, actual_key_array_trans[i]);
				}
#endif
actual_key_array_trans[actual_key_array_trans_size]='\0';


				//extract reg_value name

				PARCBuffer *get_value = NULL;
				PARCBuffer *reg_value = ccnxInterest_GetPayload_reg_value(interest);
				PARCBuffer *add_value = ccnxInterest_GetPayload_add_value(interest);
				PARCBuffer *del_value = ccnxInterest_GetPayload_del_value(interest);
				PARCBuffer *dereg_value = ccnxInterest_GetPayload_dereg_value(interest);

				if(reg_value!=NULL)
				{
					get_value=reg_value;
				}
				else if(add_value!=NULL)
				{
					get_value=add_value;
				}
				else if(del_value!=NULL)
				{
					get_value=del_value;
				}
				else if(dereg_value!=NULL)
				{
					get_value=dereg_value;
				}



#ifdef LOG_CHECK
				printf("reg_value\n");
				parcBuffer_Display(reg_value, 0);
				printf("add_value\n");
				parcBuffer_Display(add_value, 0);
				printf("del_value\n");
				parcBuffer_Display(del_value, 0);
				printf("dereg_value\n");
				parcBuffer_Display(dereg_value, 0);
#endif


				uint8_t *actual_value_array;
				if(reg_value!=NULL|| add_value!=NULL ||del_value!=NULL)
				{


					PARCBuffer *payload_value_clone = parcBuffer_Copy(get_value);
#ifdef LOG_CHECK
					printf("payload_value_clone\n");
					parcBuffer_Display(payload_value_clone, 0);
#endif
					PARCBuffer *payload_value_clone_size = parcBuffer_Copy(get_value);
#ifdef LOG_CHECK
					printf("payload_value_clone_size\n");
					parcBuffer_Display(payload_value_clone_size, 0);
#endif

					parcBuffer_Mark(payload_value_clone_size);

#ifdef LOG_CHECK
					printf("Mark of payload_value_clone_size\n");
					parcBuffer_Display(payload_value_clone_size, 0);
#endif
					parcBuffer_Resize(payload_value_clone_size, 4);

#ifdef LOG_CHECK
					printf("Resize of payload_value_clone_size\n");
					parcBuffer_Display(payload_value_clone_size, 0);
#endif
					uint8_t *actual_value_array_size = parcBuffer_ToString(payload_value_clone_size);

#ifdef LOG_CHECK
					for(int i=0; i<4; i++)
						printf("actual_value_array_size = %x\n", actual_value_array_size[i]);

#endif
					int  payload_value_clone_resize_value = actual_value_array_size[3]+4;

#ifdef LOG_CHECK
					printf("payload_value_clone_resize_value= %d\n", payload_value_clone_resize_value);
#endif

					parcBuffer_Mark(payload_value_clone);
#ifdef LOG_CHECK
					printf("Mark of payload_value_clone_size\n");
					parcBuffer_Display(payload_value_clone_size, 0);
#endif

					parcBuffer_Resize(payload_value_clone, payload_value_clone_resize_value);
#ifdef LOG_CHECK
					printf("payload_value_clone\n");
					parcBuffer_Display(payload_value_clone, 0);
#endif

					actual_value_array = parcBuffer_ToString(payload_value_clone);

#ifdef LOG_CHECK


					for(int i=0; i<payload_value_clone_resize_value; i++)
					{
						printf("actual_value_array is reg value: %x\n", actual_value_array[i]);
					}
#endif
					parcBuffer_Release(&get_value);
					parcBuffer_Release(&payload_value_clone);
					parcBuffer_Release(&payload_value_clone_size);
				}


				// Make a string Name from valuename
				int actual_value_array_name_size=(int)actual_value_array[3];
				char actual_value_array_trans[actual_value_array_name_size+1];
				int k_value = 0, n_value = 0;
				int actual_value_array_trans_size = 0;
				char command_value_array[128];
				int command_value_array_size = 0;
				int command_value_array_each_size[128];
				int command_value_array_each_size_i = 0;
				int command_value_start_point = 4;
				int command_value_actual_array_size = 0;

				for(int i=4; i<actual_value_array_name_size+4;i++)
				{
					if(actual_value_array[i] == 0x00 && actual_value_array[i+1] == 0x01 && actual_value_array[i+2] == 0x00)
					{
						actual_value_array_trans[k_value] = '/';
						k_value++;
						command_value_start_point= command_value_start_point +4+actual_value_array[i+3];

						for (int j=0; j<actual_value_array[i+3];j++)
						{
							actual_value_array_trans[k_value]=actual_value_array[i+4+j];
#ifdef LOG_CHECK
							printf("actual_value_array_trans: %c\n", actual_value_array_trans[k_value]);
#endif
							k_value++;
							actual_value_array_trans_size++;
						}
						actual_value_array_trans_size++;
					}
					else if(actual_value_array[i] == 0x10 && actual_value_array[i+2] == 0x00)
					{

						command_value_array[n_value] = '/';
						n_value++;
						command_value_array_each_size[command_value_array_each_size_i]=actual_value_array[i+3];
						command_value_array_each_size_i++;


						for (int j=0; j<actual_value_array[i+3];j++)
						{
							command_value_array[n_value] = actual_value_array[i+4+j];
							n_value++;
							command_value_array_size++;
						}
						command_value_array_size++;
					}

					else if(actual_value_array[i] == 0x00 && actual_value_array[i+1] == 0x10 && actual_value_array[i+2] == 0x00)
					{
						break;
					}

				}
#ifdef LOG_CHECK
				for(int i=0; i<actual_value_array_trans_size; i++)
				{
					printf("actual_value_array_trans[%d]=%c\n",	i, actual_value_array_trans[i]);
				}
#endif
				actual_value_array_trans[actual_value_array_trans_size]='\0';

				//make value for CO payload using value name 
				char value_hex_name[128];
				int value_hex_name_size = 0;

				//prepare for making  CO

				char actual_key_array_trans_add_domain_str[128]="ccnx:";
				CCNxName *contentobjectName_Reg_Ack = NULL;
				PARCBuffer *payload;

				//prefix check
				char managed_prefix[]="/kr/etri/";
				char managed_prefix_size=sizeof(managed_prefix) - 1;// ignore NULL

				//check domain
				int result_MS2 = 1;

				char *db_value_length_check;
				int db_value_length = 0;

				if(!strncmp(actual_key_array_trans, managed_prefix, managed_prefix_size))
				{
#ifdef LOG_CHECK
					printf("It is under %s domain!\n", managed_prefix);
					printf("managed_prefix= %s, size : %d\n", managed_prefix, managed_prefix_size);
#endif


/***********************Warning**********************************
*	connect and add DBMS e.g., mysql-server 
* 	below code is written by pseudo code
*	So you have to input real code
***************************************************************
*
*#if 1
*					//mydbms is requiredd to init function
*					MYDBMS *connection;
*					MYDBMS *connection_reg;
*end of pseudo code*/
					char query_reg_remove[1024];
					char query_reg[1024];
					char query[1024];
/*************Warning*************************
*					//mydbms resource and row
*					MYDBMS_RES *result;
*					MYDBMS_ROW row;
*					conn = dbms_init(NULL);
*					//connect dbms and checking code
*	if(!mydbms_real_connect(connection, *"host_name","id","passwd","db_name",3306,NULL,0))
*					{
*						// error of dbms
*						fprintf(stderr,"%s\n",dbms_error(conn));
*					}
*					else
*					{
*#ifdef LOG_CHECK
*						printf("mysql_real_connect is success!*\n");
*#endif
*					}
*#ifdef LOG_CHECK
*					printf("actual_key_array_trans:#%s#\n", *actual_key_array_trans);
*#endif
*
*					// query to select name
*					sprintf(query,"SELECT * FROM `db_name` *WHERE `name1` = '%s'", actual_key_array_trans);
*
*
*					// try to query to dbms
*					if(mydbms_query(connection,query))
*					{
*						printf("Write DB error\n");
*					}
*					// result of query
*					result = mydbms_use_result(conn);
*
*					// fetch of low in dbms
*					row = mydbms_fetch_row(result);
*end of pseudo code*/

					if(row != NULL)
					{
#ifdef LOG_CHECK
						printf("%s\n", row[0]);
						printf("%s\n", row[1]);
						printf("%s\n", row[2]);
						printf("%s\n", row[3]);
						printf("%s\n", row[4]);
						printf("%s\n", row[5]);
#endif

					}
					else
					{
						printf("there is not exist\n");
					}


					printf("lookup is finished\n");


/*************Warning*************************
*					// dbms is required to initiation
*					connection_reg = mydbms_init(NULL);
*
*					//dbms connect check
*	if(!mydbms_real_connect(connection_reg, *"host_name","id","passwd","db_name",3306,NULL,0))
*					{
*							// dbms error
*						      printf(stderr,"%s\n",mydbms_error(conn));
*					}
*					else
*					{
*#ifdef LOG_CHECK
*						      printf("mysql_real_connect is *success!\n");
*#endif
*
*					}
*end of pseudo code*/
					//I-reg

					if(reg_key !=NULL)
					{

#ifdef LOG_CHECK
						printf("reg_key !=NULL\n");
#endif
						if(row != NULL)
						{

/*****************Warning*****************
*	delete DBMS 
*****************************************/
*
*							sprintf(query_reg_remove,"DELETE from `db_name` WHERE `db_name`.`name1` = '%s'", actual_key_array_trans);
*
*	// query of dbms						
*	if(dbms_query(connection_reg,query_reg_remove))
*end of pseudo code*/							{
								printf("Write DB error\n");
							}
							else
							{
#ifdef LOG_CHECK
								printf("Key name is already registered in MS1 DB\n");
#endif
							}

						}

/*************Warning*************************
*						// dbms is required to initiation
*						connection_reg = mydbms_init(NULL);
*
*						//connect dbms and check it
*	if(!mydbms_real_connect(connection_reg, "host_name","id","passwd","db_na,e",3306,NULL,0))
*						{
*							// dbms error
*							fprintf(stderr,"%s\n",dbms_error(conn));
*						}
*						else
*						{
*#ifdef LOG_CHECK
*							printf("mysql_real_connect is *success!\n");
*#endif
*
*						}
*end of pseudo code*/

/*****************Warning*****************
*	insert, update DBMS 
*****************************************/
/*						// insert data to dbms
*						sprintf(query_reg,"INSERT INTO `dm_name` (`idx`, `name1`, `name2`, `name3`, `name4`, `name5`) VALUES (NULL, '%s', '%s', '', '', '')", actual_key_array_trans, actual_value_array_trans);
*
*						// query of dbms
*						if(mydbms_query(connection_reg, query_reg))
*						{
*							printf("Write DB error\n");
*						}
*					}
*end of pseudo code*/
					//I-add
					else if(add_key !=NULL)
					{
#ifdef LOG_CHECK
						printf("add_key !=NULL\n");
#endif
						for(int i=2; i<6; i++)
						{
							if(*(row[i])=='\0')
							{
								if(i==2)
								{
#ifdef LOG_CHECK
									printf("row[%d] is NULL, ####%s###\n", i, row[i]);
#endif

/*****************Warning*****************
*	update DBMS 
*****************************************
*								
*	sprintf(query_reg,"UPDATE `db_name` SET `name2` = '%s' WHERE `db_name`.`name1` = '%s'", actual_value_array_trans, actual_key_array_trans);
*end of pseudo code*/								}
								else if(i==3)
								{
#ifdef LOG_CHECK
									printf("row[%d] is NULL, ####%s###\n", i, row[i]);
#endif


/*****************Warning*****************
*	update DBMS 
*****************************************
*								
*	sprintf(query_reg,"UPDATE `db_name` SET `name3` = '%s' WHERE `db_name`.`name1` = '%s'", actual_value_array_trans, actual_key_array_trans);
*end of pseudo code*/								}
								else if(i==4)
								{
#ifdef LOG_CHECK
									printf("row[%d] is NULL, ####%s###\n", i, row[i]);
#endif

/*****************Warning*****************
*	update DBMS 
*****************************************
*								
*	sprintf(query_reg,"UPDATE `db_name` SET `name4` = '%s' WHERE `db_name`.`name1` = '%s'", actual_value_array_trans, actual_key_array_trans);
*end of pseudo code*/
								}
								else if(i==5)
								{
#ifdef LOG_CHECK
									printf("row[%d] is NULL, ####%s###\n", i, row[i]);
#endif

/*****************Warning*****************
*	update DBMS 
*****************************************
*								
*	sprintf(query_reg,"UPDATE `db_name` SET `name5` = '%s' WHERE `db_name`.`name1` = '%s'", actual_value_array_trans, actual_key_array_trans);
*								}
*
*	// query of dbms							
*	if(dbms_query(connection_reg,query_reg))
*end of pseudo code*/								{
									printf("Write DB error\n");
								}
								break;
#ifdef LOG_CHECK
								printf("row[%d] is NULL, ####%s###\n", i, row[i]);
#endif
							}
						}
					}
					//I-del
					else if(del_key !=NULL)
					{
#ifdef LOG_CHECK
						printf("del_key !=NULL\n");
#endif
						for(int i=2; i<6; i++)
						{
							db_value_length_check=row[i];
							db_value_length=0;
							while(db_value_length_check[db_value_length]!='\0')
							{
#ifdef LOG_CHECK
								printf("db_value_length_check[%d]: %c,db_value_length =%d\n", db_value_length, db_value_length_check[db_value_length], db_value_length);
#endif
								db_value_length++;
							}


							if(!strncmp(row[i], actual_value_array_trans,db_value_length) && db_value_length== actual_value_array_trans_size)
							{
								if(i==2)
								{
#ifdef LOG_CHECK
									printf("row[%d]####%s###\n", i, row[i]);
#endif

/*****************Warning*****************
*	update DBMS 
*****************************************
*								
*	sprintf(query_reg,"UPDATE `db_na,e` SET `name2` = '%s' WHERE `db_name`.`name1` = '%s'", "", actual_key_array_trans);
*end of pseudo code*/								}
								else if(i==3)
								{
#ifdef LOG_CHECK
									printf("row[%d]####%s###\n", i, row[i]);
#endif

/*****************Warning*****************
*	update DBMS 
*****************************************
*								
*	sprintf(query_reg,"UPDATE `db_name` SET `name3` = '%s' WHERE `\db_name`.`name1` = '%s'", "", actual_key_array_trans);
*end of pseudo code*/								}
								else if(i==4)
								{
#ifdef LOG_CHECK
									printf("row[%d]####%s###\n", i, row[i]);
#endif

/*****************Warning*****************
*	update DBMS 
*****************************************
*								
*	sprintf(query_reg,"UPDATE `db_name` SET `name4` = '%s' WHERE `db_name`.`name1` = '%s'", "", actual_key_array_trans);
*end of pseudo code*/
								}
								else if(i==5)
								{
#ifdef LOG_CHECK
									printf("row[%d]####%s###\n", i, row[i]);
#endif

/*****************Warning*****************
*	update DBMS 
*****************************************
*								
*	sprintf(query_reg,"UPDATE `db_na,e` SET `name5` = '%s' WHERE `db_name`.`name1` = '%s'", "", actual_key_array_trans);
*								}
*	// query of dbms							
*	if(dbms_query(connection_reg,query_reg))
*end of pseudo code*/								{
									printf("Write DB error\n");
								}
							}
						}


					}
					//I-dereg
					else if(dereg_key !=NULL)
					{
/*****************Warning*****************
*	delete DBMS 
*****************************************
*
*						sprintf(query_reg,"DELETE from `db_name` WHERE `db_name`.`name1` = '%s'", actual_key_array_trans);
*						// query of dbms
*					
*	if(dbms_query(connection_reg,query_reg))
*end of pseudo code*/						{
							printf("Write DB error\n");
						}
					}


#endif



					//make CO payload
					strcat(actual_key_array_trans_add_domain_str, actual_key_array_trans);
					contentobjectName_Reg_Ack= ccnxName_CreateFromCString(actual_key_array_trans_add_domain_str);
					server->generalPayload[0]=0x00;
					server->generalPayload[1]=0x00;
					server->generalPayload[2]=0x00;
					server->generalPayload[3]=0x11;
					server->generalPayload[4]=0x00;
					server->generalPayload[5]=0x01;
					server->generalPayload[6]=0x00;
					server->generalPayload[7]=0x07;
					server->generalPayload[8]='S';
					server->generalPayload[9]='u';
					server->generalPayload[10]='c';
					server->generalPayload[11]='c';
					server->generalPayload[12]='e';
					server->generalPayload[13]='s';
					server->generalPayload[14]='s';
					payload = parcBuffer_Wrap(server->generalPayload, 15, 0, 15);


				}
				else
				{
					//					result_MS2=0;

					//send message to MS2

					//#####################socket
#if 1
					static int option=1;
					//char key_and_value_name_to_MS2[]="/com/google/c1,/GOOGLE/C1";
					char key_and_value_name_to_MS2[actual_key_array_trans_size+actual_value_array_trans_size+1];

					strcpy(key_and_value_name_to_MS2, actual_key_array_trans);
					strcat(key_and_value_name_to_MS2, ",");
					strcat(key_and_value_name_to_MS2, actual_value_array_trans);

					strcat(message_type_to_MS2, ",");
					strncat(message_type_to_MS2, key_and_value_name_to_MS2, sizeof(key_and_value_name_to_MS2));
					message_length_to_MS2=message_length_to_MS2+sizeof(key_and_value_name_to_MS2);


#ifdef LOG_CHECK
					printf("message_type_to_MS2: %s, sizeof(message_type_to_MS2): %d\n", message_type_to_MS2, message_length_to_MS2);
					printf("key_and_value_name_to_MS2 : %s, size: %d\n",key_and_value_name_to_MS2, actual_key_array_trans_size+actual_value_array_trans_size+1);
#endif

					int sock;
					struct sockaddr_in serv_addr;
					int str_len;

					sock = socket(PF_INET, SOCK_STREAM, 0);
					setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
					if(sock == -1)
					{
						printf("In client loop, socket() error\n");
					}
					else
					{
#ifdef LOG_CHECK
						printf("In client loop, socket() success\n");
#endif
					}

					memset(&serv_addr, 0, sizeof(serv_addr));
					serv_addr.sin_family = AF_INET;


					//MS2 or DNS IP address  from name.txt
					FILE *fp_root_ip;
					fp_root_ip = fopen("./ccnxMS-Server/config/NRS_IP.txt","r");
					char root_ip[256];
					fscanf(fp_root_ip, "%s", root_ip);

					int root_ip_length=0;
					while(root_ip[root_ip_length] != '\0')
					{
						root_ip_length++;
					}
					fclose(fp_root_ip);
#ifdef LOG_CHECK
					printf("fetch root ip addr. from NRS_IP.txt: %s, size: %d\n", root_ip, root_ip_length);
#endif

					//serv_addr.sin_addr.s_addr = inet_addr("192.168.33.37");
					//serv_addr.sin_addr.s_addr = inet_addr("10.217.11.68");
					//serv_addr.sin_addr.s_addr = inet_addr("10.217.8.171");
					//serv_addr.sin_addr.s_addr = inet_addr("192.168.33.216");
					//serv_addr.sin_addr.s_addr = inet_addr("192.168.33.220");
					//serv_addr.sin_addr.s_addr = inet_addr("192.168.33.163");
					serv_addr.sin_addr.s_addr = inet_addr(root_ip);
					//serv_addr.sin_addr.s_addr = inet_addr(MS2_ip);
					serv_addr.sin_port = htons(12345);

					if(connect(sock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) == -1)
					{
						printf("In client loop, connect() error\n");
					}
					else
					{
#ifdef LOG_CHECK
						printf("In client loop, connect() success\n");
#endif
					}



					write(sock,message_type_to_MS2, message_length_to_MS2);
					close(sock);
#endif

#if 1
					int serv_sock;
					int clnt_sock;
					struct sockaddr_in serv_addr1;
					int clnt_addr_size;
					struct sockaddr_in clnt_addr;
					char message[50];

					serv_sock = socket(PF_INET, SOCK_STREAM, 0);

					setsockopt(serv_sock, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
					if(serv_sock == -1)
					{
						printf("In server loop, socket() error\n");
					}
					else
					{
#ifdef LOG_CHECK
						printf("In server loop, socket() success\n");
#endif
					}

					memset(&serv_addr1, 0, sizeof(serv_addr1));
					serv_addr1.sin_family = AF_INET;

					serv_addr1.sin_addr.s_addr = htonl(INADDR_ANY);
					serv_addr1.sin_port = htons(12346);


					if(bind(serv_sock, (struct sockaddr *) &serv_addr1, sizeof(serv_addr1)) == -1)
					{
						printf("In server loop, bind() error\n");
					}
					else
					{
#ifdef LOG_CHECK
						printf("In server loop, bind() success\n");
#endif

					}



					if(listen(serv_sock, 5) == -1)
					{
						printf("In server loop, listen() error\n");
					}
					else
					{
#ifdef LOG_CHECK
						printf("In server loop, listen() success\n");
#endif
					}

					clnt_addr_size = sizeof(clnt_addr);


					clnt_sock = accept(serv_sock, (struct sockaddr *) &clnt_addr, &clnt_addr_size);
					if(clnt_sock == -1)
					{
						printf("In server loop, accept() error\n");
					}
					else
					{
#ifdef LOG_CHECK
						printf("In server loop, accept() success\n");
#endif
					}

					str_len=read(clnt_sock,message,sizeof(message)-1);

					if(str_len==-1)
					{
						printf("in server loop, read() error\n");
					}
					else
					{
#ifdef LOG_CHECK
						printf("In server loop, read() success\n");
#endif
					}


					message[str_len]=0;


					close(clnt_sock);
					close(serv_sock);

#endif


#ifdef LOG_CHECK
					printf("received message from MS2, %s\n ", message);
#endif

					if(!strncmp(message,"reg-Success", 11) || !strncmp(message,"add-Success", 11) || !strncmp(message,"del-Success", 11) || !strncmp(message,"dereg-Success", 13))
					{

						strcat(actual_key_array_trans_add_domain_str, actual_key_array_trans);
						contentobjectName_Reg_Ack= ccnxName_CreateFromCString(actual_key_array_trans_add_domain_str);

						server->generalPayload[0]=0x00;
						server->generalPayload[1]=0x00;
						server->generalPayload[2]=0x00;
						server->generalPayload[3]=0x11;
						server->generalPayload[4]=0x00;
						server->generalPayload[5]=0x01;
						server->generalPayload[6]=0x00;
						server->generalPayload[7]=0x07;
						server->generalPayload[8]='S';
						server->generalPayload[9]='u';
						server->generalPayload[10]='c';
						server->generalPayload[11]='c';
						server->generalPayload[12]='e';
						server->generalPayload[13]='s';
						server->generalPayload[14]='s';
						payload = parcBuffer_Wrap(server->generalPayload, 15, 0, 15);
					}
					else
					{
						printf("It is not under %s domain!\n", managed_prefix);
						strcat(actual_key_array_trans_add_domain_str, actual_key_array_trans);
						actual_key_array_trans_add_domain_str[5+actual_key_array_trans_size];
						contentobjectName_Reg_Ack= ccnxName_CreateFromCString(actual_key_array_trans_add_domain_str);


#ifdef LOG_CHECK
						printf("actual_key_array_trans_add_domain_str[18]= %x\n", actual_key_array_trans_add_domain_str[18]);
						printf("actual_key_array_trans_add_domain_str: %s, size: %ld\n", actual_key_array_trans_add_domain_str, sizeof(actual_key_array_trans_add_domain_str));
						ccnxName_Display(contentobjectName_Reg_Ack, 0);
#endif


						server->generalPayload[0]=0x00;
						server->generalPayload[1]=0x00;
						server->generalPayload[2]=0x00;
						server->generalPayload[3]=0x08;
						server->generalPayload[4]=0x00;
						server->generalPayload[5]=0x01;
						server->generalPayload[6]=0x00;
						server->generalPayload[7]=0x04;
						server->generalPayload[8]='F';
						server->generalPayload[9]='a';
						server->generalPayload[10]='i';
						server->generalPayload[11]='l';

						payload = parcBuffer_Wrap(server->generalPayload, 12, 0, 12);
#ifdef LOG_CHECK
						parcBuffer_Display(payload, 0);
#endif
					}

				}
				CCNxContentObject *contentObject;
				if(reg_key !=NULL)
				{
					contentObject = ccnxContentObject_CreateWithNameAndPayload_reg_ack(contentobjectName_Reg_Ack, payload);
				}
				else if(add_key !=NULL)
				{
					contentObject = ccnxContentObject_CreateWithNameAndPayload_add_ack(contentobjectName_Reg_Ack, payload);
				}
				else if(del_key !=NULL)
				{
					contentObject = ccnxContentObject_CreateWithNameAndPayload_del_ack(contentobjectName_Reg_Ack, payload);
				}
				else if(dereg_key !=NULL)
				{
					contentObject = ccnxContentObject_CreateWithNameAndPayload_dereg_ack(contentobjectName_Reg_Ack, payload);
				}

				//send CO message

				CCNxMetaMessage *message = ccnxMetaMessage_CreateFromContentObject(contentObject);

				if (ccnxPortal_Send(server->portal, message, CCNxStackTimeout_Never) == false) {
					fprintf(stderr, "ccnxPortal_Send failed: %d\n", ccnxPortal_GetError(server->portal));
				}

				ccnxMetaMessage_Release(&message);
				parcBuffer_Release(&payload);
				}
			}
		}
	}
}

/**
 * Display the usage message.
 */
	static void
_displayUsage(char *progName)
{
	printf("CCNx Simple NRS Performance Test\n");
	printf("\n");
	printf("Usage: %s [-l locator] [-s size] \n", progName);
	printf("       %s -h\n", progName);
	printf("\n");
	printf("Example:\n");
	printf("    ccnxNRS_Server -l ccnx:/some/prefix -s 4096\n");
	printf("\n");
	printf("Options:\n");
	printf("     -h (--help) Show this help message\n");
	printf("     -l (--locator) Set the locator for this server. The default is 'ccnx:/locator'. \n");
	printf("     -s (--size) Set the payload size (less than 64000 - see `ccnxPing_MaxPayloadSize` in ccnxPing_Common.h)\n");
}

/**
 * Parse the command lines to initialize the state of the
 */
	static bool
_ccnxNRSServer_ParseCommandline(CCNxNRSServer *server, int argc, char *argv[argc])
{
	static struct option longopts[] = {
		{ "locator", required_argument, NULL, 'l' },
		{ "size",    required_argument, NULL, 's' },
		{ "help",    no_argument,       NULL, 'h' },
		{ NULL,      0,                 NULL, 0   }
	};

	// Default value
	server->payloadSize = ccnxNRS_MaxPayloadSize;

	int c;
	while ((c = getopt_long(argc, argv, "l:s:h", longopts, NULL)) != -1) {
		switch (c) {
			case 'l':
				server->prefix = ccnxName_CreateFromCString(optarg);
				break;
			case 's':
				sscanf(optarg, "%zu", &(server->payloadSize));
				if (server->payloadSize > ccnxNRS_MaxPayloadSize) {
					_displayUsage(argv[0]);
					return false;
				}
				break;
			case 'h':
				_displayUsage(argv[0]);
				return false;
			default:
				break;
		}
	}

	return true;
};

	int
main(int argc, char *argv[argc])
{
	parcSecurity_Init();

	CCNxNRSServer *server = ccnxNRSServer_Create();
	bool runServer = _ccnxNRSServer_ParseCommandline(server, argc, argv);

	if (runServer) {
		_ccnxNRSServer_Run(server);
	}

	ccnxNRSServer_Release(&server);

	parcSecurity_Fini();

	return EXIT_SUCCESS;
}
