# Name Resolution Service on CICN (CICN-NRS) 

This project is on a Name Resolution Service (NRS) in ICN. It is implemented on CICN which is one of the fd.io projects and named as CICN-NRS in this document.
- https://wiki.fd.io/view/Cicn
- https://github.com/FDio/cicn

## NRS in ICN

The Name Resolution Service (NRS) in ICN is defined as the service that provides the name resolution function translating an object name into some other information such as locator and another name that is used for forwarding the object request. In other words, the NRS is the service that shall be provided by ICN infrastructure to help a consumer to reach a specific piece of content, service, or host using a persistent name when the name resolution is needed.
(https://datatracker.ietf.org/doc/draft-irtf-icnrg-nrs-requirements/)

## CICN-NRS description

Mapping Server (MS) is defined as a key component in this project which is to process all the messages for name registration and name lookup in NRS. MS stores and maintains the actual mapping table which keeps the bindings of name to some information which is used for forwarding Interest packet in CCNx. 

This project provides the following functions:
- Name registration by Interest/ContentObject
- Name lookup by Interest/ContentObject
- Interest forwarding with two names; original name and resolved name

The followings in CICN sub projects are used in this project and the source codes are amended in order to make the NRS messages work properly in CCNx:
- cframework : C framework
- ccnxlibs : CCNx libraries 
- libicnet : socket API
- sb-forwarder : socket-based forwarder 
  
The amended parts are described in the file, 'Describtion for amend'.                      

The followings are new sub projects in CICN-NRS:
- ccnxMS-Server : mapping server 
- ccnxReg-Client : client for name registration
- ccnxSimpleFileTransfer : application for name lookup test

For more information, https://datatracker.ietf.org/doc/draft-hong-icnrg-ccnx-nrs/

### NOTICE 1

Mapping table in MS is implemented using mysql which is under GPL license.
Since this project, CICN-NRS is distributed under Apache 2 license, the source codes using mysql are excluded.

It is required to make a program for the mapping table according to 
the comments in lines in ccnxMS-Server/ccnxReg_Server.c in order to make it work properly. Please contact us if you have any question on this. 

### NOTICE 2

"file_path" should be changed according to the 'CICN-NRS' installing when  'fopen()' function is used in 
sb-forwarder/metis/ccnx/forwarder/metis/processor/metis_MessageProcessor.c.
