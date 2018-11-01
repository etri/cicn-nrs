cmake_minimum_required(VERSION 3.2)
project(ccnxSimpleFileTransfer)
include( CTest)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

include_directories($ENV{CCNX_HOME}/include)
set(OPENSSL_ROOT_DIR $ENV{CCNX_DEPENDENCIES})

find_package ( Threads REQUIRED )

find_package ( OpenSSL REQUIRED )

link_directories($ENV{CCNX_HOME}/lib)

set(TUTORIAL_LIBRARIES
       ccnx_common
       ccnx_api_portal
       ccnx_api_notify 
       ccnx_transport_rta 
       ccnx_api_control 
       ccnx_common
       parc 
       longbow 
       longbow-ansiterm)

set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")

add_executable(ccnxSimpleFileTransfer_Server
               ccnxSimpleFileTransfer_Server.c
               ccnxSimpleFileTransfer_Common.c
               ccnxSimpleFileTransfer_ChunkList.c
               ccnxSimpleFileTransfer_FileIO.c)
    
add_executable(ccnxSimpleFileTransfer_Client 
               ccnxSimpleFileTransfer_Client.c
               ccnxSimpleFileTransfer_Common.c
               ccnxSimpleFileTransfer_FileIO.c)

target_link_libraries(ccnxSimpleFileTransfer_Client ${TUTORIAL_LIBRARIES})
target_link_libraries(ccnxSimpleFileTransfer_Server ${TUTORIAL_LIBRARIES})

install(TARGETS ccnxSimpleFileTransfer_Client RUNTIME DESTINATION bin)
install(TARGETS ccnxSimpleFileTransfer_Server RUNTIME DESTINATION bin)

add_subdirectory(test)

