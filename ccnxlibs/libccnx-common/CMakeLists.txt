cmake_minimum_required(VERSION 3.2)
project(Libccnx-common)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

if( UNIX )
  link_libraries(m)
endif( UNIX )

include( CTest )
include( version )
include( detectCacheSize )

if(ANDROID_API)
    message("############ Detected cross compile for ${CMAKE_SYSTEM_NAME}")
    message("############ This build will not include doxygen, tools, or tests")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${ANDROID_C_FLAGS} -Wall")
else()
    # set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -DNDEBUG -DLibccnx_DISABLE_VALIDATION")
endif()

#set(CMAKE_C_FLAGS_NOPANTS "${CMAKE_C_FLAGS_NOPANTS} -O3 -DNDEBUG -DLibccnx_DISABLE_VALIDATION")

include_directories(${PROJECT_SOURCE_DIR} ${PROJECT_BINARY_DIR}/ccnx/common)

include_directories($ENV{CCNX_DEPENDENCIES}/include)
set(OPENSSL_ROOT_DIR $ENV{CCNX_DEPENDENCIES})

find_package( LongBow REQUIRED )
include_directories(${LONGBOW_INCLUDE_DIRS})

find_package( LibEvent REQUIRED )
include_directories(${LIBEVENT_INCLUDE_DIRS})

find_package( Libparc REQUIRED )
include_directories(${LIBPARC_INCLUDE_DIRS})

find_package ( Threads REQUIRED )

find_package ( OpenSSL REQUIRED )

find_package( Doxygen )

add_custom_target(${PROJECT_NAME}_cleanup_profiling_data
        "find" "." "-name" "*.gcda" "-delete"
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Cleanup previous profiling data.")

if (ANDROID_API) 
    macro(AddTest testFile)
        message("Android build: Skipping test ${ARGV0}")
    endmacro(AddTest)
else()
    macro(AddTest testFile)
      add_executable(${ARGV0} ${ARGV0}.c)
      target_link_libraries(${ARGV0} ${LONGBOW_LIBRARIES})
      target_link_libraries(${ARGV0} ccnx_common)
      target_link_libraries(${ARGV0} ${LIBEVENT_LIBRARIES})
      target_link_libraries(${ARGV0} ${LIBPARC_LIBRARIES})
      target_link_libraries(${ARGV0} ${OPENSSL_LIBRARIES})
      target_link_libraries(${ARGV0} ${CMAKE_THREAD_LIBS_INIT})
      add_test(${ARGV0} ${ARGV0})
      set_target_properties(${ARGV0} PROPERTIES FOLDER Test)
      add_dependencies(${ARGV0} ${PROJECT_NAME}_cleanup_profiling_data)
    endmacro(AddTest)
endif()

add_subdirectory(ccnx/common)
add_subdirectory(documentation)

# Generate DEB / RPM packages

option(DEB_PACKAGE "Create deb package" OFF)
option(RPM_PACKAGE "Create deb package" OFF)

SET(VENDOR "Cisco Systems" CACHE STRING "Vendor")
SET(CONTACT "msardara@cisco.com" CACHE STRING "Contact")
SET(DISTRIBUTION "xenial" CACHE STRING "Distribution")
SET(ARCHITECTURE "amd64" CACHE STRING "Architecture")
SET(PACKAGE_MAINTAINER "Mauro Sardara (msardara@cisco.com)" CACHE STRING "Maintainer")
SET(BUILD_NUMBER "1" CACHE STRING "Build Number")
STRING(TOLOWER ${CMAKE_PROJECT_NAME} PACKAGE_NAME)

SET(CPACK_PACKAGING_INSTALL_PREFIX "/usr")
SET(CPACK_PACKAGE_VENDOR ${VENDOR})
SET(CPACK_PACKAGE_CONTACT ${CONTACT})

# Get the version
execute_process(COMMAND bash ${CMAKE_SOURCE_DIR}/scripts/version
                OUTPUT_VARIABLE PACKAGE_VERSION)
string(STRIP ${PACKAGE_VERSION} PACKAGE_VERSION)

if(DEB_PACKAGE)
    SET(TYPE "DEBIAN")
    SET(GENERATOR "DEB")
    SET(CPACK_PACKAGE_FILE_NAME "${PACKAGE_NAME}_${PACKAGE_VERSION}_${ARCHITECTURE}")
    SET(CPACK_${TYPE}_PACKAGE_DEPENDS "longbow (>= 1.0), libevent-2.0-5, libssl1.0.0, libparc (>= 1.0)")
elseif(RPM_PACKAGE)
    SET(TYPE "RPM")
    SET(GENERATOR "RPM")
    SET(CPACK_PACKAGE_FILE_NAME "${PACKAGE_NAME}-${PACKAGE_VERSION}.${ARCHITECTURE}")
    SET(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "/usr/etc" "/usr/lib/python2.7" "/usr/lib/python2.7/site-packages")
    SET(CPACK_${TYPE}_PACKAGE_REQUIRES "longbow >= 1.0, libevent >= 2.0, openssl >= 1.0, libparc >= 1.0")
else()
    RETURN()
endif()

SET(CPACK_GENERATOR ${GENERATOR})
SET(CPACK_${TYPE}_PACKAGE_MAINTAINER ${PACKAGE_MAINTAINER})
SET(CPACK_${TYPE}_PACKAGE_NAME ${PACKAGE_NAME})
SET(CPACK_${TYPE}_PACKAGE_VERSION ${PACKAGE_VERSION})
SET(CPACK_${TYPE}_PACKAGE_ARCHITECTURE ${ARCHITECTURE})
SET(CPACK_${TYPE}_PACKAGE_RELEASE 1)
SET(CPACK_${TYPE}_PACKAGE_VENDOR ${VENDOR})
SET(CPACK_${TYPE}_PACKAGE_DESCRIPTION "The CCNx Common library is a set of functions and data structures for CCNx.")
SET(CPACK_${TYPE}_PACKAGE_HOMEPAGE "https://wiki.fd.io/view/Ccnxlib")

INCLUDE(CPack)
