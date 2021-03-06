cmake_minimum_required(VERSION 3.2)

project(Metis)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

if (NOT CMAKE_BUILD_TYPE)
    message(STATUS "No build type selected, default to Release")
    set(CMAKE_BUILD_TYPE "Release")
endif ()

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

if( UNIX )
  link_libraries(m)
endif( UNIX )

include( CTest )
include( version )
include( detectCacheSize )

if(ANDROID_API)
    message("############ Detected cross compile for $ENV{CMAKE_SYSTEM_NAME}")
    message("############ This build will not include doxygen, tools, or tests")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${ANDROID_C_FLAGS} -Wall")
else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
endif()

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} ${CMAKE_C_FLAGS}")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} ${CMAKE_C_FLAGS}")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO} ${CMAKE_C_FLAGS}")
set(CMAKE_C_FLAGS_MINSIZEREL "${CMAKE_C_FLAGS_MINSIZEREL} ${CMAKE_C_FLAGS}")

include_directories(${PROJECT_SOURCE_DIR} ${PROJECT_BINARY_DIR}/ccnx/forwarder/metis)

include_directories($ENV{CCNX_DEPENDENCIES}/include)
set(OPENSSL_ROOT_DIR $ENV{CCNX_DEPENDENCIES})

if(COMPILE_FOR_IOS)
  include_directories(iOS)
  find_host_package( LongBow REQUIRED )
  include_directories(${LONGBOW_INCLUDE_DIRS})

  find_host_package( LibEvent REQUIRED )
  include_directories(${LIBEVENT_INCLUDE_DIRS})

  find_host_package( Libparc REQUIRED )
  include_directories(${LIBPARC_INCLUDE_DIRS})

  find_host_package( CCNX_Common REQUIRED )
  include_directories(${CCNX_COMMON_INCLUDE_DIRS})

  find_host_package( CCNX_Transport_Rta REQUIRED )
  include_directories(${CCNX_TRANSPORT_RTA_INCLUDE_DIRS})

  find_host_package( CCNX_Portal REQUIRED )
  include_directories(${CCNX_PORTAL_INCLUDE_DIRS})

  find_host_package ( OpenSSL REQUIRED )

  find_host_package( Doxygen )
else()
  find_package( LongBow REQUIRED )
  include_directories(${LONGBOW_INCLUDE_DIRS})

  find_package( LibEvent REQUIRED )
  include_directories(${LIBEVENT_INCLUDE_DIRS})

  find_package( Libparc REQUIRED )
  include_directories(${LIBPARC_INCLUDE_DIRS})

  find_package( CCNX_Common REQUIRED )
  include_directories(${CCNX_COMMON_INCLUDE_DIRS})

  find_package( CCNX_Transport_Rta REQUIRED )
  include_directories(${CCNX_TRANSPORT_RTA_INCLUDE_DIRS})

  find_package( CCNX_Portal REQUIRED )
  include_directories(${CCNX_PORTAL_INCLUDE_DIRS})

  find_package ( Threads REQUIRED )

  find_package ( OpenSSL REQUIRED )

  find_package( Doxygen )
endif()

set(METIS_LINK_LIBRARIES
  metis
  ${LONGBOW_LIBRARIES}
  ${LIBEVENT_LIBRARIES}
  ${OPENSSL_LIBRARIES}
  ${CMAKE_THREAD_LIBS_INIT}
  ${CCNX_PORTAL_LIBRARIES}
  ${CCNX_TRANSPORT_RTA_LIBRARIES}
  ${CCNX_COMMON_LIBRARIES}
  ${LIBPARC_LIBRARIES}
  )

set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")

if (ANDROID_API)
    macro(AddTest testFile)
        message("Android build: Skipping test ${ARGV0}")
    endmacro(AddTest)
elseif(COMPILE_FOR_IOS)
    macro(AddTest testFile)
        message("iOS build: Skipping test ${ARGV0}")
    endmacro(AddTest)
else()
   macro(AddTest testFile)
     add_executable(${ARGV0} ${ARGV0}.c)
     target_link_libraries(${ARGV0} ${METIS_LINK_LIBRARIES})
     add_test(${ARGV0} ${ARGV0})
     set_target_properties(${ARGV0} PROPERTIES FOLDER Test)
   endmacro(AddTest)
endif()

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "AppleClang" OR COMPILE_FOR_IOS )
    set(CMAKE_SHARED_LIBRARY_CREATE_C_FLAGS "${CMAKE_SHARED_LIBRARY_CREATE_C_FLAGS} -undefined dynamic_lookup")
	message( "-- Set \"-undefined dynamic_lookup\" for shared libraries")
endif()

add_subdirectory(ccnx/forwarder/metis)

# Generate DEB / RPM packages

option(DEB_PACKAGE "Create deb package" OFF)
option(RPM_PACKAGE "Create deb package" OFF)

set(VENDOR "Cisco Systems" CACHE STRING "Vendor")
set(CONTACT "msardara@cisco.com" CACHE STRING "Contact")
set(DISTRIBUTION "xenial" CACHE STRING "Distribution")
set(ARCHITECTURE "amd64" CACHE STRING "Architecture")
set(PACKAGE_MAINTAINER "Mauro Sardara (msardara@cisco.com)" CACHE STRING "Maintainer")
set(BUILD_NUMBER "1" CACHE STRING "Build Number")
string(TOLOWER ${CMAKE_PROJECT_NAME}-forwarder PACKAGE_NAME)

set(CPACK_PACKAGING_INSTALL_PREFIX "/usr")
set(CPACK_PACKAGE_VENDOR ${VENDOR})
set(CPACK_PACKAGE_CONTACT ${CONTACT})

# Get the version
execute_process(COMMAND bash ${CMAKE_SOURCE_DIR}/scripts/version
                OUTPUT_VARIABLE PACKAGE_VERSION)
string(STRIP ${PACKAGE_VERSION} PACKAGE_VERSION)

if(DEB_PACKAGE)
    set(TYPE "DEBIAN")
    set(GENERATOR "DEB")
    set(CPACK_PACKAGE_FILE_NAME "${PACKAGE_NAME}_${PACKAGE_VERSION}_${ARCHITECTURE}")
    set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
    set(CPACK_${TYPE}_PACKAGE_DEPENDS "longbow (>= 1.0), libparc (>= 1.0), libccnx-common (>= 1.0), libccnx-transport-rta (>= 1.0), libccnx-portal (>= 1.0)")
elseif(RPM_PACKAGE)
    set(TYPE "RPM")
    set(GENERATOR "RPM")
    set(CPACK_PACKAGE_FILE_NAME "${PACKAGE_NAME}-${PACKAGE_VERSION}.${ARCHITECTURE}")
    set(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "/usr/etc" "/usr/lib/python2.7" "/usr/lib/python2.7/site-packages" "/lib/systemd/system" "/lib" "/lib/systemd")
    set(CPACK_${TYPE}_PACKAGE_AUTOREQ ON)
    set(CPACK_${TYPE}_PACKAGE_REQUIRES "longbow >= 1.0, libparc >= 1.0, libccnx-common >= 1.0, libccnx-transport-rta >= 1.0, libccnx-portal >= 1.0")
else()
    return()
endif()

# Install also configuration files
set (METIS_CONFIG ${PROJECT_SOURCE_DIR}/config/ccnx_metis.conf)
set (METIS_SERVICE ${PROJECT_SOURCE_DIR}/config/metis-forwarder.service)

install(FILES ${METIS_CONFIG} DESTINATION /etc/ccnx)
install(FILES ${METIS_SERVICE} DESTINATION /lib/systemd/system)

set(CPACK_GENERATOR ${GENERATOR})
set(CPACK_${TYPE}_PACKAGE_MAINTAINER ${PACKAGE_MAINTAINER})
set(CPACK_${TYPE}_PACKAGE_NAME ${PACKAGE_NAME})
set(CPACK_${TYPE}_PACKAGE_VERSION ${PACKAGE_VERSION})
set(CPACK_${TYPE}_PACKAGE_ARCHITECTURE ${ARCHITECTURE})
set(CPACK_${TYPE}_PACKAGE_RELEASE 1)
set(CPACK_${TYPE}_PACKAGE_VENDOR ${VENDOR})
set(CPACK_${TYPE}_PACKAGE_DESCRIPTION "Metis is a CCNx socket based forwarder")
set(CPACK_${TYPE}_PACKAGE_HOMEPAGE "https://wiki.fd.io/view/Sb-forwarder")

include(CPack)
