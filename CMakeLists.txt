cmake_minimum_required (VERSION 3.2)
project (Simple-WebSocket-Server)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall")
option(USE_SSL "Uses OpenSSL" OFF)
option(BUILD_EXAMPLES "Compiles also the examples" ON)

#if windows is used, use cppan. the dependencies are declared in cppan.yml
if (WIN32)
	MESSAGE(STATUS "Entering Win32 Mode")
	add_subdirectory(cppan)
	SET(DEP_LIBS pvt.cppan.demo.boost.system
  pvt.cppan.demo.boost.coroutine
  pvt.cppan.demo.boost.context
  pvt.cppan.demo.boost.thread
  pvt.cppan.demo.boost.asio
  pvt.cppan.demo.openssl.crypto
  pvt.cppan.demo.openssl.ssl)
	MESSAGE(STATUS "DEP_LIBS: ${DEP_LIBS}")

ELSE()
	set(BOOST_COMPONENTS system coroutine context thread)
	# Late 2017 TODO: remove the following checks and always use std::regex
	if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
	    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 4.9)
	        set(BOOST_COMPONENTS ${BOOST_COMPONENTS} regex)
	        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DUSE_BOOST_REGEX")
	    endif()
	endif()

	find_package(Boost 1.54.0 COMPONENTS ${BOOST_COMPONENTS} REQUIRED)
	include_directories(SYSTEM ${Boost_INCLUDE_DIR})

	if(APPLE)
	  set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl")
	endif()

	if(USE_SSL)
		find_package(OpenSSL REQUIRED)
		MESSAGE(STATUS "OPENSSL: ${OPENSSL_LIBRARIES}")
		include_directories(${OPENSSL_INCLUDE_DIR})
		add_definitions(-DUSE_SSL)
	ENDIF(USE_SSL)
	
	SET(DEP_LIBS ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES} ${OPENSSL_CRYPTO_LIBRARY} ${CMAKE_THREAD_LIBS_INIT})
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wextra")

ENDIF()

find_package(Threads REQUIRED)


include_directories(.)

IF(BUILD_EXAMPLES)
	add_executable(ws_examples ws_examples.cpp)
	target_link_libraries(ws_examples ${CMAKE_THREAD_LIBS_INIT} ${DEP_LIBS})
ENDIF(BUILD_EXAMPLES)

if(USE_SSL)
	add_executable(wss_examples wss_examples.cpp)
	target_link_libraries(wss_examples ${CMAKE_THREAD_LIBS_INIT} ${DEP_LIBS})
endif(USE_SSL)

if(MSYS)
    target_link_libraries(ws_examples ws2_32 wsock32)
    if(USE_SSL)
    	target_link_libraries(wss_examples ws2_32 wsock32)
    endif(USE_SSL)
endif()

enable_testing()
add_subdirectory(tests)
