cmake_minimum_required (VERSION 2.8)
project (Simple-WebSocket-Sample)
get_filename_component(SAMPLE_ROOT ${CMAKE_CURRENT_LIST_FILE} DIRECTORY)

if(MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4 /WX")
elseif(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -Wextra -Wsign-conversion")
endif()



set(BOOST_COMPONENTS system coroutine context thread)
# Late 2017 TODO: remove the following checks and always use std::regex
if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 4.9)
        set(BOOST_COMPONENTS ${BOOST_COMPONENTS} regex)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DUSE_BOOST_REGEX")
    endif()
endif()

if (WIN32)

    # prereq: populate $env:BoostRoot and $env:BoostVer to tell cmake where boost is
    set(BOOST_ROOT "$ENV{BoostRoot}")
    set(BOOST_LIBRARYDIR "$ENV{BoostRoot}/lib")
    set(BOOST_INCLUDEDIR "$ENV{BoostRoot}/include/boost-$ENV{SkyBoostVer}")
    add_definitions(-DBOOST_ALL_DYN_LINK)
    set(BOOST_COMPONENTS ${BOOST_COMPONENTS} regex)

    file(GLOB boostDlls "$ENV{BoostRoot}/lib/*.dll")
    foreach(boostDll ${boostDlls})
       file(TO_CMAKE_PATH "${boostDll}" correctedBoostDll)
           get_filename_component(boostFileName ${correctedBoostDll} NAME)
           if(boostFileName MATCHES ".*boost_(chrono|system|regex|system|thread|coroutine|context).*\\.dll$")
               configure_file( "${correctedBoostDll}" "${CMAKE_BINARY_DIR}" COPYONLY)
          endif()
    endforeach()

    # prereq: populate $env:OpenSSLRoot to tell cmake where OpenSSL is
    set(OPENSSL_ROOT_DIR "$ENV{OpenSSLRoot}")
    set(OPENSSL_INCLUDE_DIR "$ENV{OpenSSLRoot}/include")

endif()

find_package(Boost 1.54.0 COMPONENTS ${BOOST_COMPONENTS} REQUIRED)
include_directories(SYSTEM ${Boost_INCLUDE_DIR})
include_directories(SYSTEM ${Boost_INCLUDE_DIR})

if(APPLE)
  set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl")
endif()

#TODO: add requirement for version 1.0.1g (can it be done in one line?)
find_package(OpenSSL REQUIRED)
include_directories(SYSTEM ${OPENSSL_INCLUDE_DIR})

find_package(Threads REQUIRED)

include_directories(.)

include_directories("${SAMPLE_ROOT}/..")


add_executable(sample_client sample_client.cpp)
set_target_properties(sample_client PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(sample_client ${Boost_LIBRARIES})
target_link_libraries(sample_client ${OPENSSL_CRYPTO_LIBRARY})
target_link_libraries(sample_client ${CMAKE_THREAD_LIBS_INIT})

add_executable(sample_server sample_server.cpp)
set_target_properties(sample_server PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(sample_server ${Boost_LIBRARIES})
target_link_libraries(sample_server ${OPENSSL_LIBRARIES})
target_link_libraries(sample_server ${CMAKE_THREAD_LIBS_INIT})

add_executable(ws_examples ../ws_examples.cpp)
target_link_libraries(ws_examples ${Boost_LIBRARIES})
target_link_libraries(ws_examples ${OPENSSL_CRYPTO_LIBRARY})
target_link_libraries(ws_examples ${CMAKE_THREAD_LIBS_INIT})

add_executable(wss_examples ../wss_examples.cpp)
target_link_libraries(wss_examples ${Boost_LIBRARIES})
target_link_libraries(wss_examples ${OPENSSL_LIBRARIES})
target_link_libraries(wss_examples ${CMAKE_THREAD_LIBS_INIT})

if(MSYS)
    target_link_libraries(sample_client ws2_32 wsock32)
    target_link_libraries(sample_server ws2_32 wsock32)
    target_link_libraries(ws_examples ws2_32 wsock32)
    target_link_libraries(wss_examples ws2_32 wsock32)
endif()
