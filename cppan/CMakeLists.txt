#
# cppan
#

################################################################################
#
# header
#
################################################################################

include(C:/Users/funk_eu/.cppan/storage/etc/static/header.cmake)

cppan_debug_message("Entering file: ${CMAKE_CURRENT_LIST_FILE}")

################################################################################

#
# cppan
# meta config file
#

set(CPPAN_DEBUG_STACK_SPACE "" CACHE STRING "" FORCE)

################################################################################
#
# cmake setup
#
################################################################################

cppan_debug_message("Section: cmake setup")

cmake_minimum_required(VERSION 3.2.0)

################################################################################
#
# macros & functions
#
################################################################################

cppan_debug_message("Section: macros & functions")

include(C:/Users/funk_eu/.cppan/storage/etc/static/functions.cmake)
set(SDIR ${CMAKE_CURRENT_SOURCE_DIR})
set(BDIR ${CMAKE_CURRENT_BINARY_DIR})

################################################################################
#
# variables
#
################################################################################

cppan_debug_message("Section: variables")

set(CPPAN_BUILD 1 CACHE STRING "CPPAN is turned on")

################################################################################
#
# storage dirs
#
################################################################################

cppan_debug_message("Section: storage dirs")

set(STORAGE_DIR "C:/Users/funk_eu/.cppan/storage")
set(STORAGE_DIR_ETC "C:/Users/funk_eu/.cppan/storage/etc")
set(STORAGE_DIR_ETC_STATIC "C:/Users/funk_eu/.cppan/storage/etc/static")
set(STORAGE_DIR_USR "C:/Users/funk_eu/.cppan/storage/usr")

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(${CMAKE_CXX_COMPILER_ID} 1)

if (NOT DEFINED CPPAN_USE_CACHE)
    set(CPPAN_USE_CACHE 1)
endif()

if (NOT DEFINED CPPAN_SHOW_IDE_PROJECTS)
    set(CPPAN_SHOW_IDE_PROJECTS 0)
endif()

if (NOT DEFINED CPPAN_BUILD_EXECUTABLES_WITH_SAME_CONFIGURATION)
    set(CPPAN_BUILD_EXECUTABLES_WITH_SAME_CONFIGURATION 0)
endif()

if (NOT DEFINED CPPAN_BUILD_VERBOSE)
    set(CPPAN_BUILD_VERBOSE 1)
endif()

if (NOT DEFINED CPPAN_BUILD_WARNING_LEVEL)
    set(CPPAN_BUILD_WARNING_LEVEL 0)
endif()

get_configuration_variables()

include(helpers.cmake)

################################################################################
#
# direct dependencies
#
################################################################################

cppan_debug_message("Section: direct dependencies")

set(pvt_cppan_demo_boost_asio_DIR C:/Users/funk_eu/.cppan/storage/src/45/94/dadc)
set(pvt_cppan_demo_boost_context_DIR C:/Users/funk_eu/.cppan/storage/src/5a/c9/3e02)
set(pvt_cppan_demo_boost_coroutine_DIR C:/Users/funk_eu/.cppan/storage/src/e6/29/090a)
set(pvt_cppan_demo_boost_system_DIR C:/Users/funk_eu/.cppan/storage/src/d6/90/a846)
set(pvt_cppan_demo_boost_thread_DIR C:/Users/funk_eu/.cppan/storage/src/34/de/c49f)
set(pvt_cppan_demo_openssl_crypto_DIR C:/Users/funk_eu/.cppan/storage/src/01/02/7274)
set(pvt_cppan_demo_openssl_ssl_DIR C:/Users/funk_eu/.cppan/storage/src/12/9a/e40b)

# pvt.cppan.demo.boost.asio-1.64.0
cppan_include("C:/Users/funk_eu/.cppan/storage/src/45/94/dadc/include.cmake")

################################################################################
#
# include dependencies (they should be placed at the end)
#
################################################################################

cppan_debug_message("Section: include dependencies (they should be placed at the end)")

if (CPPAN_USE_CACHE)
    # pvt.cppan.demo.boost.context-1.64.0
    cppan_include("C:/Users/funk_eu/.cppan/storage/obj/5a/c9/3e02/generate.cmake")
    # pvt.cppan.demo.boost.coroutine-1.64.0
    cppan_include("C:/Users/funk_eu/.cppan/storage/obj/e6/29/090a/generate.cmake")
    # pvt.cppan.demo.boost.system-1.64.0
    cppan_include("C:/Users/funk_eu/.cppan/storage/obj/d6/90/a846/generate.cmake")
    # pvt.cppan.demo.boost.thread-1.64.0
    cppan_include("C:/Users/funk_eu/.cppan/storage/obj/34/de/c49f/generate.cmake")
    # pvt.cppan.demo.openssl.crypto-1.10.5
    cppan_include("C:/Users/funk_eu/.cppan/storage/obj/01/02/7274/generate.cmake")
    # pvt.cppan.demo.openssl.ssl-1.10.5
    cppan_include("C:/Users/funk_eu/.cppan/storage/obj/12/9a/e40b/generate.cmake")
else()
    # pvt.cppan.demo.boost.context-1.64.0
    cppan_include("C:/Users/funk_eu/.cppan/storage/src/5a/c9/3e02/include.cmake")
    # pvt.cppan.demo.boost.coroutine-1.64.0
    cppan_include("C:/Users/funk_eu/.cppan/storage/src/e6/29/090a/include.cmake")
    # pvt.cppan.demo.boost.system-1.64.0
    cppan_include("C:/Users/funk_eu/.cppan/storage/src/d6/90/a846/include.cmake")
    # pvt.cppan.demo.boost.thread-1.64.0
    cppan_include("C:/Users/funk_eu/.cppan/storage/src/34/de/c49f/include.cmake")
    # pvt.cppan.demo.openssl.crypto-1.10.5
    cppan_include("C:/Users/funk_eu/.cppan/storage/src/01/02/7274/include.cmake")
    # pvt.cppan.demo.openssl.ssl-1.10.5
    cppan_include("C:/Users/funk_eu/.cppan/storage/src/12/9a/e40b/include.cmake")
endif()

################################################################################
#
# main library
#
################################################################################

cppan_debug_message("Section: main library")

add_library                   (__cppan INTERFACE)
target_link_libraries         (__cppan
    INTERFACE pvt.cppan.demo.boost.asio-1.64.0
    INTERFACE pvt.cppan.demo.boost.context-1.64.0
    INTERFACE pvt.cppan.demo.boost.coroutine-1.64.0
    INTERFACE pvt.cppan.demo.boost.system-1.64.0
    INTERFACE pvt.cppan.demo.boost.thread-1.64.0
    INTERFACE pvt.cppan.demo.openssl.crypto-1.10.5
    INTERFACE pvt.cppan.demo.openssl.ssl-1.10.5
)
add_dependencies(__cppan cppan-d-c)

export(TARGETS __cppan FILE ${CMAKE_BINARY_DIR}/exports/cppan.cmake)

################################################################################
#
# build dependencies
#
################################################################################

cppan_debug_message("Section: build dependencies")

if (CPPAN_USE_CACHE)
    get_configuration_with_generator(config)
    if (CPPAN_BUILD_EXECUTABLES_WITH_SAME_CONFIG)
        get_configuration_with_generator(config_exe)
    else()
        get_configuration_exe(config_exe)
    endif()
    
    string(TOUPPER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE_UPPER)
    
    set(this cppan-d-b)
    
    get_target_property(implib_pvt_cppan_demo_boost_atomic_1_64_0 pvt.cppan.demo.boost.atomic-1.64.0 IMPORTED_LOCATION_${CMAKE_BUILD_TYPE_UPPER})
    get_target_property(implib_pvt_cppan_demo_boost_chrono_1_64_0 pvt.cppan.demo.boost.chrono-1.64.0 IMPORTED_LOCATION_${CMAKE_BUILD_TYPE_UPPER})
    get_target_property(implib_pvt_cppan_demo_boost_context_1_64_0 pvt.cppan.demo.boost.context-1.64.0 IMPORTED_LOCATION_${CMAKE_BUILD_TYPE_UPPER})
    get_target_property(implib_pvt_cppan_demo_boost_coroutine_1_64_0 pvt.cppan.demo.boost.coroutine-1.64.0 IMPORTED_LOCATION_${CMAKE_BUILD_TYPE_UPPER})
    get_target_property(implib_pvt_cppan_demo_boost_date_time_1_64_0 pvt.cppan.demo.boost.date_time-1.64.0 IMPORTED_LOCATION_${CMAKE_BUILD_TYPE_UPPER})
    get_target_property(implib_pvt_cppan_demo_boost_system_1_64_0 pvt.cppan.demo.boost.system-1.64.0 IMPORTED_LOCATION_${CMAKE_BUILD_TYPE_UPPER})
    get_target_property(implib_pvt_cppan_demo_boost_thread_1_64_0 pvt.cppan.demo.boost.thread-1.64.0 IMPORTED_LOCATION_${CMAKE_BUILD_TYPE_UPPER})
    get_target_property(implib_pvt_cppan_demo_openssl_crypto_1_10_5 pvt.cppan.demo.openssl.crypto-1.10.5 IMPORTED_LOCATION_${CMAKE_BUILD_TYPE_UPPER})
    get_target_property(implib_pvt_cppan_demo_openssl_ssl_1_10_5 pvt.cppan.demo.openssl.ssl-1.10.5 IMPORTED_LOCATION_${CMAKE_BUILD_TYPE_UPPER})
    
    set(rest "-DCPPAN_BUILD_EXECUTABLES_WITH_SAME_CONFIGURATION=${CPPAN_BUILD_EXECUTABLES_WITH_SAME_CONFIGURATION} -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DCPPAN_BUILD_VERBOSE=${CPPAN_BUILD_VERBOSE} -DCPPAN_BUILD_WARNING_LEVEL=${CPPAN_BUILD_WARNING_LEVEL} -DCPPAN_COPY_ALL_LIBRARIES_TO_OUTPUT=${CPPAN_COPY_ALL_LIBRARIES_TO_OUTPUT} -DN_CORES=${N_CORES} -DXCODE=${XCODE} -DNINJA=${NINJA} -DVISUAL_STUDIO=${VISUAL_STUDIO} ")
    
    set(ext sh)
    if (WIN32)
        set(ext bat)
    endif()
    
    set(file ${BDIR}/cppan_build_deps_$<CONFIG>.${ext})
    file(GENERATE OUTPUT ${file} CONTENT "
        \"${CMAKE_COMMAND}\" -DTARGET_FILE=$<TARGET_FILE:pvt.cppan.demo.boost.atomic-1.64.0> -DCONFIG=$<CONFIG> -DBUILD_DIR=C:/Users/funk_eu/.cppan/storage/obj/2a/b0/5363/build/${config} -DEXECUTABLE=0 -DMULTICORE=1 ${rest} -P C:/Users/funk_eu/.cppan/storage/obj/2a/b0/5363/build.cmake
        \"${CMAKE_COMMAND}\" -DTARGET_FILE=$<TARGET_FILE:pvt.cppan.demo.boost.chrono-1.64.0> -DCONFIG=$<CONFIG> -DBUILD_DIR=C:/Users/funk_eu/.cppan/storage/obj/bd/31/4142/build/${config} -DEXECUTABLE=0 -DMULTICORE=1 ${rest} -P C:/Users/funk_eu/.cppan/storage/obj/bd/31/4142/build.cmake
        \"${CMAKE_COMMAND}\" -DTARGET_FILE=$<TARGET_FILE:pvt.cppan.demo.boost.context-1.64.0> -DCONFIG=$<CONFIG> -DBUILD_DIR=C:/Users/funk_eu/.cppan/storage/obj/5a/c9/3e02/build/${config} -DEXECUTABLE=0 -DMULTICORE=1 ${rest} -P C:/Users/funk_eu/.cppan/storage/obj/5a/c9/3e02/build.cmake
        \"${CMAKE_COMMAND}\" -DTARGET_FILE=$<TARGET_FILE:pvt.cppan.demo.boost.coroutine-1.64.0> -DCONFIG=$<CONFIG> -DBUILD_DIR=C:/Users/funk_eu/.cppan/storage/obj/e6/29/090a/build/${config} -DEXECUTABLE=0 -DMULTICORE=1 ${rest} -P C:/Users/funk_eu/.cppan/storage/obj/e6/29/090a/build.cmake
        \"${CMAKE_COMMAND}\" -DTARGET_FILE=$<TARGET_FILE:pvt.cppan.demo.boost.date_time-1.64.0> -DCONFIG=$<CONFIG> -DBUILD_DIR=C:/Users/funk_eu/.cppan/storage/obj/45/ec/e77f/build/${config} -DEXECUTABLE=0 -DMULTICORE=1 ${rest} -P C:/Users/funk_eu/.cppan/storage/obj/45/ec/e77f/build.cmake
        \"${CMAKE_COMMAND}\" -DTARGET_FILE=$<TARGET_FILE:pvt.cppan.demo.boost.system-1.64.0> -DCONFIG=$<CONFIG> -DBUILD_DIR=C:/Users/funk_eu/.cppan/storage/obj/d6/90/a846/build/${config} -DEXECUTABLE=0 -DMULTICORE=1 ${rest} -P C:/Users/funk_eu/.cppan/storage/obj/d6/90/a846/build.cmake
        \"${CMAKE_COMMAND}\" -DTARGET_FILE=$<TARGET_FILE:pvt.cppan.demo.boost.thread-1.64.0> -DCONFIG=$<CONFIG> -DBUILD_DIR=C:/Users/funk_eu/.cppan/storage/obj/34/de/c49f/build/${config} -DEXECUTABLE=0 -DMULTICORE=1 ${rest} -P C:/Users/funk_eu/.cppan/storage/obj/34/de/c49f/build.cmake
        \"${CMAKE_COMMAND}\" -DTARGET_FILE=$<TARGET_FILE:pvt.cppan.demo.openssl.crypto-1.10.5> -DCONFIG=$<CONFIG> -DBUILD_DIR=C:/Users/funk_eu/.cppan/storage/obj/01/02/7274/build/${config} -DEXECUTABLE=0 -DMULTICORE=1 ${rest} -P C:/Users/funk_eu/.cppan/storage/obj/01/02/7274/build.cmake
        \"${CMAKE_COMMAND}\" -DTARGET_FILE=$<TARGET_FILE:pvt.cppan.demo.openssl.ssl-1.10.5> -DCONFIG=$<CONFIG> -DBUILD_DIR=C:/Users/funk_eu/.cppan/storage/obj/12/9a/e40b/build/${config} -DEXECUTABLE=0 -DMULTICORE=1 ${rest} -P C:/Users/funk_eu/.cppan/storage/obj/12/9a/e40b/build.cmake
    ")
    
    
    if (UNIX)
        set(file chmod u+x ${file} COMMAND ${file})
    endif()
    
    add_custom_target(${this}-d
        COMMAND ${file}
        BYPRODUCTS
            ${implib_pvt_cppan_demo_boost_atomic_1_64_0}
            ${implib_pvt_cppan_demo_boost_chrono_1_64_0}
            ${implib_pvt_cppan_demo_boost_context_1_64_0}
            ${implib_pvt_cppan_demo_boost_coroutine_1_64_0}
            ${implib_pvt_cppan_demo_boost_date_time_1_64_0}
            ${implib_pvt_cppan_demo_boost_system_1_64_0}
            ${implib_pvt_cppan_demo_boost_thread_1_64_0}
            ${implib_pvt_cppan_demo_openssl_crypto_1_10_5}
            ${implib_pvt_cppan_demo_openssl_ssl_1_10_5}
    )
    add_dependencies(${this} ${this}-d)
    set_target_properties(${this}-d PROPERTIES FOLDER "CPPAN Targets/Service")
    
    add_dependencies(pvt.cppan.demo.boost.atomic-1.64 ${this})
    add_dependencies(pvt.cppan.demo.boost.atomic-1 ${this})
    add_dependencies(pvt.cppan.demo.boost.atomic ${this})
    
    add_dependencies(pvt::cppan::demo::boost::atomic-1.64 ${this})
    add_dependencies(pvt::cppan::demo::boost::atomic-1 ${this})
    add_dependencies(pvt::cppan::demo::boost::atomic ${this})
    
    add_dependencies(pvt.cppan.demo.boost.chrono-1.64 ${this})
    add_dependencies(pvt.cppan.demo.boost.chrono-1 ${this})
    add_dependencies(pvt.cppan.demo.boost.chrono ${this})
    
    add_dependencies(pvt::cppan::demo::boost::chrono-1.64 ${this})
    add_dependencies(pvt::cppan::demo::boost::chrono-1 ${this})
    add_dependencies(pvt::cppan::demo::boost::chrono ${this})
    
    add_dependencies(pvt.cppan.demo.boost.context-1.64 ${this})
    add_dependencies(pvt.cppan.demo.boost.context-1 ${this})
    add_dependencies(pvt.cppan.demo.boost.context ${this})
    
    add_dependencies(pvt::cppan::demo::boost::context-1.64 ${this})
    add_dependencies(pvt::cppan::demo::boost::context-1 ${this})
    add_dependencies(pvt::cppan::demo::boost::context ${this})
    
    add_dependencies(pvt.cppan.demo.boost.coroutine-1.64 ${this})
    add_dependencies(pvt.cppan.demo.boost.coroutine-1 ${this})
    add_dependencies(pvt.cppan.demo.boost.coroutine ${this})
    
    add_dependencies(pvt::cppan::demo::boost::coroutine-1.64 ${this})
    add_dependencies(pvt::cppan::demo::boost::coroutine-1 ${this})
    add_dependencies(pvt::cppan::demo::boost::coroutine ${this})
    
    add_dependencies(pvt.cppan.demo.boost.date_time-1.64 ${this})
    add_dependencies(pvt.cppan.demo.boost.date_time-1 ${this})
    add_dependencies(pvt.cppan.demo.boost.date_time ${this})
    
    add_dependencies(pvt::cppan::demo::boost::date_time-1.64 ${this})
    add_dependencies(pvt::cppan::demo::boost::date_time-1 ${this})
    add_dependencies(pvt::cppan::demo::boost::date_time ${this})
    
    add_dependencies(pvt.cppan.demo.boost.system-1.64 ${this})
    add_dependencies(pvt.cppan.demo.boost.system-1 ${this})
    add_dependencies(pvt.cppan.demo.boost.system ${this})
    
    add_dependencies(pvt::cppan::demo::boost::system-1.64 ${this})
    add_dependencies(pvt::cppan::demo::boost::system-1 ${this})
    add_dependencies(pvt::cppan::demo::boost::system ${this})
    
    add_dependencies(pvt.cppan.demo.boost.thread-1.64 ${this})
    add_dependencies(pvt.cppan.demo.boost.thread-1 ${this})
    add_dependencies(pvt.cppan.demo.boost.thread ${this})
    
    add_dependencies(pvt::cppan::demo::boost::thread-1.64 ${this})
    add_dependencies(pvt::cppan::demo::boost::thread-1 ${this})
    add_dependencies(pvt::cppan::demo::boost::thread ${this})
    
    add_dependencies(pvt.cppan.demo.openssl.crypto-1.10 ${this})
    add_dependencies(pvt.cppan.demo.openssl.crypto-1 ${this})
    add_dependencies(pvt.cppan.demo.openssl.crypto ${this})
    
    add_dependencies(pvt::cppan::demo::openssl::crypto-1.10 ${this})
    add_dependencies(pvt::cppan::demo::openssl::crypto-1 ${this})
    add_dependencies(pvt::cppan::demo::openssl::crypto ${this})
    
    add_dependencies(pvt.cppan.demo.openssl.ssl-1.10 ${this})
    add_dependencies(pvt.cppan.demo.openssl.ssl-1 ${this})
    add_dependencies(pvt.cppan.demo.openssl.ssl ${this})
    
    add_dependencies(pvt::cppan::demo::openssl::ssl-1.10 ${this})
    add_dependencies(pvt::cppan::demo::openssl::ssl-1 ${this})
    add_dependencies(pvt::cppan::demo::openssl::ssl ${this})
    
endif()

################################################################################
#
# copy dependencies
#
################################################################################

cppan_debug_message("Section: copy dependencies")

if (CPPAN_USE_CACHE)
    set(output_dir ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
    if (VISUAL_STUDIO OR XCODE)
        set(output_dir ${output_dir}/$<CONFIG>)
    endif()
    if (CPPAN_BUILD_OUTPUT_DIR)
        set(output_dir ${CPPAN_BUILD_OUTPUT_DIR})
    endif()

    ################################################################################
    #
    # Copy pvt.cppan.demo.boost.atomic-1.64.0
    #
    ################################################################################

    cppan_debug_message("Section: Copy pvt.cppan.demo.boost.atomic-1.64.0")

    set(copy 1)
    get_target_property(type pvt.cppan.demo.boost.atomic-1.64.0 TYPE)
    if ("${type}" STREQUAL STATIC_LIBRARY)
        set(copy 0)
    endif()

    if (CPPAN_COPY_ALL_LIBRARIES_TO_OUTPUT)
        set(copy 1)
    endif()

    if (copy)
        add_custom_command(TARGET cppan-d-c POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_FILE:pvt.cppan.demo.boost.atomic-1.64.0> ${output_dir}//$<TARGET_FILE_NAME:pvt.cppan.demo.boost.atomic-1.64.0>
        )

    endif()

    ################################################################################
    #
    # Copy pvt.cppan.demo.boost.chrono-1.64.0
    #
    ################################################################################

    cppan_debug_message("Section: Copy pvt.cppan.demo.boost.chrono-1.64.0")

    set(copy 1)
    get_target_property(type pvt.cppan.demo.boost.chrono-1.64.0 TYPE)
    if ("${type}" STREQUAL STATIC_LIBRARY)
        set(copy 0)
    endif()

    if (CPPAN_COPY_ALL_LIBRARIES_TO_OUTPUT)
        set(copy 1)
    endif()

    if (copy)
        add_custom_command(TARGET cppan-d-c POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_FILE:pvt.cppan.demo.boost.chrono-1.64.0> ${output_dir}//$<TARGET_FILE_NAME:pvt.cppan.demo.boost.chrono-1.64.0>
        )

    endif()

    ################################################################################
    #
    # Copy pvt.cppan.demo.boost.context-1.64.0
    #
    ################################################################################

    cppan_debug_message("Section: Copy pvt.cppan.demo.boost.context-1.64.0")

    set(copy 1)
    get_target_property(type pvt.cppan.demo.boost.context-1.64.0 TYPE)
    if ("${type}" STREQUAL STATIC_LIBRARY)
        set(copy 0)
    endif()

    if (CPPAN_COPY_ALL_LIBRARIES_TO_OUTPUT)
        set(copy 1)
    endif()

    if (copy)
        add_custom_command(TARGET cppan-d-c POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_FILE:pvt.cppan.demo.boost.context-1.64.0> ${output_dir}//$<TARGET_FILE_NAME:pvt.cppan.demo.boost.context-1.64.0>
        )

    endif()

    ################################################################################
    #
    # Copy pvt.cppan.demo.boost.coroutine-1.64.0
    #
    ################################################################################

    cppan_debug_message("Section: Copy pvt.cppan.demo.boost.coroutine-1.64.0")

    set(copy 1)
    get_target_property(type pvt.cppan.demo.boost.coroutine-1.64.0 TYPE)
    if ("${type}" STREQUAL STATIC_LIBRARY)
        set(copy 0)
    endif()

    if (CPPAN_COPY_ALL_LIBRARIES_TO_OUTPUT)
        set(copy 1)
    endif()

    if (copy)
        add_custom_command(TARGET cppan-d-c POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_FILE:pvt.cppan.demo.boost.coroutine-1.64.0> ${output_dir}//$<TARGET_FILE_NAME:pvt.cppan.demo.boost.coroutine-1.64.0>
        )

    endif()

    ################################################################################
    #
    # Copy pvt.cppan.demo.boost.date_time-1.64.0
    #
    ################################################################################

    cppan_debug_message("Section: Copy pvt.cppan.demo.boost.date_time-1.64.0")

    set(copy 1)
    get_target_property(type pvt.cppan.demo.boost.date_time-1.64.0 TYPE)
    if ("${type}" STREQUAL STATIC_LIBRARY)
        set(copy 0)
    endif()

    if (CPPAN_COPY_ALL_LIBRARIES_TO_OUTPUT)
        set(copy 1)
    endif()

    if (copy)
        add_custom_command(TARGET cppan-d-c POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_FILE:pvt.cppan.demo.boost.date_time-1.64.0> ${output_dir}//$<TARGET_FILE_NAME:pvt.cppan.demo.boost.date_time-1.64.0>
        )

    endif()

    ################################################################################
    #
    # Copy pvt.cppan.demo.boost.system-1.64.0
    #
    ################################################################################

    cppan_debug_message("Section: Copy pvt.cppan.demo.boost.system-1.64.0")

    set(copy 1)
    get_target_property(type pvt.cppan.demo.boost.system-1.64.0 TYPE)
    if ("${type}" STREQUAL STATIC_LIBRARY)
        set(copy 0)
    endif()

    if (CPPAN_COPY_ALL_LIBRARIES_TO_OUTPUT)
        set(copy 1)
    endif()

    if (copy)
        add_custom_command(TARGET cppan-d-c POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_FILE:pvt.cppan.demo.boost.system-1.64.0> ${output_dir}//$<TARGET_FILE_NAME:pvt.cppan.demo.boost.system-1.64.0>
        )

    endif()

    ################################################################################
    #
    # Copy pvt.cppan.demo.boost.thread-1.64.0
    #
    ################################################################################

    cppan_debug_message("Section: Copy pvt.cppan.demo.boost.thread-1.64.0")

    set(copy 1)
    get_target_property(type pvt.cppan.demo.boost.thread-1.64.0 TYPE)
    if ("${type}" STREQUAL STATIC_LIBRARY)
        set(copy 0)
    endif()

    if (CPPAN_COPY_ALL_LIBRARIES_TO_OUTPUT)
        set(copy 1)
    endif()

    if (copy)
        add_custom_command(TARGET cppan-d-c POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_FILE:pvt.cppan.demo.boost.thread-1.64.0> ${output_dir}//$<TARGET_FILE_NAME:pvt.cppan.demo.boost.thread-1.64.0>
        )

    endif()

    ################################################################################
    #
    # Copy pvt.cppan.demo.openssl.crypto-1.10.5
    #
    ################################################################################

    cppan_debug_message("Section: Copy pvt.cppan.demo.openssl.crypto-1.10.5")

    set(copy 1)
    get_target_property(type pvt.cppan.demo.openssl.crypto-1.10.5 TYPE)
    if ("${type}" STREQUAL STATIC_LIBRARY)
        set(copy 0)
    endif()

    if (CPPAN_COPY_ALL_LIBRARIES_TO_OUTPUT)
        set(copy 1)
    endif()

    if (copy)
        add_custom_command(TARGET cppan-d-c POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_FILE:pvt.cppan.demo.openssl.crypto-1.10.5> ${output_dir}//$<TARGET_FILE_NAME:pvt.cppan.demo.openssl.crypto-1.10.5>
        )

    endif()

    ################################################################################
    #
    # Copy pvt.cppan.demo.openssl.ssl-1.10.5
    #
    ################################################################################

    cppan_debug_message("Section: Copy pvt.cppan.demo.openssl.ssl-1.10.5")

    set(copy 1)
    get_target_property(type pvt.cppan.demo.openssl.ssl-1.10.5 TYPE)
    if ("${type}" STREQUAL STATIC_LIBRARY)
        set(copy 0)
    endif()

    if (CPPAN_COPY_ALL_LIBRARIES_TO_OUTPUT)
        set(copy 1)
    endif()

    if (copy)
        add_custom_command(TARGET cppan-d-c POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_FILE:pvt.cppan.demo.openssl.ssl-1.10.5> ${output_dir}//$<TARGET_FILE_NAME:pvt.cppan.demo.openssl.ssl-1.10.5>
        )

    endif()

endif()

################################################################################
#
# local project groups
#
################################################################################

cppan_debug_message("Section: local project groups")

if (CPPAN_HIDE_LOCAL_DEPENDENCIES)
endif()

################################################################################
#
# footer
#
################################################################################

cppan_debug_message("Leaving file: ${CMAKE_CURRENT_LIST_FILE}")

string(LENGTH "${CPPAN_DEBUG_STACK_SPACE}" len)
math(EXPR len "${len}-4")
if (NOT ${len} LESS 0)
    string(SUBSTRING "${CPPAN_DEBUG_STACK_SPACE}" 0 ${len} CPPAN_DEBUG_STACK_SPACE)
else()
    set(CPPAN_DEBUG_STACK_SPACE "")
endif()
set(CPPAN_DEBUG_STACK_SPACE "${CPPAN_DEBUG_STACK_SPACE}" CACHE STRING "" FORCE)

################################################################################

