set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-access-control")

add_executable(crypto_test crypto_test.cpp)
target_link_libraries(crypto_test ${OPENSSL_CRYPTO_LIBRARY})
add_test(crypto_test crypto_test)

add_executable(io_test io_test.cpp)
target_link_libraries(io_test ${Boost_LIBRARIES})
target_link_libraries(io_test ${OPENSSL_CRYPTO_LIBRARY})
target_link_libraries(io_test ${CMAKE_THREAD_LIBS_INIT})

add_executable(parse_test parse_test.cpp)
target_link_libraries(parse_test ${Boost_LIBRARIES})
target_link_libraries(parse_test ${CMAKE_THREAD_LIBS_INIT})

if(MSYS)
    target_link_libraries(io_test ws2_32 wsock32)
    target_link_libraries(parse_test ws2_32 wsock32)
endif()

add_test(io_test io_test)
add_test(parse_test parse_test)
