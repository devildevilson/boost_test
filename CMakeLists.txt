cmake_minimum_required(VERSION 3.15)

set(ASIO_TEST_NAME asio_test)
set(MYSQL_TEST_NAME mysql_test)

project(
  boost_test
  VERSION 0.0.1
  LANGUAGES CXX
)

find_package(Boost REQUIRED COMPONENTS headers)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(${ASIO_TEST_NAME})
target_sources(${ASIO_TEST_NAME} PRIVATE main.cpp)
target_link_libraries(${ASIO_TEST_NAME} PRIVATE Boost::headers Threads::Threads OpenSSL::Crypto OpenSSL::SSL ws2_32 wsock32)

add_executable(${MYSQL_TEST_NAME})
target_sources(${MYSQL_TEST_NAME} PRIVATE mysql.cpp)
target_link_libraries(${ASIO_TEST_NAME} PRIVATE Boost::headers Threads::Threads OpenSSL::Crypto OpenSSL::SSL)