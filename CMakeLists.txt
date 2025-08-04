cmake_minimum_required(VERSION 3.10)
project(DGTOTP-C VERSION 1.0)

# 设置C++标准
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# 查找依赖库
find_package(OpenSSL REQUIRED)

# 手动指定路径
set(GMP_INCLUDE_DIR "/usr/include/x86_64-linux-gnu")
set(GMP_LIBRARY "/usr/lib/x86_64-linux-gnu/libgmp.so")
find_library(GMP_LIBRARY NAMES gmp)
if(GMP_INCLUDE_DIR AND GMP_LIBRARY)
    set(GMP_FOUND TRUE)
    set(GMP_INCLUDE_DIRS ${GMP_INCLUDE_DIR})
    set(GMP_LIBRARIES ${GMP_LIBRARY})
    message(STATUS "Found GMP: ${GMP_LIBRARY}")
else()
    message(FATAL_ERROR "GMP library not found")
endif()

# 添加Crypto++库
find_library(CRYPTOPP_LIBRARY cryptopp)

# 包含目录
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${OPENSSL_INCLUDE_DIR})

# 源文件目录
file(GLOB SOURCES "src/*.cpp")

# 生成可执行文件
add_executable(dgtotp ${SOURCES})

# 链接库
target_link_libraries(dgtotp ${OPENSSL_LIBRARIES})
target_link_libraries(dgtotp ${GMP_LIBRARIES})
target_link_libraries(dgtotp ${CRYPTOPP_LIBRARY})