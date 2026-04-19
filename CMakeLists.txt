cmake_minimum_required(VERSION 3.10)
project(DGTOTP-TLS VERSION 1.0)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Find GMP with improved detection
find_package(GMP QUIET)

if(NOT GMP_FOUND)
    # Use pkg-config if available (more reliable on Ubuntu)
    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(GMP QUIET gmp)
    endif()
    
    if(NOT GMP_FOUND)
        find_path(GMP_INCLUDE_DIR gmp.h
            PATHS /usr/include /usr/local/include /opt/local/include
        )
        find_library(GMP_LIBRARY NAMES gmp
            PATHS /usr/lib /usr/local/lib /opt/local/lib
        )
        
        if(GMP_INCLUDE_DIR AND GMP_LIBRARY)
            set(GMP_FOUND TRUE)
            set(GMP_INCLUDE_DIRS ${GMP_INCLUDE_DIR})
            set(GMP_LIBRARIES ${GMP_LIBRARY})
        endif()
    endif()
endif()

if(GMP_FOUND)
    message(STATUS "Found GMP: ${GMP_LIBRARIES}")
    message(STATUS "GMP include dirs: ${GMP_INCLUDE_DIRS}")
else()
    message(FATAL_ERROR "GMP library not found. Please install libgmp-dev: sudo apt-get install libgmp-dev")
endif()

# Find Crypto++ with header path
find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(CRYPTOPP QUIET libcrypto++)
endif()

if(NOT CRYPTOPP_FOUND)
    find_path(CRYPTOPP_INCLUDE_DIR cryptopp/aes.h
        PATHS /usr/include /usr/local/include /opt/local/include
    )
    find_library(CRYPTOPP_LIBRARY NAMES cryptopp crypto++
        PATHS /usr/lib /usr/local/lib /opt/local/lib
    )
    
    if(CRYPTOPP_INCLUDE_DIR AND CRYPTOPP_LIBRARY)
        set(CRYPTOPP_FOUND TRUE)
        set(CRYPTOPP_INCLUDE_DIRS ${CRYPTOPP_INCLUDE_DIR})
        set(CRYPTOPP_LIBRARIES ${CRYPTOPP_LIBRARY})
    endif()
endif()

if(CRYPTOPP_FOUND)
    message(STATUS "Found Crypto++: ${CRYPTOPP_LIBRARIES}")
else()
    message(FATAL_ERROR "Crypto++ library not found. Please install libcrypto++-dev: sudo apt-get install libcrypto++-dev")
endif()

# Include directories - more organized approach
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/inc
    ${OPENSSL_INCLUDE_DIR}
    ${GMP_INCLUDE_DIRS}
    ${CRYPTOPP_INCLUDE_DIRS}
)

# Source files
set(COMMON_SOURCES
    src/ChameleonHash.cpp
    src/DGTOTP.cpp
    src/DGTOTP_PRF.cpp
    src/Member.cpp
    src/MerkleTrees.cpp
    src/Parameter.cpp
    src/RA.cpp
    src/AS.cpp
    src/TOTP.cpp
    src/Verifier.cpp
    src/util.cpp
)

add_library(dgtotp_lib STATIC ${COMMON_SOURCES})

# Add library include directories to the library target
target_include_directories(dgtotp_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/inc
)

# Generate executables
add_executable(client tls/client.cpp)
target_link_libraries(client 
    dgtotp_lib 
    ${OPENSSL_LIBRARIES} 
    ${GMP_LIBRARIES} 
    ${CRYPTOPP_LIBRARIES}
)

add_executable(server tls/server.cpp)
target_link_libraries(server 
    dgtotp_lib 
    ${OPENSSL_LIBRARIES} 
    ${GMP_LIBRARIES} 
    ${CRYPTOPP_LIBRARIES}
)

add_executable(verifier tls/verifier.cpp)
target_link_libraries(verifier 
    dgtotp_lib 
    ${OPENSSL_LIBRARIES} 
    ${GMP_LIBRARIES} 
    ${CRYPTOPP_LIBRARIES}
)


add_executable(main src/main.cpp)
target_link_libraries(main
    dgtotp_lib
    ${OPENSSL_LIBRARIES}
    ${GMP_LIBRARIES}
    ${CRYPTOPP_LIBRARIES}
)
