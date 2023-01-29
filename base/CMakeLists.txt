if(DEFINED CIPHER_LIBRARY)
  return()
else()
  set(CIPHER_LIBRARY 1)
endif()

project(cipher)

if(TARGET ${PROJECT_NAME})
  message("The ${PROJECT_NAME} arledy included in main Project")
  return()
endif()

cmake_minimum_required(VERSION 3.1)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
option(BUILD_SHARED_LIBS "Enable or disable shared libraries" OFF)
option(CIPHER_TESTS "Enable tests of the ${PROJECT_NAME} library" OFF)

file(GLOB SOURCE_CPP
    "base/*.h"
    "base/*.cpp"
    "cipher/*.h"
    "cipher/*.cpp"
    "cipher/*.c"
)

add_library(${PROJECT_NAME} ${SOURCE_CPP})
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_LIST_DIR})


if (CIPHER_TESTS)

    file(GLOB SOURCE_CPP_TEST
        "cipher/unittest/*.h"
        "cipher/unittest/*.cpp"
        "cipher/unittest/*.c"

        "cipher/unittest/ut/*.h"
        "cipher/unittest/ut/*.cpp"
        "cipher/unittest/ut/*.c"
    )

    add_executable(${PROJECT_NAME}_test ${SOURCE_CPP_TEST})
    target_link_libraries(${PROJECT_NAME}_test PUBLIC ${PROJECT_NAME})

endif()
