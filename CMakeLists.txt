cmake_minimum_required(VERSION 3.18)
project(mds_tools LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

include(CTest)
add_subdirectory(certifier)

if(BUILD_TESTING)
  find_package(Python3 3.10 COMPONENTS Interpreter)
  if(Python3_Interpreter_FOUND)
    add_test(NAME python_tools
      COMMAND ${CMAKE_COMMAND} -E env
        MDS_CERTIFIER=$<TARGET_FILE:mds-certifier>
        ${Python3_EXECUTABLE} -B -m unittest discover
        -s "${CMAKE_CURRENT_SOURCE_DIR}/tests" -v)
  endif()
endif()
