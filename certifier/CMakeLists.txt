set(DSP56300_SOURCE "${PROJECT_SOURCE_DIR}/external/dsp56300/source")
if(NOT EXISTS "${DSP56300_SOURCE}/dsp56kEmu/dsp.h" OR
   NOT EXISTS "${DSP56300_SOURCE}/asmjit/CMakeLists.txt")
  message(FATAL_ERROR
    "The dsp56300 submodule is missing: run git submodule update --init --recursive")
endif()

set(EMULATOR_PATCH "${CMAKE_CURRENT_SOURCE_DIR}/patches/dsp56300-mds-certifier.patch")
file(SHA256 "${EMULATOR_PATCH}" EMULATOR_PATCH_HASH)
set(PATCHED_EMULATOR "${CMAKE_CURRENT_BINARY_DIR}/dsp56300")
if(NOT EXISTS "${PATCHED_EMULATOR}/patched-${EMULATOR_PATCH_HASH}")
  file(REMOVE_RECURSE "${PATCHED_EMULATOR}")
  file(COPY "${DSP56300_SOURCE}/dsp56kEmu" DESTINATION "${PATCHED_EMULATOR}/source")
  execute_process(
    COMMAND patch -p1 --forward --quiet -i "${EMULATOR_PATCH}"
    WORKING_DIRECTORY "${PATCHED_EMULATOR}"
    RESULT_VARIABLE PATCH_RESULT)
  if(NOT PATCH_RESULT EQUAL 0)
    message(FATAL_ERROR "The emulator patch does not apply to the pinned dsp56300 revision")
  endif()
  file(WRITE "${PATCHED_EMULATOR}/patched-${EMULATOR_PATCH_HASH}" "")
endif()

set(ASMJIT_STATIC TRUE)
add_subdirectory("${DSP56300_SOURCE}/asmjit" "${CMAKE_CURRENT_BINARY_DIR}/asmjit" EXCLUDE_FROM_ALL)
if(WIN32 OR (UNIX AND NOT APPLE))
  add_subdirectory("${DSP56300_SOURCE}/vtuneSdk" "${CMAKE_CURRENT_BINARY_DIR}/vtuneSdk" EXCLUDE_FROM_ALL)
endif()
set(DSP56300_DEBUGGER ON)
add_subdirectory("${PATCHED_EMULATOR}/source/dsp56kEmu" "${CMAKE_CURRENT_BINARY_DIR}/dsp56kEmu" EXCLUDE_FROM_ALL)
set_source_files_properties("${PATCHED_EMULATOR}/source/dsp56kEmu/dspthread.cpp"
  DIRECTORY "${PATCHED_EMULATOR}/source/dsp56kEmu" PROPERTIES HEADER_FILE_ONLY ON)

add_executable(mds-certifier
  src/main.cpp
  src/sysex.cpp
  src/package.cpp
  src/emulator.cpp
  src/services.cpp
  src/certify.cpp)
target_include_directories(mds-certifier PRIVATE src)
target_link_libraries(mds-certifier PRIVATE dsp56kEmu)
set_target_properties(mds-certifier PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")
if(MSVC)
  target_compile_options(mds-certifier PRIVATE /W4)
else()
  target_compile_options(mds-certifier PRIVATE -Wall -Wextra)
endif()

if(BUILD_TESTING)
  add_test(NAME sine COMMAND mds-certifier --quiet "${PROJECT_SOURCE_DIR}/tests/fixtures/sine.mds")
  set_tests_properties(sine PROPERTIES PASS_REGULAR_EXPRESSION "cycles per track MKI 954, MKII 894")

  add_executable(mds-cycle-tests tests/cycles.cpp src/package.cpp src/emulator.cpp)
  target_include_directories(mds-cycle-tests PRIVATE src)
  target_link_libraries(mds-cycle-tests PRIVATE dsp56kEmu)
  add_test(NAME cycle_contract COMMAND mds-cycle-tests "${PROJECT_SOURCE_DIR}/tests/fixtures/sine.mds")

  add_executable(mds-rule-tests tests/rules.cpp src/package.cpp src/emulator.cpp src/services.cpp)
  target_include_directories(mds-rule-tests PRIVATE src)
  target_link_libraries(mds-rule-tests PRIVATE dsp56kEmu)
  add_test(NAME rule_contract COMMAND mds-rule-tests)
endif()
