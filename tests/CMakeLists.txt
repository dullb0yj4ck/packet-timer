# setup for this test-set
include_directories (${CXXTEST_PATH})
#include_directories (${CMAKE_SOURCE_DIR}/libtest/inc)

foreach(CLASS pcap)
  #Generate test source files from cxxtest headers using cxxtestgen.pl
  add_custom_command(OUTPUT
    ${CMAKE_CURRENT_SOURCE_DIR}/${CLASS}_testRunner.cpp
    COMMAND
    perl ${CXXTEST_PATH}/cxxtestgen.pl --error-printer -o ${CMAKE_CURRENT_SOURCE_DIR}/${CLASS}_testRunner.cpp ${CMAKE_CURRENT_SOURCE_DIR}/${CLASS}_test.h)
  #Build testing executables
  add_executable(${CLASS}_testRunner
    ${CMAKE_CURRENT_SOURCE_DIR}/${CLASS}_testRunner.cpp)
  add_sysshep_libs(${CLASS}_testRunner)
  #Add tests 
  add_test(${CLASS}_Test
    ${EXECUTABLE_OUTPUT_PATH}/${CLASS}_testRunner)
  #Set properties for tests 
  SET_TESTS_PROPERTIES(${CLASS}_Test PROPERTIES 
    FAIL_REGULAR_EXPRESSION "ERROR;Error;FAIL;Test failed"
    PASS_REGULAR_EXPRESSION "Test passed;OK;ok;Ok")
endforeach(CLASS)
