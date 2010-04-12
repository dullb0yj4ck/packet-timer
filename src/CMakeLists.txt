MACRO(ADD_AGENT_EXECUTABLE target) # expects files after target
  ADD_EXECUTABLE(${target} ${ARGN})
  ADD_SYSSHEP_LIBS(${target})
ENDMACRO(ADD_AGENT_EXECUTABLE)


SET(SRC_FILES
  capture_descriptor.cxx
  network_device.cxx)

# make a shared library for delta, else a static one
IF(DEFINED USE_STATIC_LIBS OR LIB_SYSSHEP_BUILD_MODE STREQUAL "agent")
  ADD_LIBRARY(pcapp STATIC ${SRC_FILES})
ELSE(DEFINED USE_STATIC_LIBS OR LIB_SYSSHEP_BUILD_MODE STREQUAL "agent")
  IF(UNIX)
    ADD_LIBRARY(pcapp SHARED ${SRC_FILES})
  ELSE(UNIX)
    ADD_LIBRARY(pcapp ${SRC_FILES})
  ENDIF(UNIX)
ENDIF(DEFINED USE_STATIC_LIBS OR LIB_SYSSHEP_BUILD_MODE STREQUAL "agent")


# Cxx Packed Timer
IF (UNIX)
  ADD_AGENT_EXECUTABLE(packet-timerxx
    packet-timer.cxx)
ENDIF (UNIX)
