option(LTO "Build With link table optimisation" OFF)
# https://cmake.org/cmake/help/latest/module/CheckIPOSupported.html
if(LTO)
  include(CheckIPOSupported)
  check_ipo_supported(RESULT supported OUTPUT error)

  if(supported)
    message(STATUS "IPO / LTO enabled")
    set(CMAKE_POLICY_DEFAULT_CMP0069 NEW)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE) # It is -lto : link table
    # optimisation flag
    set_target_properties(${PROJECT_NAME}
                          PROPERTIES INTERPROCEDURAL_OPTIMIZATION TRUE)
    set_property(TARGET ${PROJECT_NAME} PROPERTY INTERPROCEDURAL_OPTIMIZATION
                                                 TRUE)
  else(supported)
    # FATAL_ERROR
    message(WARNING "IPO / LTO not supported: <${error}>")
  endif(supported)
else()
  message(WARNING "IPO / LTO not activated")
endif()
