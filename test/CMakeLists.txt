macro(add_guest_executable target)
  add_executable(${target} ${ARGN})
  set_target_properties(${target}
    PROPERTIES LINK_FLAGS "-nostdlib -T${CMAKE_CURRENT_SOURCE_DIR}/link.ld")
endmacro()

add_guest_executable(ref ref.c)
add_guest_executable(exit exit.c)


