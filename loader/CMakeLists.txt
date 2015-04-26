set(CMAKE_C_FLAGS "-Wall -std=gnu99 -Werror-implicit-function-declaration -Werror=format")
add_executable(perf-container perf-container.c)

target_link_libraries(perf-container hugetlbfs)