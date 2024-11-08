##cmake_minimum_required(VERSION 3.10)
##project(....)

##set(CMAKE_CXX_STANDARD 11)

add_executable(m main.cpp utils.cpp file_gen.cpp k_switch.cpp verify.cpp)
target_link_libraries(m tfhe++ )


# file(GLOB test_sources RELATIVE "${CMAKE_CURRENT_LIST_DIR}" "*.cpp")


#####add_executable(f file_gen.cpp)
#####target_link_libraries(f tfhe++ )

#####add_executable(k k_switch.cpp)
#####target_link_libraries(k tfhe++ )

#####add_executable(v verify.cpp)
#####target_link_libraries(v tfhe++ )

#####add_executable(m main.cpp)
#####target_link_libraries(m tfhe++ )


# foreach(test_source ${test_sources})
#     string( REPLACE ".cpp" "" test_name ${test_source} )
#     add_executable(${test_name} ${test_source})
#     target_link_libraries(${test_name} tfhe++ )
# endforeach(test_source ${test_sources})

# # For GMP used in INTorus test
# find_library(gmp NAMES gmp gmpxx)
# if(gmp)
#     add_compile_definitions(ENABLE_LSHTEST)
#     target_link_libraries(INTorus gmp)
# endif()

# add_subdirectory(axell)