##cmake_minimum_required(VERSION 3.10)
##projecthomo)
#####add_library(utils STATIC  utils.cpp)

add_executable(m  main.cpp utils.cpp file_genA.cpp  file_genB.cpp  k_switch.cpp  verify.cpp)

target_link_libraries(m  tfhe++)

#####target_include_directories(m  PUBLIC
#####  ${CMAKE_CURRENT_SOURCE_DIR}
#####  AEShomo/include/tfhe++.hpp
#####)
##set(CMAKE_CXX_STANDARD 11)
#####add_library(utils STATIC  utils.cpp )
#####target_link_libraries(utils tfhe++ )


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
