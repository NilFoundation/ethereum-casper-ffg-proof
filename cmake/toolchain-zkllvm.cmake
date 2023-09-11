if(CIRCUIT_ASSEMBLY_OUTPUT)
    set(extension ll)
    set(format_option -S)
else()
    set(extension bc)
    set(format_option -c)
endif()

if(CMAKE_C_COMPILER)
    set(CMAKE_C_COMPILER ${CMAKE_C_COMPILER} CACHE PATH "" FORCE)
    get_filename_component(CMAKE_C_COMPILER_DIR ${CMAKE_C_COMPILER} DIRECTORY)
endif()

if(CMAKE_CXX_COMPILER)
    set(CMAKE_CXX_COMPILER ${CMAKE_CXX_COMPILER} CACHE PATH "" FORCE)
    get_filename_component(CMAKE_CXX_COMPILER_DIR ${CMAKE_CXX_COMPILER} DIRECTORY)
endif()

include_directories(${CMAKE_C_COMPILER_DIR}/../include/c++/v1 ${CMAKE_CXX_COMPILER_DIR}/../include/c++/v1)
link_directories(${CMAKE_C_COMPILER_DIR}/../lib ${CMAKE_CXX_COMPILER_DIR}/../lib)

#set(CMAKE_CXX_LINK_EXECUTABLE ${CMAKE_CXX_COMPILER_DIR}/llvm-link)

set(CMAKE_C_COMPILER_TARGET "assigner")
set(CMAKE_CXX_COMPILER_TARGET "assigner")

set(CMAKE_LIBRARY_ARCHITECTURE "")

list(APPEND CMAKE_C_FLAGS "-Xclang -no-opaque-pointers -Xclang -fpreserve-vec3-type -emit-llvm -O1 ${format_option} -nostdinc -stdlib=libc++ -rpath -Wl")
list(APPEND CMAKE_CXX_FLAGS "-Xclang -no-opaque-pointers -Xclang -fpreserve-vec3-type -emit-llvm -O1 ${format_option} -nostdinc -stdlib=libc++ -rpath -Wl")

set(CMAKE_C_OUTPUT_EXTENSION "${extension}")
set(CMAKE_CXX_OUTPUT_EXTENSION "${extension}")

list(APPEND COMPILE_DEFINITIONS "-D __ZKLLVM__")

list(APPEND LINK_FLAGS "-opaque-pointers=0")

if(CIRCUIT_ASSEMBLY_OUTPUT)
    list(APPEND LINK_FLAGS "-S")
endif()