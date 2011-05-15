#Set up project
CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(ETHONMEM)

#Set appropiate flags. Currently only supports g++ 4.5.0 and higher versions.
IF(CMAKE_COMPILER_IS_GNUCXX)
  set(CMAKE_CXX_FLAGS "-g -std=c++0x -Wall -Wextra")
ENDIF()

#Boost is required to build Ethonmem.
FIND_PACKAGE(Boost)

#Specify include directories.
INCLUDE_DIRECTORIES( ${ETHONMEM_SOURCE_DIR}/include
  ${ETHONMEM_SOURCE_DIR}/depend/asmjit )

#Compile AsmJit as static library.
FILE(GLOB asmjitsources "${ETHONMEM_SOURCE_DIR}/depend/asmjit/AsmJit/*.cpp")
ADD_LIBRARY( asmjit STATIC ${asmjitsources} )

#Compile ethonmem as static library.
ADD_LIBRARY( ethonmem STATIC
  source/Error.cpp
	source/Debugger.cpp
	source/Memory.cpp
	source/MemoryRegions.cpp
	source/Processes.cpp
	source/Scanner.cpp
	source/Threads.cpp
)

#Link.
TARGET_LINK_LIBRARIES( ethonmem boost_system boost_filesystem asmjit)

#Install ethonmem.
INSTALL(FILES libethonmem.a DESTINATION lib)
FILE(GLOB files "${ETHONMEM_SOURCE_DIR}/include/Ethon/*.hpp")
INSTALL(FILES ${files} DESTINATION include/Ethon)
INSTALL(FILES "${ETHONMEM_SOURCE_DIR}/include/Ethonmem.hpp" DESTINATION include/)
