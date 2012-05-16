#Set up project
cmake_minimum_required(VERSION 2.4)
project(ethonmem)
set(ETHONMEM_SOURCE_DIR .)

# Set appropiate flags. A C++11 compiler is required.
if(CMAKE_COMPILER_IS_GNUCXX)
	set(CMAKE_CXX_FLAGS "-std=c++0x -Wall -Wextra -pedantic")
	set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g")
	set(CMAKE_CXX_FLAGS_RELEASE "-O3 -s -DNDEBUG")
endif()

# Search for required packages.
find_package(Boost 1.42.0 COMPONENTS system filesystem REQUIRED)

# Specify include directories.
set(ETHONMEM_INCLUDE_DIR ${ETHONMEM_SOURCE_DIR}/include)
INCLUDE_DIRECTORIES(
	${ETHONMEM_INCLUDE_DIR}
)

# Specify source files.
set(ETHONMEM_SOURCE_FILES
	source/Error.cpp
	source/Debugger.cpp
	source/Memory.cpp
	source/MemoryRegions.cpp
	source/Processes.cpp
	source/Scanner.cpp
	source/Threads.cpp
	source/ProcessLock.cpp
)

#Compile ethonmem as library.
ADD_LIBRARY(ethonmem
	${ETHONMEM_SOURCE_FILES}
)

#Link.
TARGET_LINK_LIBRARIES(ethonmem ${Boost_LIBRARIES})

#Install ethonmem.
INSTALL(TARGETS ethonmem DESTINATION lib)
FILE(GLOB files "${ETHONMEM_SOURCE_DIR}/include/Ethon/*.hpp")
INSTALL(FILES ${files} DESTINATION include/Ethon)
INSTALL(FILES "${ETHONMEM_SOURCE_DIR}/include/Ethonmem.hpp" DESTINATION include/)
