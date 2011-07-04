#Set up project
CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(PRINTREGIONS)

#Set appropiate flags. Currently only supports g++ 4.5.0 and higher versions.
IF(CMAKE_COMPILER_IS_GNUCXX)
  set(CMAKE_CXX_FLAGS "-g -std=c++0x -Wall -Wextra")
ENDIF()

#Boost is required to build PrintRegions.
FIND_PACKAGE(Boost)

#Compile PrintRegions.
ADD_EXECUTABLE( PrintRegions PrintRegions.cpp )

#Link.
TARGET_LINK_LIBRARIES( PrintRegions ethonmem boost_system boost_filesystem )
