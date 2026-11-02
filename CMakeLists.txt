cmake_minimum_required(VERSION 3.10)

project(SCSymbolizer VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
	set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

add_executable(SCSymbolizer
	importer.cpp
	main.cpp
	ByteStream.h
)

target_include_directories(SCSymbolizer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

if(MSVC)
	target_compile_options(SCSymbolizer PRIVATE /W4 /utf-8)
	target_compile_definitions(SCSymbolizer PRIVATE _CRT_SECURE_NO_WARNINGS)
else()
	target_compile_options(SCSymbolizer PRIVATE -Wall -Wextra)
endif()

if(WIN32)
	target_link_libraries(SCSymbolizer PRIVATE shell32)
endif()

install(TARGETS SCSymbolizer RUNTIME DESTINATION bin)
