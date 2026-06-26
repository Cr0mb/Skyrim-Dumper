cmake_minimum_required(VERSION 3.20)
project(GHaxSkyrimDumper LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_executable(GHaxSkyrimDumper
    src/main.cpp
    src/log.cpp
    src/process.cpp
    src/pe.cpp
    src/pdata.cpp
    src/rtti.cpp
    src/singletons.cpp
    src/getters.cpp
    src/data_scan.cpp
    src/vtable_dump.cpp
    src/hierarchy.cpp
)

target_include_directories(GHaxSkyrimDumper PRIVATE src)

if (MSVC)
    set_target_properties(GHaxSkyrimDumper PROPERTIES
        LINK_FLAGS "/SUBSYSTEM:CONSOLE")
    target_compile_options(GHaxSkyrimDumper PRIVATE
        /W3 /permissive- /Zc:__cplusplus /utf-8)
    target_compile_definitions(GHaxSkyrimDumper PRIVATE
        _CRT_SECURE_NO_WARNINGS
        UNICODE _UNICODE
        WIN32_LEAN_AND_MEAN
        NOMINMAX)
endif()

target_link_libraries(GHaxSkyrimDumper PRIVATE
    psapi.lib
    advapi32.lib)
