cmake_minimum_required(VERSION 3.20)

project(BA2ArchiveIndexFix LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(FREEZEFIX_BUILD_PLUGIN "Build the Windows x64 F4SE plugin" ${WIN32})
set(FREEZEFIX_NATIVE_LOOKUP_ROUTINE "" CACHE FILEPATH
    "Optional extract of the verified native archive_lookup routine (1.10.163)")
set(FREEZEFIX_NATIVE_INSERT_ROUTINE "" CACHE FILEPATH
    "Optional extract of the verified native archive_insert routine (1.10.163)")
option(FREEZEFIX_REQUIRE_NATIVE_TESTS
    "Fail configuration when the native routine extracts are missing" OFF)
if(FREEZEFIX_REQUIRE_NATIVE_TESTS AND
   (NOT FREEZEFIX_NATIVE_LOOKUP_ROUTINE OR NOT FREEZEFIX_NATIVE_INSERT_ROUTINE))
    message(FATAL_ERROR
        "FREEZEFIX_REQUIRE_NATIVE_TESTS is ON but the native routine extracts were not provided. "
        "Supply FREEZEFIX_NATIVE_INSERT_ROUTINE and FREEZEFIX_NATIVE_LOOKUP_ROUTINE.")
endif()

set(FREEZEFIX_MINHOOK_SOURCES
    third_party/minhook/src/buffer.c
    third_party/minhook/src/hook.c
    third_party/minhook/src/trampoline.c
    third_party/minhook/src/hde/hde64.c
)

if(FREEZEFIX_BUILD_PLUGIN)
    if(NOT WIN32 OR NOT MSVC OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
        message(FATAL_ERROR "The plugin requires an MSVC Windows x64 toolchain.")
    endif()

    add_library(BA2ArchiveIndexFix SHARED
        src/main.cpp
        ${FREEZEFIX_MINHOOK_SOURCES}
    )
    target_include_directories(BA2ArchiveIndexFix PRIVATE
        third_party
        third_party/minhook/src
    )
    target_compile_definitions(BA2ArchiveIndexFix PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    target_compile_options(BA2ArchiveIndexFix PRIVATE /W4 /EHsc)
    target_link_libraries(BA2ArchiveIndexFix PRIVATE bcrypt)
    set_property(TARGET BA2ArchiveIndexFix PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

include(CTest)
if(BUILD_TESTING)
    find_package(Threads REQUIRED)
    add_executable(freezefix_tests tests/core_tests.cpp)
    target_include_directories(freezefix_tests PRIVATE src)
    target_link_libraries(freezefix_tests PRIVATE Threads::Threads)
    if(MSVC)
        target_compile_options(freezefix_tests PRIVATE /W4 /WX /EHsc)
        set_property(TARGET freezefix_tests PROPERTY
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    else()
        target_compile_options(freezefix_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
    add_test(NAME freezefix_core COMMAND freezefix_tests)
    set_tests_properties(freezefix_core PROPERTIES TIMEOUT 30)

    if(WIN32 AND MSVC AND CMAKE_SIZEOF_VOID_P EQUAL 8)
        add_executable(freezefix_adapter_tests
            tests/windows_adapter_tests.cpp
            ${FREEZEFIX_MINHOOK_SOURCES}
        )
        target_include_directories(freezefix_adapter_tests PRIVATE
            src third_party third_party/minhook/src)
        target_compile_definitions(freezefix_adapter_tests PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
        target_compile_options(freezefix_adapter_tests PRIVATE /W4 /EHsc)
        target_link_libraries(freezefix_adapter_tests PRIVATE bcrypt)
        set_property(TARGET freezefix_adapter_tests PROPERTY
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        add_test(NAME freezefix_windows_adapter COMMAND freezefix_adapter_tests)
        set_tests_properties(freezefix_windows_adapter PROPERTIES TIMEOUT 30)

        # Executes the real native lookup routine against a rebuilt table. The
        # routine is caller-supplied and identity-checked; it is not committed.
        add_executable(freezefix_native_lookup tests/native_lookup_windows.cpp)
        target_include_directories(freezefix_native_lookup PRIVATE src)
        target_compile_definitions(freezefix_native_lookup PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
        target_compile_options(freezefix_native_lookup PRIVATE /W4 /EHsc)
        target_link_libraries(freezefix_native_lookup PRIVATE bcrypt)
        set_property(TARGET freezefix_native_lookup PROPERTY
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        if(FREEZEFIX_NATIVE_LOOKUP_ROUTINE)
            add_test(NAME freezefix_native_lookup
                     COMMAND freezefix_native_lookup "${FREEZEFIX_NATIVE_LOOKUP_ROUTINE}")
            set_tests_properties(freezefix_native_lookup PROPERTIES TIMEOUT 60)
        endif()

        add_executable(freezefix_native_insert tests/native_insert_windows.cpp)
        target_include_directories(freezefix_native_insert PRIVATE src)
        target_compile_definitions(freezefix_native_insert PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
        target_compile_options(freezefix_native_insert PRIVATE /W4 /EHsc)
        target_link_libraries(freezefix_native_insert PRIVATE bcrypt)
        set_property(TARGET freezefix_native_insert PROPERTY
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        if(FREEZEFIX_NATIVE_INSERT_ROUTINE)
            add_test(NAME freezefix_native_insert
                     COMMAND freezefix_native_insert "${FREEZEFIX_NATIVE_INSERT_ROUTINE}")
            set_tests_properties(freezefix_native_insert PROPERTIES TIMEOUT 120)
        endif()

        add_executable(freezefix_native_integration tests/native_integration_windows.cpp)
        target_include_directories(freezefix_native_integration PRIVATE src)
        target_compile_definitions(freezefix_native_integration PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
        target_compile_options(freezefix_native_integration PRIVATE /W4 /EHsc)
        target_link_libraries(freezefix_native_integration PRIVATE bcrypt)
        set_property(TARGET freezefix_native_integration PROPERTY
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        if(FREEZEFIX_NATIVE_INSERT_ROUTINE AND FREEZEFIX_NATIVE_LOOKUP_ROUTINE)
            add_test(NAME freezefix_native_integration
                     COMMAND freezefix_native_integration
                             "${FREEZEFIX_NATIVE_INSERT_ROUTINE}"
                             "${FREEZEFIX_NATIVE_LOOKUP_ROUTINE}")
            set_tests_properties(freezefix_native_integration PROPERTIES TIMEOUT 600)
        endif()
    endif()
endif()
