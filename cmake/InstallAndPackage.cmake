if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
    set(ARCHITECTURE "amd64")
else()
    string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" ARCHITECTURE)
endif()

# Windows is a bit more annoying to detect; using the size of void pointer
# seems to be the most robust.
if(WIN32)
    # Check if the MSVC platform has been defined
    if ("$ENV{Platform}" STREQUAL "arm64")
        set(ARCHITECTURE "arm64")
    else()
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            set(ARCHITECTURE "win64")
        else()
            set(ARCHITECTURE "win32")
        endif()
    endif()
endif()

if(APPLE AND CMAKE_OSX_ARCHITECTURES)
    string(TOLOWER "${CMAKE_OSX_ARCHITECTURES}" ARCHITECTURE)
endif()

set(CPACK_SYSTEM_NAME "${ARCHITECTURE}")
set(CPACK_PACKAGE_NAME ${PROJECT_NAME})
set(CPACK_PACKAGE_VENDOR "OpenTTD")
set(CPACK_RESOURCE_FILE_README "${CMAKE_SOURCE_DIR}/README.md")
set(CPACK_MONOLITHIC_INSTALL YES)
set(CPACK_STRIP_FILES YES)
set(CPACK_OUTPUT_FILE_PREFIX "bundles")

if(APPLE)
    set(CPACK_GENERATOR "Bundle")
    include(PackageBundle)

    if (APPLE_UNIVERSAL_PACKAGE)
        set(CPACK_PACKAGE_FILE_NAME "${PROJECT_NAME}-#CPACK_PACKAGE_VERSION#-macos-universal")
    else()
        set(CPACK_PACKAGE_FILE_NAME "${PROJECT_NAME}-#CPACK_PACKAGE_VERSION#-macos-${CPACK_SYSTEM_NAME}")
    endif()
elseif(WIN32)
    set(CPACK_GENERATOR "ZIP")

    set(CPACK_PACKAGE_FILE_NAME "${PROJECT_NAME}-#CPACK_PACKAGE_VERSION#-windows-${CPACK_SYSTEM_NAME}")
elseif(UNIX)
    set(CPACK_GENERATOR "TXZ")

    set(CPACK_PACKAGE_FILE_NAME "${PROJECT_NAME}-#CPACK_PACKAGE_VERSION#-linux-generic-${CPACK_SYSTEM_NAME}")
else()
    message(FATAL_ERROR "Unknown OS found for packaging; please consider creating a Pull Request to add support for this OS.")
endif()

# List all the dependencies of this library.
get_target_property(LIBRARIES ${PROJECT_NAME} LINK_LIBRARIES)
if(APPLE)
    string(REGEX REPLACE "([^;]+)" "lib\\1.dylib" LIBRARIES "${LIBRARIES}")
elseif(WIN32)
    string(REGEX REPLACE "([^;]+)" "\\1.dll" LIBRARIES "${LIBRARIES}")
else()
    string(REGEX REPLACE "([^;]+)" "lib\\1.so" LIBRARIES "${LIBRARIES}")
endif()

install(
    CODE
    "
    message(STATUS \"Creating signature file for libraries: $<TARGET_FILE_NAME:${PROJECT_NAME}> ${LIBRARIES}\")
    execute_process(
        COMMAND python ${CMAKE_SOURCE_DIR}/cmake/create_signature_file.py $<TARGET_FILE_NAME:${PROJECT_NAME}> ${LIBRARIES}
        WORKING_DIRECTORY ${CMAKE_INSTALL_PREFIX}
        OUTPUT_FILE ${CMAKE_BINARY_DIR}/$<TARGET_FILE_NAME:${PROJECT_NAME}>.sig
    )
    file(COPY \"${CMAKE_BINARY_DIR}/$<TARGET_FILE_NAME:${PROJECT_NAME}>.sig\" DESTINATION \${CMAKE_INSTALL_PREFIX}/)
    "
    DESTINATION .
    COMPONENT Runtime)

include(CPack)
