# cmake verson
cmake_minimum_required(VERSION 3.2)

# project name
PROJECT(vpn_uv)

add_subdirectory("ThirdParty/snappy")
add_subdirectory("ThirdParty/net_uv")
add_subdirectory("ThirdParty/libuv")

macro(add_console name)
    project(${name})

    set(_Example_Sources
        ${ARGN}
    )

    source_group("" FILES ${_Example_Sources})
    source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${_Example_Sources})

    add_executable(${name} ${_Example_Sources})

    target_link_libraries(${name} PRIVATE common libuv net_uv snappy)

    set(_ExampleBinDir ${CMAKE_BINARY_DIR}/Bin)

    set_target_properties(${name} PROPERTIES
        FOLDER "Apps"
        RUNTIME_OUTPUT_DIRECTORY                "${_ExampleBinDir}"
        RUNTIME_OUTPUT_DIRECTORY_DEBUG          "${_ExampleBinDir}"
        RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${_ExampleBinDir}"
        RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL     "${_ExampleBinDir}"
        RUNTIME_OUTPUT_DIRECTORY_RELEASE        "${_ExampleBinDir}"
        DEBUG_POSTFIX                           _d
        RELWITHDEBINGO_POSTFIX                  _rd
        MINSIZEREL_POSTFIX                      _r
        VS_DEBUGGER_WORKING_DIRECTORY           ${_ExampleBinDir}
        #MACOSX_BUNDLE_INFO_PLIST                "${CMAKE_SOURCE_DIR}/Apps/Common/Support/Info.plist.in"
        #MACOSX_BUNDLE_BUNDLE_NAME               "${PACKAGE_NAME}"
        #MACOSX_BUNDLE_GUI_IDENTIFIER            "com.sandbox.collisions"
        #MACOSX_BUNDLE_LONG_VERSION_STRING       "${PACKAGE_VERSION}"
        #MACOSX_BUNDLE_SHORT_VERSION_STRING      "${PACKAGE_VERSION_MAJOR}.${PACKAGE_VERSION_MINOR}"
        #MACOSX_BUNDLE_ICON_FILE                 Icon.icns
    )

    add_custom_command(
        TARGET ${name}
        PRE_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory ARGS ${_ExampleBinDir}
    )

endmacro()

add_subdirectory("common")
add_subdirectory("client")
add_subdirectory("server")
add_subdirectory("test")