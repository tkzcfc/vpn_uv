project(snappy)

set(SNAPPY_SRC
  snappy.cc
  snappy.h
  snappy-c.cc
  snappy-c.h
  snappy-internal.h
  snappy-sinksource.cc
  snappy-sinksource.h
  snappy-stubs-internal.cc
  snappy-stubs-internal.h
)


function(assign_source_group)
    foreach(_source IN ITEMS ${ARGN})
        if (IS_ABSOLUTE "${_source}")
            file(RELATIVE_PATH _source_rel "${CMAKE_CURRENT_SOURCE_DIR}" "${_source}")
        else()
            set(_source_rel "${_source}")
        endif()
        get_filename_component(_source_path "${_source_rel}" PATH)
        string(REPLACE "/" "\\" _source_path_msvc "${_source_path}")
        source_group("${_source_path_msvc}" FILES "${_source}")
    endforeach()
endfunction(assign_source_group)

function(my_add_library)
    foreach(_source IN ITEMS ${ARGN})
        assign_source_group(${_source})
    endforeach()
    add_library(${ARGV})
endfunction(my_add_library)

# STATIC SHARED
my_add_library(${PROJECT_NAME} STATIC
  ${SNAPPY_SRC}
)

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})


set_property(TARGET ${PROJECT_NAME} PROPERTY FOLDER "ThirdParty")

