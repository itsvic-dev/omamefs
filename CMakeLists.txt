cmake_minimum_required(VERSION 3.15)

project(omamefs)

find_package(PkgConfig REQUIRED)
pkg_check_modules(FUSE3 REQUIRED fuse3)

add_executable(${PROJECT_NAME}
    src/main.c
)

add_executable(${PROJECT_NAME}-debugout
    src/debug.c
)

target_link_libraries(${PROJECT_NAME} ${FUSE3_LIBRARIES})
target_include_directories(${PROJECT_NAME} PUBLIC ${FUSE3_INCLUDE_DIRS})
target_compile_options(${PROJECT_NAME} PUBLIC ${FUSE3_CFLAGS_OTHER})

target_link_libraries(${PROJECT_NAME}-debugout ${FUSE3_LIBRARIES})
target_include_directories(${PROJECT_NAME}-debugout PUBLIC ${FUSE3_INCLUDE_DIRS})
target_compile_options(${PROJECT_NAME}-debugout PUBLIC ${FUSE3_CFLAGS_OTHER})
