cmake_minimum_required(VERSION 3.11)
set(CMAKE_CXX_STANDARD 17)

project(chain)

add_subdirectory(payload/loader/reflective)

# stage 1
add_subdirectory(payload/sbx)
# stage 2
add_subdirectory(payload/root)

add_custom_target(payload.js ALL DEPENDS sbx stage0
	COMMAND python3 ${PROJECT_SOURCE_DIR}/make.py)

add_custom_target(stage0 ALL
	COMMAND nasm ${PROJECT_SOURCE_DIR}/payload/stage0.asm -o stage0)
