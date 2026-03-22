cmake_minimum_required(VERSION 3.10)
project(bitvault)

add_executable(bitvault 
	src/main.cpp
	src/aes256.cpp
	src/vault.cpp
)

install(TARGETS bitvault DESTINATION /usr/local/bin)

target_include_directories(bitvault PRIVATE include)
