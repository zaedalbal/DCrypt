cmake_minimum_required(VERSION 3.16)

project(DCrypt VERSION 0.1 LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets)

set(PROJECT_SOURCES
    src/main.cpp
    src/mainwindow.cpp
    src/mainwindow.h
    src/crypt_algorithms/abstract_crypt_class.h
    src/crypt_algorithms/crypt_des.cpp src/crypt_algorithms/crypt_des.h
    src/crypt_algorithms/crypt_des_cbc.cpp src/crypt_algorithms/crypt_des_cbc.h
    src/crypt_algorithms/crypt_rc4.cpp src/crypt_algorithms/crypt_rc4.h
    src/crypt_algorithms/crypt_aes.cpp src/crypt_algorithms/crypt_aes.h
    src/crypt_algorithms/crypt_rsa.cpp src/crypt_algorithms/crypt_rsa.h
    src/crypt_algorithms/crypt_caesar.cpp src/crypt_algorithms/crypt_caesar.h
    src/crypt_algorithms/crypt_vigenere.cpp src/crypt_algorithms/crypt_vigenere.h
    src/crypt_algorithms/abstract_alphabet_crypt_class.cpp src/crypt_algorithms/abstract_alphabet_crypt_class.h
    src/crypt_algorithms/crypt_gronsfeld.cpp src/crypt_algorithms/crypt_gronsfeld.h
    src/crypt_algorithms/crypt_vernam.cpp src/crypt_algorithms/crypt_vernam.h
)

if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(DCrypt
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}
    )
else()
    if(ANDROID)
        add_library(DCrypt SHARED ${PROJECT_SOURCES})
    else()
        add_executable(DCrypt ${PROJECT_SOURCES})
    endif()
endif()

target_link_libraries(DCrypt PRIVATE Qt${QT_VERSION_MAJOR}::Widgets)

# Windows-specific libraries
if(WIN32)
    target_link_libraries(DCrypt PRIVATE bcrypt)
endif()

set_target_properties(DCrypt PROPERTIES
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

include(GNUInstallDirs)
install(TARGETS DCrypt
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(DCrypt)
endif()
