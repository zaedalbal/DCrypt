cmake_minimum_required(VERSION 3.16)

project(DCrpyt VERSION 0.1 LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets)

set(PROJECT_SOURCES
        main.cpp
        mainwindow.cpp
        mainwindow.h
)

if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(DCrpyt
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}
        crypt_algorithms/abstract_crypt_class.h
        crypt_algorithms/crypt_des.h crypt_algorithms/crypt_des.cpp
        crypt_algorithms/crypt_des_cbc.h crypt_algorithms/crypt_des_cbc.cpp
        crypt_algorithms/crypt_rc4.h crypt_algorithms/crypt_rc4.cpp
        crypt_algorithms/crypt_aes.h crypt_algorithms/crypt_aes.cpp
        crypt_algorithms/crypt_rsa.h crypt_algorithms/crypt_rsa.cpp
        crypt_algorithms/crypt_caesar.h crypt_algorithms/crypt_caesar.cpp
        crypt_algorithms/crypt_vigenere.h crypt_algorithms/crypt_vigenere.cpp

        crypt_algorithms/abstract_alphabet_crypt_class.h crypt_algorithms/abstract_alphabet_crypt_class.cpp
        crypt_algorithms/crypt_gronsfeld.h crypt_algorithms/crypt_gronsfeld.cpp


        crypt_algorithms/crypt_vernam.h crypt_algorithms/crypt_vernam.cpp




    )
# Define target properties for Android with Qt 6 as:
#    set_property(TARGET DCrpyt APPEND PROPERTY QT_ANDROID_PACKAGE_SOURCE_DIR
#                 ${CMAKE_CURRENT_SOURCE_DIR}/android)
# For more information, see https://doc.qt.io/qt-6/qt-add-executable.html#target-creation
else()
    if(ANDROID)
        add_library(DCrpyt SHARED
            ${PROJECT_SOURCES}
        )
# Define properties for Android with Qt 5 after find_package() calls as:
#    set(ANDROID_PACKAGE_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/android")
    else()
        add_executable(DCrpyt
            ${PROJECT_SOURCES}
        )
    endif()
endif()

target_link_libraries(DCrpyt PRIVATE Qt${QT_VERSION_MAJOR}::Widgets)
target_link_libraries(DCrpyt PRIVATE bcrypt)

# Qt for iOS sets MACOSX_BUNDLE_GUI_IDENTIFIER automatically since Qt 6.1.
# If you are developing for iOS or macOS you should consider setting an
# explicit, fixed bundle identifier manually though.
if(${QT_VERSION} VERSION_LESS 6.1.0)
  set(BUNDLE_ID_OPTION MACOSX_BUNDLE_GUI_IDENTIFIER com.example.DCrpyt)
endif()
set_target_properties(DCrpyt PROPERTIES
    ${BUNDLE_ID_OPTION}
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

include(GNUInstallDirs)
install(TARGETS DCrpyt
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(DCrpyt)
endif()
