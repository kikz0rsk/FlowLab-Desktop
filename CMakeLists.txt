cmake_minimum_required(VERSION 3.16)

project(network-analyzer-gui VERSION 0.1)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets)
find_package(OpenSSL REQUIRED)
find_package(botan CONFIG REQUIRED)

include_directories(${PcapPlusPlus_INCLUDE_DIRS})
include_directories(include/)
include_directories(lib/include/)

set(PROJECT_SOURCES
        src/main.cpp
        src/mainwindow.cpp
        src/logswindow.cpp
        src/dnspage.cpp
        src/connections_page.cpp
        include/mainwindow.h
        include/logswindow.h
        include/dnspage.h
        include/connections_page.h

        src/syntax_highlighter.cpp
        src/connection_manager.cpp
        src/logger.cpp
        src/connection.cpp
        src/tcp_connection.cpp
        src/udp_connection.cpp
        src/packet_utils.cpp
        src/dns_manager.cpp

        mainwindow.ui
        logswindow.ui
        dnspage.ui
        connections_page.ui

        include/connection.h
        include/remote_socket_status.h
        include/tcp_status.h
        include/udp_connection.h
        include/protocol.h
        include/tcp_connection.h
        include/connection_manager.h
        include/logger.h
        include/ndpi.h
        include/packet_utils.h
        include/syntax_highlighter.h
        include/pcap_writer.h
        include/dns_manager.h
        include/dns_entry.h
        include/forwarder.h
        src/forwarder.cpp
        include/socket_utils.h
        src/socket_utils.cpp
)

if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(network-analyzer-gui
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}
    )
# Define target properties for Android with Qt 6 as:
#    set_property(TARGET network-analyzer-gui APPEND PROPERTY QT_ANDROID_PACKAGE_SOURCE_DIR
#                 ${CMAKE_CURRENT_SOURCE_DIR}/android)
# For more information, see https://doc.qt.io/qt-6/qt-add-executable.html#target-creation
else()
    if(ANDROID)
        add_library(network-analyzer-gui SHARED
            ${PROJECT_SOURCES}
        )
# Define properties for Android with Qt 5 after find_package() calls as:
#    set(ANDROID_PACKAGE_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/android")
    else()
        add_executable(network-analyzer-gui
            ${PROJECT_SOURCES}
        )
    endif()
endif()

#target_compile_options(network-analyzer-gui PUBLIC "/Zc:__cplusplus")
#target_compile_options(network-analyzer-gui PUBLIC "/permissive-")

add_library(ndpi STATIC IMPORTED)
set_target_properties(ndpi PROPERTIES IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/lib/lib/libndpi.a)
target_link_libraries(ndpi INTERFACE wsock32 ws2_32)

target_link_libraries(network-analyzer-gui PRIVATE Qt${QT_VERSION_MAJOR}::Widgets)
target_link_libraries(network-analyzer-gui PUBLIC Botan::Botan-static)
target_link_libraries(network-analyzer-gui PUBLIC
        ${CMAKE_SOURCE_DIR}/lib/lib/libPcap++.a
        ${CMAKE_SOURCE_DIR}/lib/lib/libPacket++.a
        ${CMAKE_SOURCE_DIR}/lib/lib/libCommon++.a
        ${CMAKE_SOURCE_DIR}/lib/lib/libpcap.a
        OpenSSL::Crypto OpenSSL::SSL crypt32
)
target_link_libraries(network-analyzer-gui PUBLIC ndpi)

# Qt for iOS sets MACOSX_BUNDLE_GUI_IDENTIFIER automatically since Qt 6.1.
# If you are developing for iOS or macOS you should consider setting an
# explicit, fixed bundle identifier manually though.
if(${QT_VERSION} VERSION_LESS 6.1.0)
  set(BUNDLE_ID_OPTION MACOSX_BUNDLE_GUI_IDENTIFIER com.example.network-analyzer-gui)
endif()
set_target_properties(network-analyzer-gui PROPERTIES
    ${BUNDLE_ID_OPTION}
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

qt_add_ui(network-analyzer-gui SOURCES mainwindow.ui logswindow.ui dnspage.ui connections_page.ui)

include(GNUInstallDirs)
install(TARGETS network-analyzer-gui
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(network-analyzer-gui)
endif()

target_compile_options(network-analyzer-gui PRIVATE -Wall -Wextra -Wpedantic)

add_custom_command(
        TARGET network-analyzer-gui POST_BUILD
        COMMAND "D:\\Qt\\6.8.0\\mingw_64\\bin\\windeployqt6.exe"
        $<TARGET_FILE_DIR:network-analyzer-gui>
)
