cmake_minimum_required(VERSION 3.24)

project("AmneziaVPN CLI" LANGUAGES NONE)

if(NOT CMAKE_GENERATOR MATCHES "^Ninja")
    message(FATAL_ERROR "AmneziaVPN CLI requires the Ninja generator")
endif()

find_program(GO_EXECUTABLE go REQUIRED)

set(DIST_DIR "${CMAKE_BINARY_DIR}/dist")
set(LIBEXEC_DIR "${DIST_DIR}/libexec/amn")
set(GO_BUILD_ARGS -trimpath -buildvcs=false "-ldflags=-s -w")

file(GLOB_RECURSE AMN_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_SOURCE_DIR}/cmd/*.go"
    "${CMAKE_SOURCE_DIR}/internal/*.go"
)
file(GLOB_RECURSE XRAY_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_SOURCE_DIR}/thirdparty/xray-core/*"
)
file(GLOB_RECURSE WIREGUARD_GO_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_SOURCE_DIR}/thirdparty/wireguard-go/*"
)
file(GLOB_RECURSE AMNEZIAWG_GO_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_SOURCE_DIR}/thirdparty/amneziawg-go/*"
)

set(AMN_BINARY "${DIST_DIR}/amn")
set(XRAY_BINARY "${LIBEXEC_DIR}/xray")
set(WIREGUARD_GO_BINARY "${LIBEXEC_DIR}/wireguard-go")
set(AMNEZIAWG_GO_BINARY "${LIBEXEC_DIR}/amneziawg-go")

add_custom_command(
    OUTPUT "${AMN_BINARY}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${DIST_DIR}"
    COMMAND "${CMAKE_COMMAND}" -E env CGO_ENABLED=0 "${GO_EXECUTABLE}" build ${GO_BUILD_ARGS} -o "${AMN_BINARY}" ./cmd/amn
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    DEPENDS ${AMN_SOURCES} "${CMAKE_SOURCE_DIR}/go.mod"
    VERBATIM
)

add_custom_command(
    OUTPUT "${XRAY_BINARY}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${LIBEXEC_DIR}"
    COMMAND "${CMAKE_COMMAND}" -E env CGO_ENABLED=0 "${GO_EXECUTABLE}" build ${GO_BUILD_ARGS} -o "${XRAY_BINARY}" ./main
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/thirdparty/xray-core"
    DEPENDS ${XRAY_SOURCES} "${CMAKE_SOURCE_DIR}/thirdparty/xray-core/go.mod" "${CMAKE_SOURCE_DIR}/thirdparty/xray-core/go.sum"
    VERBATIM
)

add_custom_command(
    OUTPUT "${WIREGUARD_GO_BINARY}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${LIBEXEC_DIR}"
    COMMAND "${CMAKE_COMMAND}" -E env CGO_ENABLED=0 "${GO_EXECUTABLE}" build ${GO_BUILD_ARGS} -o "${WIREGUARD_GO_BINARY}" .
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/thirdparty/wireguard-go"
    DEPENDS ${WIREGUARD_GO_SOURCES} "${CMAKE_SOURCE_DIR}/thirdparty/wireguard-go/go.mod" "${CMAKE_SOURCE_DIR}/thirdparty/wireguard-go/go.sum"
    VERBATIM
)

add_custom_command(
    OUTPUT "${AMNEZIAWG_GO_BINARY}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${LIBEXEC_DIR}"
    COMMAND "${CMAKE_COMMAND}" -E env CGO_ENABLED=0 "${GO_EXECUTABLE}" build ${GO_BUILD_ARGS} -o "${AMNEZIAWG_GO_BINARY}" .
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/thirdparty/amneziawg-go"
    DEPENDS ${AMNEZIAWG_GO_SOURCES} "${CMAKE_SOURCE_DIR}/thirdparty/amneziawg-go/go.mod" "${CMAKE_SOURCE_DIR}/thirdparty/amneziawg-go/go.sum"
    VERBATIM
)

add_custom_target(amn ALL DEPENDS "${AMN_BINARY}")
add_custom_target(xray ALL DEPENDS "${XRAY_BINARY}")
add_custom_target(wireguard-go ALL DEPENDS "${WIREGUARD_GO_BINARY}")
add_custom_target(amneziawg-go ALL DEPENDS "${AMNEZIAWG_GO_BINARY}")

add_custom_target(check
    COMMAND "${CMAKE_COMMAND}" -E env "AMN_TEST_XRAY=${XRAY_BINARY}" "${GO_EXECUTABLE}" test -race ./...
    COMMAND "${GO_EXECUTABLE}" vet ./...
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    DEPENDS amn xray wireguard-go amneziawg-go
    USES_TERMINAL
    VERBATIM
)
