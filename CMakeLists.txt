cmake_minimum_required(VERSION 2.6)

PROJECT(procd C)
INCLUDE(GNUInstallDirs)
ADD_DEFINITIONS(-Os -ggdb -Wall -Werror --std=gnu99 -Wmissing-declarations)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

IF(APPLE)
  INCLUDE_DIRECTORIES(/opt/local/include)
  LINK_DIRECTORIES(/opt/local/lib)
ENDIF()


ADD_LIBRARY(setlbf SHARED service/setlbf.c)
INSTALL(TARGETS setlbf
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)


SET(SOURCES procd.c signal.c state.c hotplug-dispatch.c inittab.c rcS.c ubus.c
	system.c sysupgrade.c service/service.c service/instance.c
	service/validate.c service/trigger.c service/watch.c utils/utils.c)
IF(NOT DISABLE_INIT)
  SET(SOURCES ${SOURCES} watchdog.c plug/coldplug.c plug/hotplug.c)
ENDIF()

FIND_LIBRARY(ubox NAMES ubox)
FIND_LIBRARY(ubus NAMES ubus)
FIND_LIBRARY(uci NAMES uci)
FIND_LIBRARY(blobmsg_json NAMES blobmsg_json)
FIND_LIBRARY(json_script NAMES json_script)
FIND_LIBRARY(json NAMES json-c json)
FIND_LIBRARY(udebug NAMES udebug)

SET(LIBS ${ubox} ${ubus} ${json} ${blobmsg_json} ${json_script} ${udebug})

IF(DEBUG)
  ADD_DEFINITIONS(-DUDEV_DEBUG -g3)
ENDIF()

IF(EARLY_PATH)
  ADD_DEFINITIONS(-DEARLY_PATH="${EARLY_PATH}")
ENDIF()

IF(SELINUX)
  include(FindPkgConfig)
  pkg_search_module(SELINUX REQUIRED libselinux)
  add_compile_definitions(WITH_SELINUX)
ENDIF()

add_subdirectory(upgraded)

ADD_EXECUTABLE(procd ${SOURCES})
TARGET_LINK_LIBRARIES(procd ${LIBS})
SET_TARGET_PROPERTIES(procd PROPERTIES COMPILE_DEFINITIONS "HAS_UDEBUG")
INSTALL(TARGETS procd
	RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

FIND_PATH(ubox_include_dir libubox/uloop.h)
FIND_PATH(udebug_include_dir NAMES udebug.h)
INCLUDE_DIRECTORIES(${ubox_include_dir} ${udebug_include_dir})

IF(DISABLE_INIT)
ADD_DEFINITIONS(-DDISABLE_INIT)
ELSE()
ADD_EXECUTABLE(init initd/init.c initd/early.c initd/preinit.c initd/mkdev.c sysupgrade.c watchdog.c
	utils/utils.c)
TARGET_INCLUDE_DIRECTORIES(init PUBLIC ${SELINUX_INCLUDE_DIRS})
TARGET_LINK_LIBRARIES(init ${LIBS} ${SELINUX_LIBRARIES})
INSTALL(TARGETS init
	RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

ADD_EXECUTABLE(udevtrigger plug/udevtrigger.c)
INSTALL(TARGETS udevtrigger
	RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)
ENDIF()


ADD_EXECUTABLE(askfirst utils/askfirst.c)
INSTALL(TARGETS askfirst
	RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

ADD_CUSTOM_COMMAND(
	OUTPUT syscall-names.h
	COMMAND ./make_syscall_h.sh ${CMAKE_C_COMPILER} > ./syscall-names.h
	DEPENDS ./make_syscall_h.sh
)
ADD_CUSTOM_TARGET(syscall-names-h DEPENDS syscall-names.h)

ADD_CUSTOM_COMMAND(
	OUTPUT capabilities-names.h
	COMMAND ./make_capabilities_h.sh ${CMAKE_C_COMPILER} > ./capabilities-names.h
	DEPENDS ./make_capabilities_h.sh
)
ADD_CUSTOM_TARGET(capabilities-names-h DEPENDS capabilities-names.h)

IF(SECCOMP_SUPPORT)
ADD_DEFINITIONS(-DSECCOMP_SUPPORT)
ADD_LIBRARY(preload-seccomp SHARED jail/preload.c jail/seccomp.c jail/seccomp-oci.c)
TARGET_LINK_LIBRARIES(preload-seccomp dl ${ubox} ${blobmsg_json})
INSTALL(TARGETS preload-seccomp
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
ADD_DEPENDENCIES(preload-seccomp syscall-names-h)
SET(SOURCES_OCI_SECCOMP jail/seccomp-oci.c)
ENDIF()

IF(JAIL_SUPPORT)
ADD_EXECUTABLE(ujail jail/jail.c jail/cgroups.c jail/cgroups-bpf.c jail/elf.c jail/fs.c jail/capabilities.c jail/netifd.c ${SOURCES_OCI_SECCOMP})
TARGET_LINK_LIBRARIES(ujail ${ubox} ${ubus} ${uci} ${blobmsg_json})
INSTALL(TARGETS ujail
	RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)
ADD_DEPENDENCIES(ujail capabilities-names-h)
IF(SECCOMP_SUPPORT)
  ADD_DEPENDENCIES(ujail syscall-names-h)
ENDIF()

ADD_EXECUTABLE(uxc uxc.c)
TARGET_LINK_LIBRARIES(uxc ${ubox} ${ubus} ${blobmsg_json})
INSTALL(TARGETS uxc
	RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)
endif()

IF(UTRACE_SUPPORT)
ADD_EXECUTABLE(utrace trace/trace.c)
TARGET_LINK_LIBRARIES(utrace ${ubox} ${json} ${blobmsg_json})
INSTALL(TARGETS utrace
	RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)
ADD_DEPENDENCIES(utrace syscall-names-h)

ADD_LIBRARY(preload-trace SHARED trace/preload.c)
TARGET_LINK_LIBRARIES(preload-trace dl)
INSTALL(TARGETS preload-trace
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
endif()
