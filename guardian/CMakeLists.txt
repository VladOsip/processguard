add_executable(guardian
    main.cpp
    ProcessAttacher.cpp
    MemoryIntegrityMonitor.cpp
    ModuleWatchdog.cpp
    EtwSessionMonitor.cpp
    EventDispatcher.cpp
    HeartbeatMonitor.cpp
    GuardianOrchestrator.cpp
    ${CMAKE_SOURCE_DIR}/common/WinError.cpp
)

target_include_directories(guardian PRIVATE
    ${CMAKE_SOURCE_DIR}/common
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(guardian PRIVATE
    psapi
    advapi32
    tdh
    bcrypt
)

# Request elevated privileges via manifest.
set_target_properties(guardian PROPERTIES
    LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\""
)
