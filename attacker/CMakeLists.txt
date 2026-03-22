# Attacker executable
add_executable(attacker
    main.cpp
)

target_include_directories(attacker PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/common
)

target_link_libraries(attacker PRIVATE psapi)

# Payload DLL — the benign DLL injected by the 'inject' attack mode.
add_library(payload SHARED payload.cpp)

# Copy payload.dll next to attacker.exe after build so the inject mode
# can find it without manual copying.
add_custom_command(TARGET attacker POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:payload>
        $<TARGET_FILE_DIR:attacker>/payload.dll
    COMMENT "Copying payload.dll next to attacker.exe"
)
