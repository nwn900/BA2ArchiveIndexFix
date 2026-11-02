#pragma once

namespace freezefix {

enum class InstallStage { installed, initialize, create_hook, start_watchdog, enable_hook };

struct InstallResult {
    InstallStage stage = InstallStage::initialize;
    bool rollback_ok = true;
    explicit operator bool() const noexcept { return stage == InstallStage::installed; }
};

// Ordering is part of the safety boundary: the original trampoline and monitor
// resources exist before the hook can execute. A failed installation keeps the
// DLL loaded; a failed rollback must never invalidate a still-live trampoline.
// Operations methods own their Win32 resources and return bool for success.
template<class Operations>
InstallResult install_observer(Operations& operations) {
    if (!operations.initialize()) return {InstallStage::initialize, true};
    if (!operations.create_hook())
        return {InstallStage::create_hook, operations.uninitialize()};
    if (!operations.start_watchdog()) {
        const bool removed = operations.remove_hook();
        const bool clean = removed && operations.uninitialize();
        return {InstallStage::start_watchdog, clean};
    }
    if (!operations.enable_hook()) {
        // A callback can already be inside the detour, immediately before it
        // calls its original trampoline. Disabling/removing the hook does not
        // make that future call safe after MinHook frees its executable buffer.
        // Without a callback-quiescence protocol, retain all process-lifetime
        // resources after any successful enable. The caller leaves recovery
        // inactive, so retained detours remain pass-through only.
        if (operations.any_hook_enabled())
            return {InstallStage::enable_hook, false};
        const bool stopped = operations.stop_watchdog();
        const bool removed = operations.remove_hook();
        const bool uninitialized = removed && operations.uninitialize();
        return {InstallStage::enable_hook, stopped && removed && uninitialized};
    }
    return {InstallStage::installed, true};
}

} // namespace freezefix
