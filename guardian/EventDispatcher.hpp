#pragma once

#include <atomic>
#include <condition_variable>
#include <flat_map>      // C++23
#include <functional>
#include <mutex>
#include <queue>
#include <vector>

#include "Events.hpp"

namespace pg {

// ---------------------------------------------------------------------------
// EventDispatcher  (C++23 edition)
//
// Changes from C++20 version:
//   - Handler map changed from std::unordered_map<EventType, vector<Handler>>
//     to std::flat_map<EventType, vector<Handler>>.
//     std::flat_map (C++23) stores keys and values in contiguous sorted
//     vectors rather than a hash table. For a small, fixed set of event
//     types this is more cache-friendly at lookup time than unordered_map,
//     and avoids hash collision overhead.
//   - No functional changes to the producer-consumer design.
// ---------------------------------------------------------------------------

class EventDispatcher {
public:
    using Handler = std::function<void(const SecurityEvent&)>;

    void registerHandler(EventType type, Handler handler);
    void registerCatchAll(Handler handler);

    void post(SecurityEvent event);
    void run();
    void stop();

    bool isRunning() const noexcept { return m_running.load(); }

private:
    void dispatch(const SecurityEvent& event);

    std::queue<SecurityEvent>                         m_queue;
    std::mutex                                        m_mutex;
    std::condition_variable                           m_cv;
    std::atomic<bool>                                 m_running{ false };

    // flat_map: contiguous sorted storage, cache-friendly for small N.
    std::flat_map<EventType, std::vector<Handler>>    m_handlers;
    std::vector<Handler>                              m_catchAll;

    mutable std::mutex m_handlerMutex;
};

} // namespace pg
