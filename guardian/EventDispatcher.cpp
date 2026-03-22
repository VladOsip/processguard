#include "EventDispatcher.hpp"
#include "Logger.hpp"

namespace pg {

void EventDispatcher::registerHandler(EventType type, Handler handler) {
    std::lock_guard lock(m_handlerMutex);
    m_handlers[type].push_back(std::move(handler));
}

void EventDispatcher::registerCatchAll(Handler handler) {
    std::lock_guard lock(m_handlerMutex);
    m_catchAll.push_back(std::move(handler));
}

void EventDispatcher::post(SecurityEvent event) {
    {
        std::lock_guard lock(m_mutex);
        m_queue.push(std::move(event));
    }
    m_cv.notify_one();
}

void EventDispatcher::run() {
    m_running = true;
    Logger::info("EventDispatcher started");

    while (true) {
        std::unique_lock lock(m_mutex);
        m_cv.wait(lock, [this] {
            return !m_queue.empty() || !m_running;
        });

        std::queue<SecurityEvent> batch;
        std::swap(batch, m_queue);
        lock.unlock();

        while (!batch.empty()) {
            dispatch(batch.front());
            batch.pop();
        }

        if (!m_running && m_queue.empty()) break;
    }

    Logger::info("EventDispatcher exiting");
}

void EventDispatcher::stop() {
    m_running = false;
    m_cv.notify_all();
}

void EventDispatcher::dispatch(const SecurityEvent& event) {
    std::lock_guard lock(m_handlerMutex);

    if (auto it = m_handlers.find(event.type); it != m_handlers.end())
        for (const auto& handler : it->second)
            handler(event);

    for (const auto& handler : m_catchAll)
        handler(event);
}

} // namespace pg
