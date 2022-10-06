#ifndef TRACE_H
#define TRACE_H

#include <string>
#include <vector>

#include "winkrabs.h"

class Tracer {
public:
    Tracer(const std::wstring& sessionName) :
        mTrace{ sessionName },
        mProviders{}
    {
    }

    void addProcessProvider();

    void addCustomProvider(const std::wstring& providerName, ULONGLONG providerAny, auto&& callback)
    {
        auto& customProvider = mProviders.emplace_back(providerName);

        customProvider.any(providerAny);
        customProvider.trace_flags(customProvider.trace_flags() | EVENT_ENABLE_PROPERTY_STACK_TRACE);

        krabs::event_filter mitigations_filter(krabs::predicates::any_event);
        mitigations_filter.add_on_event_callback(std::forward<decltype(callback)>(callback));
        customProvider.add_filter(mitigations_filter);
    }

    void start();

private:
    krabs::user_trace mTrace;
    std::vector<krabs::provider<>> mProviders;
};

#endif // TRACE_H
