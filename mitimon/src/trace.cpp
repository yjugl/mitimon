#include <string>

#include "data.h"
#include "trace.h"
#include "symbols.h"
#include "winkrabs.h"

#define WINEVENT_KEYWORD_PROCESS 0x10
#define WINEVENT_KEYWORD_IMAGE 0x40

enum ProcessProvider {
    ProcessStart = 1,
    ProcessStop = 2,
    ImageLoad = 5,
    ImageUnload = 6,
};

void Tracer::addProcessProvider()
{
    auto& processProvider = mProviders.emplace_back(L"Microsoft-Windows-Kernel-Process");
    processProvider.any(WINEVENT_KEYWORD_PROCESS | WINEVENT_KEYWORD_IMAGE);

    krabs::event_filter processFilter(
        krabs::predicates::or_filter(
            krabs::predicates::or_filter(
                krabs::predicates::id_is(ProcessProvider::ProcessStart),
                krabs::predicates::id_is(ProcessProvider::ProcessStop)
            ),
            krabs::predicates::or_filter(
                krabs::predicates::id_is(ProcessProvider::ImageLoad),
                krabs::predicates::id_is(ProcessProvider::ImageUnload)
            )
        )
    );
    processFilter.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& traceContext) {
        krabs::schema schema(record, traceContext.schema_locator);
        krabs::parser parser(schema);

        switch (schema.event_id()) {
        case ProcessProvider::ProcessStart:
        {
            auto pid = parser.parse<uint32_t>(L"ProcessID");
            auto imageName = parser.parse<std::wstring>(L"ImageName");
            ProcessData::add(pid, imageName);
            break;
        }

        case ProcessProvider::ProcessStop:
        {
            auto pid = parser.parse<uint32_t>(L"ProcessID");
            ProcessData::remove(pid);
            break;
        }

        case ProcessProvider::ImageLoad:
        {
            auto pid = parser.parse<uint32_t>(L"ProcessID");
            auto imageName = parser.parse<std::wstring>(L"ImageName");
            auto imageBase = parser.parse<void*>(L"ImageBase");
            auto imageSize = parser.parse<size_t>(L"ImageSize");
            ImageData::add(pid, imageBase, imageSize, imageName);
            break;
        }

        case ProcessProvider::ImageUnload:
        {
            auto pid = parser.parse<uint32_t>(L"ProcessID");
            auto imageBase = parser.parse<void*>(L"ImageBase");
            ImageData::remove(pid, imageBase);
            break;
        }

        default:
            ;
        }
    });
    processProvider.add_filter(processFilter);
}

void Tracer::start()
{
    for (const auto& provider : mProviders) {
        mTrace.enable(provider);
    }

    mTrace.start();
}
