#include <cstdint>
#include <format>
#include <fstream>
#include <future>
#include <iostream>
#include <mutex>
#include <string>

#include "symbols.h"
#include "trace.h"
#include "winkrabs.h"

#define OUTPUT_FILE L"output.txt"

#define SYM_DIR L"C:\\MozSym"

#define SYM_PATH L"SRV*" SYM_DIR L"*https://msdl.microsoft.com/download/symbols;" \
                 L"SRV*" SYM_DIR L"*https://symbols.mozilla.org;"                 \
                 L"SRV*" SYM_DIR L"*https://symbols.mozilla.org/try"

#define SESSION_NAME L"mitimon"

#define MITIGATIONS_PROVIDER L"Microsoft-Windows-Security-Mitigations"
#define MITIGATIONS_ANY 0x8000000000000000Ui64

inline std::wstring stringify(const EVENT_RECORD& record, krabs::parser& parser, const krabs::property& property)
{
    std::wstring result(property.name());

    auto type = property.type();
    if (type == TDH_INTYPE_POINTER) {
        if (record.EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) {
            type = TDH_INTYPE_UINT32;
        }
        else {
            type = TDH_INTYPE_UINT64;
        }
    }

    switch (type) {
    case TDH_INTYPE_UNICODESTRING:
        result += std::format(L" L\"{}\"", parser.parse<std::wstring>(property.name()));
        break;

    case TDH_INTYPE_INT8:
    case TDH_INTYPE_UINT8:
        result += std::format(L" 0x{:02x}", parser.parse<uint8_t>(property.name()));
        break;

    case TDH_INTYPE_INT16:
    case TDH_INTYPE_UINT16:
        result += std::format(L" 0x{:04x}", parser.parse<uint16_t>(property.name()));
        break;

    case TDH_INTYPE_INT32:
    case TDH_INTYPE_UINT32:
        result += std::format(L" 0x{:08x}", parser.parse<uint32_t>(property.name()));
        break;

    case TDH_INTYPE_INT64:
    case TDH_INTYPE_UINT64:
    case TDH_INTYPE_FILETIME:
        result += std::format(L" 0x{:016x}", parser.parse<uint64_t>(property.name()));
        break;

    default:
        result += std::format(L" ? <unsupported data type {}>", static_cast<int>(type));
        break;
    }

    return result;
}

int main()
{
    std::vector<std::future<void>> backgroundTasks;

    std::wofstream sout{OUTPUT_FILE};
    std::mutex soutMutex;

    Tracer tracer(SESSION_NAME);

    // The process provider will track process creation and image loading,
    // this is required for symbolication to work.
    tracer.addProcessProvider();

    // This adds the real provider we are interested in.
    tracer.addCustomProvider(MITIGATIONS_PROVIDER, MITIGATIONS_ANY,
        [&backgroundTasks, &sout, &soutMutex](const EVENT_RECORD& record, const krabs::trace_context& traceContext)
        {
            krabs::schema schema(record, traceContext.schema_locator);
            auto taskName = schema.task_name();
            auto eventId = schema.event_id();
            auto pid = schema.process_id();
            auto tid = schema.thread_id();
            auto stackTrace = schema.stack_trace();

            krabs::parser parser(schema);
            for (const krabs::property& property : parser.properties()) {
                sout << stringify(record, parser, property) << std::endl;
            }

            ProcessData processData{ pid, L"unknown" };
            if (ProcessData::exists(pid)) {
                processData = ProcessData::get(pid);
            }

            // Defer symbolication to leave the main thread responsive to future events.
            // Use a copy of the process data on the new thread, as it may get modified by future events.
            backgroundTasks.emplace_back(std::async(std::launch::async, [&sout, &soutMutex, taskName, eventId, pid, tid, stackTrace, processData]() mutable {
                Symbolicator symbolicator{ std::move(processData), SYM_DIR, SYM_PATH };

                std::lock_guard guard(soutMutex);

                std::cout << "Please wait while a new event is being processed..." << std::endl;

                sout << std::endl << std::endl;
                sout << L"TaskName " << taskName << std::endl;
                sout << L"EventId " << eventId << std::endl;
                sout << std::format(L"ProcessId 0x{:08x}", pid) << std::endl;
                sout << std::format(L"ThreadId 0x{:08x}", tid) << std::endl;
                sout << std::endl;

                // Locate the kernel based on the assumption that the first return address points somewhere in EtwWrite.
                symbolicator.loadWithHint(L"ntoskrnl", L"C:\\Windows\\System32\\ntoskrnl.exe",
                    L"EtwWrite", reinterpret_cast<void*>(stackTrace[0]));

                sout << L"Call Stack:" << std::endl;
                for (auto& return_address : stackTrace)
                {
                    sout << L"   " << symbolicator.symbolicate(reinterpret_cast<void*>(return_address)) << std::endl;
                }
                sout << std::endl;

                std::cout << "The event was successfully processed." << std::endl << std::endl;
            }));
        }
    );
    try {
        tracer.start();
    }
    catch (std::runtime_error e) {
        std::cout << e.what() << std::endl;
    }

    return 0;
}
