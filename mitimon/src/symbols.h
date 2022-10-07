#ifndef SYMBOLS_H
#define SYMBOLS_H

#include <cstdint>
#include <string>
#include <unordered_map>

#include "data.h"
#include "winkrabs.h"

class Symbolicator {
public:
    Symbolicator(const ProcessData&& processData, const std::wstring& symDir, const std::wstring& symPath);

    ~Symbolicator();

    Symbolicator(Symbolicator&) = delete;
    Symbolicator& operator=(const Symbolicator&) = delete;

    Symbolicator(Symbolicator&&) = delete;
    Symbolicator& operator=(Symbolicator&&) = delete;

    std::wstring symbolicate(void* address);

    ImageData guessImageFromSymbol(const std::wstring& imagePath, const std::wstring& symbolName, void* symbolAddress);

private:
    ProcessData mProcessData;
    HANDLE mProcess;
    std::unordered_map<void*, DWORD64> mModuleMap;

    bool load(const ImageData& imageData);

private:
    static std::atomic<uint32_t> nextSymbolicatorId;
};

#endif // SYMBOLS_H
