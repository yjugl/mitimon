#include <cstring>
#include <format>
#include <iostream>
#include <string>
#include <unordered_map>

#include "data.h"
#include "symbols.h"
#include "winkrabs.h"

Symbolicator::Symbolicator(const ProcessData&& processData, const std::wstring& symDir, const std::wstring& symPath) :
    mProcessData{ processData },
    mProcess{ reinterpret_cast<HANDLE>(processData.pid()) },
    mModuleMap{}
{
    ::SymSetOptions(SYMOPT_IGNORE_NT_SYMPATH);

    if (!::CreateDirectoryW(symDir.c_str(), nullptr) && ::GetLastError() != ERROR_ALREADY_EXISTS) {
        throw std::runtime_error("CreateDirectoryW failed.");
    }

    if (!::SymInitializeW(mProcess, symPath.c_str(), FALSE)) {
        throw std::runtime_error("SymInitializeW failed.");
    }
}


Symbolicator::~Symbolicator()
{
    for (auto& [imageBase, module_] : mModuleMap) {
        ::SymUnloadModule64(mProcess, module_);
    }

    ::SymCleanup(mProcess);
}

std::wstring Symbolicator::symbolicate(void* address)
{
    std::wstring result{ std::format(L"0x{:016x}", reinterpret_cast<size_t>(address)) };

    auto [imageBase, offset] = mProcessData.decompose(address);

    if (!imageBase) {
        return result;
    }

    const auto& imageData = mProcessData.getImage(imageBase);
    result += std::format(L" {}+0x{:x}", imageData.name(), offset);

    if (!load(imageData)) {
        return result;
    }

    char buffer[sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(wchar_t)]{};
    auto symbol = reinterpret_cast<SYMBOL_INFOW*>(buffer);

    symbol->SizeOfStruct = sizeof(*symbol);
    symbol->MaxNameLen = MAX_SYM_NAME;

    DWORD64 displacement;
    if (!::SymFromAddrW(mProcess, reinterpret_cast<DWORD64>(address), &displacement, symbol)) {
        return result;
    }

    result += std::format(L" {}!{}+0x{:x}", imageData.name(), symbol->Name, displacement);

    IMAGEHLP_LINEW64 line{};
    line.SizeOfStruct = sizeof(line);
    DWORD lineDisplacement;
    if (!::SymGetLineFromAddrW64(mProcess, reinterpret_cast<DWORD64>(address), &lineDisplacement, &line)) {
        return result;
    }
    result += std::format(L" {}:{}+0x{:x}", line.FileName, line.LineNumber, lineDisplacement);
    return result;
}

bool Symbolicator::load(const ImageData& imageData)
{
    auto [it, isNew] = mModuleMap.emplace(std::make_pair(imageData.base(), 0));

    if (!isNew) {
        auto & [imageBase, module_] = *it;
        return bool(module_);
    }

    const wchar_t* imagePath = imageData.path().c_str();

    SYMSRV_INDEX_INFOW indexInfo{};
    indexInfo.sizeofstruct = sizeof(indexInfo);
    if (!::SymSrvGetFileIndexInfoW(imagePath, &indexInfo, 0)) {
        return false;
    }

    std::wcout << L"Downloading symbols file " << indexInfo.pdbfile << L"..." << std::endl;

    wchar_t foundFile[MAX_PATH + 1]{};
    if (!::SymFindFileInPathW(mProcess, nullptr, indexInfo.pdbfile,
        &indexInfo.guid, indexInfo.age, 0, SSRVOPT_GUIDPTR, foundFile,
        nullptr, nullptr)) {
        return false;
    }

    const wchar_t* imageName = imageData.name().c_str();
    auto module_ = ::SymLoadModuleExW(
        mProcess, nullptr, imagePath, imageName,
        reinterpret_cast<DWORD64>(imageData.base()), 0, nullptr, 0);
    if (!module_) {
        return false;
    }

    IMAGEHLP_MODULEW64 moduleInfo{};
    moduleInfo.SizeOfStruct = sizeof moduleInfo;
    if (!::SymGetModuleInfoW64(mProcess, module_, &moduleInfo)) {
        ::SymUnloadModule64(mProcess, module_);
        return false;
    }

    it->second = module_;
    return true;
}

bool Symbolicator::loadWithHint(const std::wstring& imageName, const std::wstring& imagePath, const std::wstring& symbolName, void* symbolAddress)
{
    SYMSRV_INDEX_INFOW indexInfo{};
    indexInfo.sizeofstruct = sizeof(indexInfo);
    if (!::SymSrvGetFileIndexInfoW(imagePath.c_str(), &indexInfo, 0)) {
        return false;
    }

    std::wcout << L"Downloading symbols file " << indexInfo.pdbfile << L"..." << std::endl;

    wchar_t foundFile[MAX_PATH + 1]{};
    if (!::SymFindFileInPathW(mProcess, nullptr, indexInfo.pdbfile,
        &indexInfo.guid, indexInfo.age, 0, SSRVOPT_GUIDPTR, foundFile,
        nullptr, nullptr)) {
        return false;
    }

    auto module_ = ::SymLoadModuleExW(
        mProcess, nullptr, imagePath.c_str(), imageName.c_str(),
        0, 0, nullptr, 0);
    if (!module_) {
        return false;
    }

    IMAGEHLP_MODULEW64 moduleInfo{};
    moduleInfo.SizeOfStruct = sizeof moduleInfo;
    if (!::SymGetModuleInfoW64(mProcess, module_, &moduleInfo)) {
        ::SymUnloadModule64(mProcess, module_);
        return false;
    }

    SYMBOL_INFOW symbol{};
    symbol.SizeOfStruct = sizeof (symbol);
    symbol.MaxNameLen = 0;
    if (!::SymFromNameW(mProcess, std::format(L"{}!{}", imageName, symbolName).c_str(), &symbol)) {
        ::SymUnloadModule64(mProcess, module_);
        return false;
    }

    bool isOnNextPage = (reinterpret_cast<DWORD64>(symbolAddress) & 0xFFFUi64) < (symbol.Address & 0xFFFUi64);
    DWORD64 symbolPage = reinterpret_cast<DWORD64>(symbolAddress) & ~0xFFFUi64;
    if (isOnNextPage) {
        symbolPage -= 0x1000Ui64;
    }

    DWORD64 guessedImageBase = symbolPage - ((symbol.Address - moduleInfo.BaseOfImage) & ~0xFFFUi64);

    ::SymUnloadModule64(mProcess, module_);

    ImageData imageData{ reinterpret_cast<void*>(guessedImageBase), moduleInfo.ImageSize, imagePath };
    mProcessData.addImage(std::move(imageData));

    module_ = ::SymLoadModuleExW(
        mProcess, nullptr, imagePath.c_str(), imageName.c_str(),
        guessedImageBase, 0, nullptr, 0);
    if (!module_) {
        return false;
    }

    moduleInfo.SizeOfStruct = sizeof moduleInfo;
    if (!::SymGetModuleInfoW64(mProcess, module_, &moduleInfo)) {
        ::SymUnloadModule64(mProcess, module_);
        return false;
    }

    mModuleMap.emplace(std::make_pair(reinterpret_cast<void*>(guessedImageBase), module_));
    return true;
}
