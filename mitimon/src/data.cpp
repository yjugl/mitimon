#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "winkrabs.h"

#include "data.h"

std::unordered_map<uint32_t, ProcessData> ProcessData::processMap;

ImageData ProcessData::kernelImageData;

bool ProcessData::add(uint32_t pid, const std::wstring& imageName)
{
    auto [it, isNew] = processMap.emplace(std::make_pair(pid, ProcessData(pid, imageName)));
    return isNew;
}

bool ProcessData::remove(uint32_t pid)
{
    return bool(processMap.erase(pid));
}

bool ProcessData::exists(uint32_t pid)
{
    return bool(processMap.count(pid));
}

ProcessData& ProcessData::get(uint32_t pid)
{
    return processMap.at(pid);
}

bool ProcessData::addImage(const ImageData& imageData)
{
    return addImage(ImageData(imageData));
}

bool ProcessData::addImage(ImageData&& imageData)
{
    auto [it, isNew] = mImageMap.emplace(std::make_pair(imageData.base(), std::move(imageData)));
    return isNew;
}

bool ProcessData::removeImage(void* imageBase)
{
    return bool(mImageMap.erase(imageBase));
}

ImageData& ProcessData::getImage(void* imageBase)
{
    return mImageMap.at(imageBase);
}

std::pair<void*, size_t> ProcessData::decompose(void* address)
{
    for (auto const& [imageBase, imageData] : mImageMap) {
        auto imageEnd = reinterpret_cast<void*>(
            reinterpret_cast<size_t>(imageBase) + imageData.size()
        );
        if (imageBase <= address && address < imageEnd) {
            auto offset = reinterpret_cast<size_t>(address) - reinterpret_cast<size_t>(imageBase);
            return std::make_pair(imageBase, offset);
        }
    }
    return std::make_pair(nullptr, 0);
}


bool ImageData::add(uint32_t pid, void* imageBase, std::size_t imageSize, const std::wstring& imageName)
{
    if (!ProcessData::exists(pid)) {
        return false;
    }
    auto& processData = ProcessData::get(pid);
    return processData.addImage(ImageData(imageBase, imageSize, imageName));
}

bool ImageData::remove(uint32_t pid, void* imageBase)
{
    if (!ProcessData::exists(pid)) {
        return false;
    }
    auto& processData = ProcessData::get(pid);
    return processData.removeImage(imageBase);
}

std::wstring ImageData::nameFromEtwName(const std::wstring& imageName)
{
    size_t start = imageName.rfind(L"\\");
    if (start == std::wstring::npos) {
        start = 0;
    }
    else {
        start += 1;
    }

    size_t count = imageName.length() - start;
    if (imageName.ends_with(L".DLL") || imageName.ends_with(L".EXE") ||
        imageName.ends_with(L".dll") || imageName.ends_with(L".exe")) {
        count -= 4;
    }

    return imageName.substr(start, count);
}

std::wstring ImageData::pathFromEtwName(const std::wstring& imageName)
{
    if (!imageName.starts_with(L"\\")) {
        return imageName;
    }

    std::wstring result(L"\\\\?\\GLOBALROOT");
    result += imageName;
    return result;
}
