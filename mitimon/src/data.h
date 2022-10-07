#ifndef DATA_H
#define DATA_H

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>

class ImageData;

class ProcessData {
public:
    ProcessData(uint32_t pid, const std::wstring& imageName) :
        mPid{ pid },
        mImageName{ imageName },
        mImageMap{}
    {
    };

    static bool add(uint32_t pid, const std::wstring& imageName);
    static bool remove(uint32_t pid);
    static bool exists(uint32_t pid);
    static ProcessData& get(uint32_t pid);

private:
    static std::unordered_map<uint32_t, ProcessData> processMap;

public:
    uint32_t pid() const { return mPid; }
    const std::wstring& imageName() const { return mImageName; }

    bool addImage(ImageData&& imageData);
    bool removeImage(void* imageBase);
    ImageData& getImage(void* imageBase);

    std::pair<void*, size_t> decompose(void* address);

private:
    uint32_t mPid;
    std::wstring mImageName;
    std::unordered_map<void*, ImageData> mImageMap;
};



class ImageData {
public:
    static bool add(uint32_t pid, void* imageBase, size_t imageSize, const std::wstring& imageName);
    static bool remove(uint32_t pid, void* imageBase);

    static std::wstring nameFromEtwName(const std::wstring& imageName);
    static std::wstring pathFromEtwName(const std::wstring& imageName);

public:
    ImageData(void* base, size_t size, const std::wstring& name) :
        mBase{ base },
        mSize{ size },
        mName{ nameFromEtwName(name) },
        mPath{ pathFromEtwName(name) }
    {
    }

    void* base() const { return mBase; }
    size_t size() const { return mSize; }
    const std::wstring& name() const { return mName; }
    const std::wstring& path() const { return mPath; }

private:
    void* mBase;
    size_t mSize;
    std::wstring mName;
    std::wstring mPath;
};

#endif // DATA_H
