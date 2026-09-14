#include "syslocker/nightflyer.hpp"
#include <filesystem>
#include <fstream>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <wincrypt.h>

namespace syslocker::nightflyer
{
    namespace
    {
        constexpr std::uintmax_t maxStateBytes = 1048576;
        // DPAPI framing can make protected data larger than its plaintext.
        constexpr std::uintmax_t maxProtectedStateBytes = maxStateBytes * 2;

        class VectorWiper final
        {
        public:
            explicit VectorWiper(std::vector<unsigned char>& value) : value_(value) {}
            ~VectorWiper() { if (!value_.empty()) SecureZeroMemory(value_.data(), value_.size()); }
            VectorWiper(const VectorWiper&) = delete;
            VectorWiper& operator=(const VectorWiper&) = delete;
        private:
            std::vector<unsigned char>& value_;
        };

        std::filesystem::path temporaryPath(const std::filesystem::path& path)
        {
            GUID identifier{};
            wchar_t suffix[39]{};
            if (CoCreateGuid(&identifier) != S_OK || StringFromGUID2(identifier, suffix, 39) == 0)
                throw Error(Failure::local_failure, "Could not allocate a temporary Nightflyer state name.");
            return path.parent_path() / (L"." + path.filename().wstring() + L"." + suffix + L".tmp");
        }

        class FileLock final
        {
        public:
            explicit FileLock(const std::filesystem::path& path)
            {
                handle_ = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
                if (handle_ == INVALID_HANDLE_VALUE) throw Error(Failure::local_failure, "Could not open the Nightflyer state lock file.");
                OVERLAPPED operation{};
                if (!LockFileEx(handle_, LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &operation))
                {
                    CloseHandle(handle_); handle_ = INVALID_HANDLE_VALUE;
                    throw Error(Failure::local_failure, "Could not lock the Nightflyer state file.");
                }
            }
            ~FileLock()
            {
                if (handle_ == INVALID_HANDLE_VALUE) return;
                OVERLAPPED operation{}; (void)UnlockFileEx(handle_, 0, 1, 0, &operation); CloseHandle(handle_);
            }
            FileLock(const FileLock&) = delete;
            FileLock& operator=(const FileLock&) = delete;
        private:
            HANDLE handle_ = INVALID_HANDLE_VALUE;
        };

        class LocalBlob final
        {
        public:
            DATA_BLOB value{};
            ~LocalBlob() { if (value.pbData) { SecureZeroMemory(value.pbData, value.cbData); LocalFree(value.pbData); } }
        };

        class DpapiStateStore final : public IStateStore
        {
        public:
            explicit DpapiStateStore(std::string path) : path_(std::filesystem::absolute(std::move(path))), lockPath_(path_.wstring() + L".lock") {}

            std::optional<std::vector<unsigned char>> load() override
            {
                ensureDirectory(); FileLock lock(lockPath_);
                if (!std::filesystem::exists(path_)) return std::nullopt;
                const auto size = std::filesystem::file_size(path_);
                if (size == 0 || size > maxProtectedStateBytes) throw Error(Failure::invalid_state, "Protected Nightflyer state has an invalid size.");
                std::ifstream input(path_, std::ios::binary);
                std::vector<unsigned char> encrypted((std::istreambuf_iterator<char>(input)), {});
                VectorWiper wipeEncrypted(encrypted);
                if (input.bad()) throw Error(Failure::local_failure, "Could not read protected Nightflyer state.");
                DATA_BLOB source{static_cast<DWORD>(encrypted.size()), encrypted.data()}; LocalBlob result;
                if (!CryptUnprotectData(&source, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &result.value))
                    throw Error(Failure::local_failure, "Windows could not unprotect Nightflyer state for this user.");
                if (result.value.cbData == 0 || result.value.cbData > maxStateBytes)
                    throw Error(Failure::invalid_state, "Protected Nightflyer state has an invalid payload size.");
                std::vector<unsigned char> plain(result.value.pbData, result.value.pbData + result.value.cbData);
                return plain;
            }

            void save(const std::vector<unsigned char>& value) override
            {
                if (value.empty() || value.size() > maxStateBytes) throw Error(Failure::local_failure, "Nightflyer state has an invalid size.");
                ensureDirectory(); FileLock lock(lockPath_);
                DATA_BLOB source{static_cast<DWORD>(value.size()), const_cast<BYTE*>(value.data())}; LocalBlob protectedValue;
                if (!CryptProtectData(&source, L"System Locker Nightflyer", nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &protectedValue.value))
                    throw Error(Failure::local_failure, "Windows could not protect Nightflyer state for this user.");
                if (protectedValue.value.cbData == 0 || protectedValue.value.cbData > maxProtectedStateBytes)
                    throw Error(Failure::local_failure, "Windows returned protected Nightflyer state with an invalid size.");
                const auto temporary = temporaryPath(path_);
                try
                {
                    HANDLE output = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
                    if (output == INVALID_HANDLE_VALUE) throw Error(Failure::local_failure, "Could not create temporary protected Nightflyer state.");
                    DWORD written = 0;
                    const bool okay = WriteFile(output, protectedValue.value.pbData, protectedValue.value.cbData, &written, nullptr)
                        && written == protectedValue.value.cbData && FlushFileBuffers(output);
                    CloseHandle(output);
                    if (!okay) throw Error(Failure::local_failure, "Could not flush protected Nightflyer state.");
                    if (!MoveFileExW(temporary.c_str(), path_.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                        throw Error(Failure::local_failure, "Could not atomically replace protected Nightflyer state.");
                }
                catch (...)
                {
                    std::error_code ignored; std::filesystem::remove(temporary, ignored); throw;
                }
            }

            void erase() override
            {
                ensureDirectory(); FileLock lock(lockPath_); std::error_code error; std::filesystem::remove(path_, error);
                if (error) throw Error(Failure::local_failure, "Could not remove protected Nightflyer state.");
            }

            std::string lockIdentity() const override { return path_.string(); }

        private:
            void ensureDirectory() const
            {
                std::error_code error; std::filesystem::create_directories(path_.parent_path(), error);
                if (error) throw Error(Failure::local_failure, "Could not create the Nightflyer state directory.");
            }
            std::filesystem::path path_;
            std::filesystem::path lockPath_;
        };
    }
    std::unique_ptr<IStateStore> makeWindowsDpapiStateStore(std::string path) { return std::make_unique<DpapiStateStore>(std::move(path)); }
}
#else
namespace syslocker::nightflyer
{
    std::unique_ptr<IStateStore> makeWindowsDpapiStateStore(std::string)
    {
        throw Error(Failure::configuration, "Windows DPAPI state storage is unavailable on this platform; provide an OS key-store state adapter.");
    }
}
#endif
