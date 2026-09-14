#include "UnrealHttpTransport.h"

#include "HttpModule.h"
#include "Interfaces/IHttpRequest.h"
#include "Interfaces/IHttpResponse.h"
#include "Async/Async.h"
#include "HAL/Event.h"
#include "HAL/PlatformProcess.h"
#include "Templates/SharedPointer.h"

#include <algorithm>
#include <atomic>
#include <cctype>

namespace syslocker::nightflyer
{
    namespace
    {
        // Owns the completion event for its whole lifetime. The completion
        // lambda holds a shared reference to the slot, so a late completion
        // after a caller timeout still writes into valid (ignored) memory
        // instead of a pooled or freed event.
        struct ExchangeSlot final
        {
            ExchangeSlot() { Done = FPlatformProcess::CreateSynchEvent(false); }
            ~ExchangeSlot() { delete Done; }
            ExchangeSlot(const ExchangeSlot&) = delete;
            ExchangeSlot& operator=(const ExchangeSlot&) = delete;

            FEvent* Done = nullptr;
            std::atomic<bool> Signalled{false};
            long Status = 0;
            std::string Body;
            std::string Error;
            std::map<std::string, std::string> Headers;
        };

        std::string narrow(const FString& value)
        {
            return std::string(TCHAR_TO_UTF8(*value));
        }

        FString widen(std::string_view value)
        {
            const FUTF8ToTCHAR converted(value.data(), static_cast<int32>(value.size()));
            return FString(converted.Length(), converted.Get());
        }

        class UnrealHttpClient final : public IHttpClient
        {
        public:
            UnrealHttpClient(std::chrono::milliseconds timeout, std::string userAgent)
                : timeoutSeconds_(static_cast<float>(timeout.count()) / 1000.0f), userAgent_(std::move(userAgent)) {}

            HttpResponse postJson(std::string_view url, std::string_view body, std::string_view proof) override
            {
                if (IsInGameThread())
                {
                    // The engine pumps HTTP on the game thread; blocking here
                    // would wait forever on our own completion callback.
                    return failure("Nightflyer network calls must run off the game thread");
                }

                const auto slot = std::make_shared<ExchangeSlot>();
                if (!slot->Done)
                {
                    return failure("The engine could not allocate a Nightflyer completion event");
                }

                const FString targetUrl = widen(url);
                const FString requestBody = widen(body);
                const FString proofHeader = widen(proof);
                const float timeoutSeconds = timeoutSeconds_;
                const std::string userAgent = userAgent_;

                // Requests live on the game thread from creation through
                // completion; the shared slot carries the result back to the
                // blocked worker thread.
                AsyncTask(ENamedThreads::GameThread, [slot, targetUrl, requestBody, proofHeader, timeoutSeconds, userAgent]()
                {
                    const auto& module = FHttpModule::Get();
                    const auto request = module.CreateRequest();
                    request->SetURL(targetUrl);
                    request->SetVerb(TEXT("POST"));
                    request->SetContentAsString(requestBody);
                    request->SetTimeout(FMath::Max(timeoutSeconds, 1.0f));
                    request->AppendToHeader(TEXT("Content-Type"), TEXT("application/json"));
                    request->AppendToHeader(TEXT("Accept"), TEXT("application/json"));
                    request->AppendToHeader(TEXT("Cache-Control"), TEXT("no-store"));
                    request->AppendToHeader(TEXT("User-Agent"), widen(userAgent));
                    request->AppendToHeader(TEXT("Nightflyer-Proof"), proofHeader);

                    // The HTTP manager retains a started request. The callback
                    // only captures the exchange slot, avoiding a request/delegate
                    // reference cycle after completion.
                    request->OnProcessRequestComplete().BindLambda([slot](FHttpRequestPtr, FHttpResponsePtr response, bool succeeded)
                    {
                        if (!succeeded || !response)
                        {
                            slot->Error = "The engine HTTP request failed";
                        }
                        else
                        {
                            const auto content = response->GetContent();
                            if (content.Num() > 1048576)
                            {
                                slot->Error = "response body exceeds 1 MiB limit";
                            }
                            else
                            {
                                slot->Status = static_cast<long>(response->GetResponseCode());
                                slot->Body.assign(reinterpret_cast<const char*>(content.GetData()), static_cast<std::size_t>(content.Num()));
                                for (const FString& header : response->GetAllHeaders())
                                {
                                    // Engine headers arrive as "Name: Value".
                                    const int32 separator = header.Find(TEXT(":"), ESearchCase::IgnoreCase, ESearchDir::FromStart);
                                    if (separator > 0)
                                    {
                                        auto name = narrow(header.Left(separator));
                                        std::transform(name.begin(), name.end(), name.begin(), [](unsigned char character)
                                        {
                                            return static_cast<char>(std::tolower(character));
                                        });
                                        const auto value = narrow(header.Mid(separator + 1).TrimStartAndEnd());
                                        // The protocol matches header names case-insensitively.
                                        slot->Headers[name] = value;
                                    }
                                }
                            }
                        }
                        slot->Signalled.store(true);
                        slot->Done->Trigger();
                    });

                    if (!request->ProcessRequest())
                    {
                        slot->Error = "The engine HTTP request could not be started";
                        slot->Signalled.store(true);
                        slot->Done->Trigger();
                    }
                });

                // Grace beyond the request timeout covers engine scheduling. A
                // timeout leaves the slot alive for the eventual callback.
                const double graceSeconds = 30.0;
                slot->Done->Wait(static_cast<uint32>((timeoutSeconds_ + graceSeconds) * 1000.0f));

                if (!slot->Signalled.load())
                {
                    return failure("The Nightflyer request timed out");
                }
                return HttpResponse{slot->Status, std::move(slot->Body), std::move(slot->Error), std::move(slot->Headers)};
            }

        private:
            static HttpResponse failure(std::string message)
            {
                HttpResponse response;
                response.status = 0;
                response.error = std::move(message);
                return response;
            }

            float timeoutSeconds_;
            std::string userAgent_;
        };
    }

    std::shared_ptr<IHttpClient> makeUnrealHttpTransport(std::chrono::milliseconds timeout, std::string userAgent)
    {
        return std::make_shared<UnrealHttpClient>(timeout, std::move(userAgent));
    }
}
