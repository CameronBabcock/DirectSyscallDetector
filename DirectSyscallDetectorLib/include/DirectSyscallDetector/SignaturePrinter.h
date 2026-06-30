/*
Nirvana v2: Electric Boogaloo
Return-provenance detection for raw and gadgeted direct syscalls.

Project: DirectSyscallDetector
Copyright 2026 Cameron Babcock

Author / Researcher: Cameron Babcock
GitHub: https://github.com/CameronBabcock
Email: Cameron@CameronBabcock.net
LinkedIn: https://www.linkedin.com/in/cameronbabcock/

Licensed under the Apache License, Version 2.0. See LICENSE and NOTICE.
For EDR, CNO, pentest agent work, endpoint security, Windows internals,
or detection engineering work,
please contact Cameron Babcock using the email or LinkedIn profile above.
*/

#pragma once

#include <array>
#include <cstdint>
#include <format>
#include <memory>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>

namespace DirectSyscallDetector
{
    struct ArgumentSnapshot
    {
        std::uint64_t FirstArgument{};
        std::uint64_t StackArgument5{};
        std::uint64_t StackArgument6{};
        bool HasStackArgument5{};
        bool HasStackArgument6{};
    };

    class ISyscallSignature
    {
    public:
        virtual ~ISyscallSignature() = default;

        [[nodiscard]] virtual std::string FormatArguments(const ArgumentSnapshot& snapshot) const = 0;
        [[nodiscard]] virtual std::string_view FunctionName() const noexcept = 0;
        [[nodiscard]] virtual std::size_t ArgumentCount() const noexcept = 0;
    };

    template <typename TFunction>
    struct FunctionTraits;

    template <typename TReturn, typename... TArgs>
    struct FunctionTraits<TReturn(TArgs...)>
    {
        using ReturnType = TReturn;
        using ArgumentTuple = std::tuple<TArgs...>;
        constexpr static std::size_t ArgumentCount{ sizeof...(TArgs) };
    };

    template <typename TArgument>
    struct ArgumentFormattingTraits
    {
        using ArgumentType = std::remove_cv_t<std::remove_reference_t<TArgument>>;

        constexpr static bool IsSmallIntegral{
            std::is_integral_v<ArgumentType> && sizeof(ArgumentType) <= sizeof(std::uint32_t)
        };
    };

    template <typename TArgument>
    [[nodiscard]] std::string FormatRawArgumentValue(const std::uint64_t rawValue)
    {
        if constexpr (ArgumentFormattingTraits<TArgument>::IsSmallIntegral)
        {
            return std::format("0x{:08X}", static_cast<std::uint32_t>(rawValue));
        }
        else
        {
            return std::format("0x{:016X}", rawValue);
        }
    }

    template <typename TArgument>
    [[nodiscard]] std::string FormatNamedArgument(
        const std::string_view argumentName,
        const std::string_view argumentTypeName,
        const std::uint64_t rawValue)
    {
        return std::format(
            "{}({})={}",
            argumentName,
            argumentTypeName,
            FormatRawArgumentValue<TArgument>(rawValue));
    }

    template <typename TFunction, std::size_t t_argumentCount>
    class SyscallSignature final : public ISyscallSignature
    {
    public:
        SyscallSignature(
            const std::string_view functionName,
            const std::array<std::string_view, t_argumentCount>& argumentNames,
            const std::array<std::string_view, t_argumentCount>& argumentTypeNames) :
            m_functionName{ functionName },
            m_argumentNames{ argumentNames },
            m_argumentTypeNames{ argumentTypeNames }
        {
            static_assert(FunctionTraits<TFunction>::ArgumentCount == t_argumentCount);
        }

        [[nodiscard]] std::string FormatArguments(const ArgumentSnapshot& snapshot) const override
        {
            std::string formatted{};

            // ThreadLastSystemCall gives argument one; the callback stack
            // snapshot gives arguments five and six. We do not invent 2-4.
            if constexpr (t_argumentCount >= 1)
            {
                using ArgumentType = std::tuple_element_t<0, typename FunctionTraits<TFunction>::ArgumentTuple>;
                formatted += FormatNamedArgument<ArgumentType>(
                    m_argumentNames[0],
                    m_argumentTypeNames[0],
                    snapshot.FirstArgument);
            }

            if constexpr (t_argumentCount >= 5)
            {
                if (snapshot.HasStackArgument5)
                {
                    if (false == formatted.empty())
                    {
                        formatted += ", ";
                    }
                    using ArgumentType = std::tuple_element_t<4, typename FunctionTraits<TFunction>::ArgumentTuple>;
                    formatted += FormatNamedArgument<ArgumentType>(
                        m_argumentNames[4],
                        m_argumentTypeNames[4],
                        snapshot.StackArgument5);
                }
            }

            if constexpr (t_argumentCount >= 6)
            {
                if (snapshot.HasStackArgument6)
                {
                    if (false == formatted.empty())
                    {
                        formatted += ", ";
                    }
                    using ArgumentType = std::tuple_element_t<5, typename FunctionTraits<TFunction>::ArgumentTuple>;
                    formatted += FormatNamedArgument<ArgumentType>(
                        m_argumentNames[5],
                        m_argumentTypeNames[5],
                        snapshot.StackArgument6);
                }
            }

            if (formatted.empty())
            {
                formatted = "(no printable arguments)";
            }

            return formatted;
        }

        [[nodiscard]] std::string_view FunctionName() const noexcept override
        {
            return m_functionName;
        }

        [[nodiscard]] std::size_t ArgumentCount() const noexcept override
        {
            return t_argumentCount;
        }

    private:
        std::string_view m_functionName{};
        std::array<std::string_view, t_argumentCount> m_argumentNames{};
        std::array<std::string_view, t_argumentCount> m_argumentTypeNames{};
    };

    template <typename TFunction, std::size_t t_argumentCount>
    [[nodiscard]] std::unique_ptr<const ISyscallSignature> MakeSyscallSignature(
        const std::string_view functionName,
        const std::array<std::string_view, t_argumentCount>& argumentNames,
        const std::array<std::string_view, t_argumentCount>& argumentTypeNames)
    {
        return std::make_unique<SyscallSignature<TFunction, t_argumentCount>>(
            functionName,
            argumentNames,
            argumentTypeNames);
    }
}
