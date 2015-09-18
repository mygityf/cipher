/*
** Copyright (C) 2014 Wang Yaofu
** All rights reserved.
**
**Author:Wang Yaofu voipman@qq.com
**Description: The source file of class CStringUitls.
*/
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cstdarg>
#include <iomanip>
#include "stringutils.h"
namespace common {
    const char kWhitespaceASCII[] =
    {
        0x09,    // <control-0009> to <control-000D>
        0x0A,
        0x0B,
        0x0C,
        0x0D,
        0x20,    // Space
        0
    };

    template<typename STR>
    void TrimStringT(const STR& input,
        const typename STR::value_type trim_chars[],
        TrimOption option,
        STR* output) {
        // Find the edges of leading/trailing whitespace as desired.
        const typename STR::size_type last_char = input.length() - 1;
        const typename STR::size_type first_good_char = (option & kTrimLeading) ?
            input.find_first_not_of(trim_chars) : 0;
        const typename STR::size_type last_good_char = (option & kTrimTrailing) ?
            input.find_last_not_of(trim_chars) : last_char;

        // When the string was all whitespace, report that we stripped off
        // whitespace from whichever position the caller was interested in.
        // For empty input, we stripped no whitespace, but we still need to
        // clear |output|.
        if (input.empty() ||
            (first_good_char == STR::npos) || (last_good_char == STR::npos)) {
                output->clear();
                return;
        }

        // Trim the whitespace.
        *output =
            input.substr(first_good_char, last_good_char - first_good_char + 1);
    }

    void StrUtils::TrimWhitespace(const std::string& input,
        TrimOption option,
        std::string* output) {
        TrimStringT(input, kWhitespaceASCII, option, output);
    }

    void StrUtils::ReplaceString(const std::string& input,
        const std::string& old_val,
        const std::string& new_val,
        std::string* output) {
        if (old_val.empty()) {
            return;
        }

        std::ostringstream ss;
        std::string::size_type pos = 0;
        std::string::size_type pos_prev = 0;

        while (pos != std::string::npos) {
            pos_prev = pos;
            if ((pos = input.find(old_val, pos)) != std::string::npos) {
                if (pos > pos_prev) {
                    ss << input.substr(pos_prev, pos - pos_prev);
                }
                ss << new_val;
                pos += old_val.length();
            } else {
                if (pos_prev + 1 <= input.length()) {
                    ss << input.substr(pos_prev);
                }
                break;
            }
        }

        *output = ss.str();
    }

    std::string StrUtils::ToLowerCase(const std::string& input) {
        if (input.empty()) {
            return std::string();
        }
        std::string output(input);
        std::string::pointer begin = &output[0];
        std::string::pointer end = begin + output.size();
        for (; begin < end; ++begin) {
            *begin = tolower(*begin);
        }
        return output;
    }

    std::string StrUtils::ToUpperCase(const std::string& input) {
        if (input.empty()) {
            return std::string();
        }
        std::string output(input);
        std::string::pointer begin = &output[0];
        std::string::pointer end = begin + output.size();
        for (; begin < end; ++begin) {
            *begin = toupper(*begin);
        }
        return output;
    }

    template <typename STR>
    void SplitStringT(const STR& str,
        const STR& s,
        std::vector<STR>* r) {
        r->clear();
        typename STR::size_type begin_index = 0;
        while (true) {
            const typename STR::size_type end_index = str.find(s, begin_index);
            if (end_index == STR::npos) {
                const STR term = str.substr(begin_index);
                r->push_back(term);
                return;
            }
            const STR term = str.substr(begin_index, end_index - begin_index);
            r->push_back(term);
            begin_index = end_index + s.size();
        }
    }

    void StrUtils::SplitString(const std::string& str,
        const std::string& s,
        std::vector<std::string>* r) {
        SplitStringT(str, s, r);
    }
    bool StrUtils::Split(const std::string& s,
          char sep,
          std::string& first,
          std::string& second) {
      std::string::size_type sep_pos = s.find(sep);
      first = s.substr(0, sep_pos);
      if (sep_pos!=std::string::npos)
          second = s.substr(sep_pos+1);
      return true;
    }
    int StrUtils::stoi(const std::string &str) {
        return ::atoi(str.c_str());
    }
    long StrUtils::stol(const std::string &str, const int base) {
        char *ep;
        return ::strtol(str.c_str(), &ep, base);
    }
    long long StrUtils::stoll(const std::string &str, const int base) {
        char *ep;
        return ::strtoll(str.c_str(), &ep, base);
    }
    unsigned long StrUtils::stoul(const std::string &str, const int base) {
        char *ep;
        return ::strtoul(str.c_str(), &ep, base);
    }
    unsigned long long StrUtils::stoull(const std::string &str, const int base) {
        char *ep;
        return ::strtoull(str.c_str(), &ep, base);
    }
    float StrUtils::stof(const std::string& str) {
        char *ep;
        return ::strtof(str.data(), &ep);
    }
    double StrUtils::stod(const std::string& str) {
        char *ep;
        return ::strtold(str.data(), &ep);
    }
    long double StrUtils::stold(const std::string& str) {
        char *ep;
        return ::strtod(str.data(), &ep);
    }
    std::string StrUtils::JoinStr(std::vector<std::string>& parts,
        const std::string& delimiter) {
        if (parts.empty()) {
            return "";
        }
        std::stringstream  ss;
        for (size_t i = 0; i < parts.size() - 1; ++i) {
            ss << parts[i];
            ss << delimiter;
        }
        ss << parts[parts.size() - 1]; //no delimiter at last
        return ss.str();
    }

    std::string StrUtils::JoinStr(std::vector<std::string>& parts, char delimiter) {
        std::string tmp;
        tmp.assign(1, delimiter);
        return JoinStr(parts, tmp);
    }

    std::string StrUtils::Hex(const char* cpSrcStr, int len, bool isUpper) {
        if (cpSrcStr == NULL) {
            return "";
        }
        std::string ret(len * 2, 0x00);
        const char* hex = isUpper ? "0123456789ABCDEF" : "0123456789abcdef";
        for (size_t i = 0; i < len; ++i) {
            unsigned char v = static_cast<unsigned char>(cpSrcStr[i]);
            ret[2*i]  = hex[(v >> 4) & 0x0f];
            ret[2*i+1] = hex[ v & 0x0f];
        }
        return ret;
    }

    std::string StrUtils::Hex(const std::string& srcStr, bool isUpper) {
        return Hex(srcStr.c_str(), srcStr.size(), isUpper);
    }
    std::string StrUtils::Hex(const char ch, bool isUpper) {
        return Hex(&ch, 1, isUpper);
    }
    namespace {
        char asc_bcd(const char *what) {
            unsigned char digit;
            unsigned char m;

            digit = (what[0] >= 'a' ? ((what[0]) - 'a') + 10 : (what[0] - '0'));
            digit *= 16;
            digit += (what[1] >= 'a' ? ((what[1]) - 'a') + 10 : (what[1] - '0'));
            return(digit);
        }
    }

    std::string StrUtils::fromHex(const char* from, size_t len) {
        std::string ret(len / 2, 0x00);
        for (size_t ii = 0; ii < len / 2; ii++)
            ret[ii] = asc_bcd(from + ii * 2);
        return ret;
    }

    std::string StrUtils::fromHex(const std::string& from) {
        return fromHex(from.c_str(), from.length());
    }

    int StrUtils::fromHex(const char* from, char* to) {
        int len = strlen(from)/2;
        for (size_t ii = 0; ii < len; ii++)
            to[ii] = asc_bcd(from + ii * 2);
        return len;
    }

    int StrUtils::HexStr2Int(const char* aStr, int len) {
        int i, res = 0;

        for(i = 0; i < len; i++) {
            res *= 16;
            if ((aStr[i] >= '0') && (aStr[i] <= '9')) {
                res += aStr[i] - '0';
            } else if ((aStr[i] >= 'a') && (aStr[i] <= 'f')) {
                res += aStr[i] - 'a' + 10;
            } else if ((aStr[i] >= 'A') && (aStr[i] <= 'F')) {
                res += aStr[i] - 'A' + 10;
            } else {
                return 0;
            }
        }
        return res;
    }
    int StrUtils::HexStr2Int(const std::string& srcStr) {
        return HexStr2Int(srcStr.c_str(), srcStr.length());
    }
    int StrUtils::Int2HexInt(int src) {
        std::string hexStr;
        Format(hexStr, "%d", src);
        return HexStr2Int(hexStr.c_str(), hexStr.length());
    }
    bool StrUtils::IsNumber(char ch) {
        return (ch >= '0' && ch <= '9');
    }

    bool StrUtils::IsLetter(char ch) {
        return ((ch >= 'a' && ch <= 'z') || ((ch >= 'A') && (ch <= 'Z')));
    }

    bool StrUtils::IsUnderLine(char ch) {
        return (ch == '_');
    }

    bool StrUtils::Format(std::string &outStr, const char *format, ...) {
        char* mem;
        va_list ap;
        va_start(ap, format);
        if (vasprintf(&mem, format, ap) < 0) {
            va_end(ap);
            return false;
        }
        outStr = mem;
        va_end(ap);
        free(mem);
        return true;
    }

    unsigned int StrUtils::ELFhash(const char* aStr, unsigned int aHashMod) {
        unsigned int h = 0;

        while (*aStr) {
            h = (h << 4) + *aStr++;
            unsigned int g = h & 0xF0000000;
            if (g) h ^= g >> 24;
            h &= ~g;
        }

        return h % aHashMod;
    }

    unsigned int StrUtils::HfIp(const char* aStr, unsigned int aHashMod) {
        unsigned int n = 0;
        unsigned char* b = (unsigned char*)&n;

        for (unsigned int i = 0; aStr[i] != 0x00; i++)
            b[i%4] ^= aStr[i];

        return n % aHashMod;
    }

    unsigned int StrUtils::hf(const char* aStr, unsigned int aHashMod) {
        int result = 0;
        const char* ptr = aStr;
        int c;

        for (int i = 1; (c = *ptr++); i++)
            result += c * 3 * i;
        if (result < 0) result = -result;
        return result % aHashMod;
    }

}// namespace common
