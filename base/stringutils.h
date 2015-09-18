/*
** Copyright (C) 2014 Wang Yaofu
** All rights reserved.
**
**Author:Wang Yaofu voipman@qq.com
**Description: The header file of class CStringUitls.
*/
#pragma once
#include <string>
#include <sstream>
#include <vector>
#include <map>
#include <set>
#include <list>
#include <cctype>

namespace common {
    enum TrimOption {
        kTrimNone = 0,
        kTrimLeading = 1 << 0,
        kTrimTrailing = 1 << 1,
        kTrimAll = kTrimLeading | kTrimTrailing,
    };
    class StrUtils {
    public:
        static void TrimWhitespace(const std::string& input,
            TrimOption option, std::string* output);

        static void ReplaceString(const std::string& input,
            const std::string& old_val,
            const std::string& new_val,
            std::string* output);

        static std::string ReplaceString(const std::string& input,
            const std::string& old_val,
            const std::string& new_val) {
            std::string output;
            ReplaceString(input, old_val, new_val, &output);
            return output;
        }

        static void Trim(std::string& aStr, const std::string& aSep,
            TrimOption aOption = kTrimTrailing) {
            size_t pos = 0;
            if (aOption & kTrimLeading) {
                pos = aStr.find(aSep);
                if (pos != aStr.npos) {
                    aStr.erase(0, pos + 1);
                }
            }
            if (aOption & kTrimTrailing) {
                pos = aStr.rfind(aSep);
                if (pos != aStr.npos) {
                    aStr.erase(pos);
                }
            }
        }

        // ABC => abc
        static std::string ToLowerCase(const std::string& input);
        // str => STR
        static std::string ToUpperCase(const std::string& input);
        // 11&22&33 +& =>11 22 33 + &
        static void SplitString(const std::string& str,
            const std::string& s,
            std::vector<std::string>* r);
        // string to split string
        static bool Split(const std::string& s,
            char sep,
            std::string& first,
            std::string& second);
        // any to string.
        template <typename INT_TYPE>
        static std::string to_string(const INT_TYPE& aValue) {
            std::stringstream ss;
            ss << aValue;
            return ss.str();
        }

        template <typename K, typename V>
        static std::string to_string(const typename std::pair<K, V>& v) {
            std::ostringstream o;
            o << to_string(v.first) << ": " << to_string(v.second);
            return o.str();
        }

        template <typename T>
        static std::string to_string(const T& beg, const T& end) {
            std::ostringstream o;
            for (T it = beg; it != end; ++it) {
                if (it != beg)
                    o << ", ";
                o << to_string(*it);
            }
            return o.str();
        }

        template <typename T>
        static std::string to_string(const std::vector<T>& t) {
            std::ostringstream o;
            o << "[" << to_string(t.begin(), t.end()) << "]";
            return o.str();
        }

        template <typename T>
        static std::string to_string(const std::list<T>& t) {
            std::ostringstream o;
            o << "[" << to_string(t.begin(), t.end()) << "]";
            return o.str();
        }

        template <typename K, typename V>
        static std::string to_string(const std::map<K, V>& m) {
            std::ostringstream o;
            o << "{" << to_string(m.begin(), m.end()) << "}";
            return o.str();
        }

        template <typename T>
        static std::string to_string(const std::set<T>& s) {
            std::ostringstream o;
            o << "{" << to_string(s.begin(), s.end()) << "}";
            return o.str();
        }

        template <class Type>
        static Type stringToNum(const std::string& str) {
            std::istringstream iss(str);
            Type num;
            iss >> num;
            return num;
        }
        static int stoi(const std::string &str);
        static long stol(const std::string &str, const int base = 10);
        static long long stoll(const std::string &str, const int base = 10);
        static unsigned long stoul(const std::string &str, const int base = 10);
        static unsigned long long stoull(const std::string &str, const int base = 10);
        static float stof(const std::string& str);
        static double stod(const std::string& str);
        static long double stold(const std::string& str);

        // 11 22 33 + & => 11&22&33
        static std::string JoinStr(std::vector<std::string>& parts, char delimiter);
        // 11 22 33 + %% => 11%%22%%33
        static std::string JoinStr(std::vector<std::string>& parts, const std::string& delimiter);

        // 19AaZz\n => 31 39 41 61 5a 7a 0a
        static std::string Hex(const char* cpSrcStr, int len, bool isUpper = false);
        static std::string Hex(const std::string& srcStr, bool isUpper = false);
        static std::string Hex(const char ch, bool isUpper = false);
        static std::string fromHex(const char* from, size_t len);
        static int fromHex(const char* from, char* to);
        static std::string fromHex(const std::string& from);
        static int HexStr2Int(const char* aStr, int len);
        static int HexStr2Int(const std::string& srcStr);
        static int Int2HexInt(int src);
        static bool IsNumber(char ch);
        static bool IsLetter(char ch);
        static bool IsUnderLine(char ch);
        static bool Format(std::string &outStr, const char *format, ...);
        static unsigned int HfIp(const char* aStr, unsigned int aHashMod);
        static unsigned int hf(const char* aStr, unsigned int aHashMod);
        // System - v hash method, it is nice.
        static unsigned int ELFhash(const char* aStr, unsigned int aHashMod = 0x7FFFFFFF);
    };
} // namespace common
