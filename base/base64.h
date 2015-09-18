/*
** Copyright (C) 2014 Wang Yaofu
** All rights reserved.
**
**Author:Wang Yaofu voipman@qq.com
**Description: The header file of base64.
*/
#ifndef _BASE64UTILS_H_
#define _BASE64UTILS_H_
#include <string>
bool Base64Encode(const std::string& input, std::string* output);
bool Base64Encode(const std::string& input, char* output, size_t* len);

bool Base64Decode(const std::string& input, std::string* output);
bool Base64Decode(const std::string& input, char* output, size_t* len);

#endif // #define _BASE64UTILS_H_
