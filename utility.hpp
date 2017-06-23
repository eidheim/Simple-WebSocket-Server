#ifndef SIMPLE_WEBSOCKET_SERVER_UTILITY_HPP
#define SIMPLE_WEBSOCKET_SERVER_UTILITY_HPP

#include <iostream>
#include <string>
#include <unordered_map>

// TODO when switching to c++14, use [[deprecated]] instead
#ifndef DEPRECATED
#ifdef __GNUC__
#define DEPRECATED __attribute__((deprecated))
#elif defined(_MSC_VER)
#define DEPRECATED __declspec(deprecated)
#else
#define DEPRECATED
#endif
#endif

namespace SimpleWeb {
#ifndef CASE_INSENSITIVE_EQUAL_AND_HASH
#define CASE_INSENSITIVE_EQUAL_AND_HASH

inline bool case_insensitive_equal(const std::string &str1, const std::string &str2) {
  return str1.size() == str2.size() &&
         std::equal(str1.begin(), str1.end(), str2.begin(), [](char a, char b) {
           return tolower(a) == tolower(b);
         });
}
class CaseInsensitiveEqual {
public:
  bool operator()(const std::string &str1, const std::string &str2) const {
    return case_insensitive_equal(str1, str2);
  }
};
// Based on https://stackoverflow.com/questions/2590677/how-do-i-combine-hash-values-in-c0x/2595226#2595226
class CaseInsensitiveHash {
public:
  size_t operator()(const std::string &str) const {
    size_t h = 0;
    std::hash<int> hash;
    for(auto c : str)
      h ^= hash(tolower(c)) + 0x9e3779b9 + (h << 6) + (h >> 2);
    return h;
  }
};
#endif

typedef std::unordered_multimap<std::string, std::string, CaseInsensitiveHash, CaseInsensitiveEqual> CaseInsensitiveMultimap;
} // namespace SimpleWeb

#endif // SIMPLE_WEBSOCKET_SERVER_UTILITY_HPP
