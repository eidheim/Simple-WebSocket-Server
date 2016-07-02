#include <iostream>
#include <sstream>
#include <vector>
#include <utility>
#include <iomanip>

#include "crypto.hpp"

using namespace std;
using namespace SimpleWeb;

const vector<pair<string, string> > Base64_string_tests = {
    {"", ""},
    {"f" , "Zg=="},
    {"fo", "Zm8="},
    {"foo", "Zm9v"},
    {"foob", "Zm9vYg=="},
    {"fooba", "Zm9vYmE="},
    {"foobar", "Zm9vYmFy"}
};

const vector<pair<string, string> > MD5_string_tests = {
    {"", "d41d8cd98f00b204e9800998ecf8427e"},
    {"The quick brown fox jumps over the lazy dog", "9e107d9d372bb6826bd81d3542a419d6"}
};

const vector<pair<string, string> > SHA1_string_tests = {
    {"", "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
    {"The quick brown fox jumps over the lazy dog", "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"}
};

const vector<pair<string, string> > SHA256_string_tests = {
    {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
    {"The quick brown fox jumps over the lazy dog", "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"}
};

const vector<pair<string, string> > SHA512_string_tests = {
    {"", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
    {"The quick brown fox jumps over the lazy dog", "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"}
};

template<class type>
string to_hex_string(type chars) {
    stringstream hex_ss;
    hex_ss.fill('0');
    for(auto c: chars) {
        hex_ss << setw(2) << hex << (int)(unsigned char)c;
    }
    return hex_ss.str();
}

int main() {
    //Testing SimpleWeb::Crypt::Base64
    for(auto& string_test: Base64_string_tests) {
        if(Crypto::Base64::encode(string_test.first)!=string_test.second) {
            cerr << "FAIL Crypto::Base64::encode: " << string_test.first << "!=" << string_test.second << endl;
            return 1;
        }
        if(Crypto::Base64::decode(string_test.second)!=string_test.first) {
            cerr << "FAIL Crypto::Base64::decode: " << string_test.second << "!=" << string_test.first << endl;
            return 1;
        }
        
        pair<vector<unsigned char>, vector<unsigned char> > vector_test={
            {string_test.first.begin(), string_test.first.end()},
            {string_test.second.begin(), string_test.second.end()}
        };
        if(Crypto::Base64::encode(vector_test.first)!=vector_test.second) {
            cerr << "FAIL Crypto::Base64::encode: " << string_test.first << "!=" << string_test.second << endl;
            return 1;
        }
        if(Crypto::Base64::decode(vector_test.second)!=vector_test.first) {
            cerr << "FAIL Crypto::Base64::decode: " << string_test.second << "!=" << string_test.first << endl;
            return 1;
        }
    }
    
    //Testing SimpleWeb::Crypt::MD5
    for(auto& string_test: MD5_string_tests) {
        if(to_hex_string(Crypto::MD5(string_test.first)) != string_test.second) {
            cerr << "FAIL Crypto::MD5: " << string_test.first << "!=" << string_test.second << endl;
            return 1;
        }
        
        vector<unsigned char> vector_test_first(string_test.first.begin(), string_test.first.end());
        if(to_hex_string(Crypto::MD5(vector_test_first)) != string_test.second) {
            cerr << "FAIL Crypto::MD5: " << string_test.first << "!=" << string_test.second << endl;
            return 1;
        }
    }
    
    //Testing SimpleWeb::Crypt::SHA1
    for(auto& string_test: SHA1_string_tests) {
        if(to_hex_string(Crypto::SHA1(string_test.first)) != string_test.second) {
            cerr << "FAIL Crypto::SHA1: " << string_test.first << "!=" << string_test.second << endl;
            return 1;
        }
        
        vector<unsigned char> vector_test_first(string_test.first.begin(), string_test.first.end());
        if(to_hex_string(Crypto::SHA1(vector_test_first)) != string_test.second) {
            cerr << "FAIL Crypto::SHA1: " << string_test.first << "!=" << string_test.second << endl;
            return 1;
        }
    }
    
    //Testing SimpleWeb::Crypt::SHA256
    for(auto& string_test: SHA256_string_tests) {
        if(to_hex_string(Crypto::SHA256(string_test.first)) != string_test.second) {
            cerr << "FAIL Crypto::SHA256: " << string_test.first << "!=" << string_test.second << endl;
            return 1;
        }
        
        vector<unsigned char> vector_test_first(string_test.first.begin(), string_test.first.end());
        if(to_hex_string(Crypto::SHA256(vector_test_first)) != string_test.second) {
            cerr << "FAIL Crypto::SHA256: " << string_test.first << "!=" << string_test.second << endl;
            return 1;
        }
    }
    
    //Testing SimpleWeb::Crypt::SHA512
    for(auto& string_test: SHA512_string_tests) {
        if(to_hex_string(Crypto::SHA512(string_test.first)) != string_test.second) {
            cerr << "FAIL Crypto::SHA512: " << string_test.first << "!=" << string_test.second << endl;
            return 1;
        }
        
        vector<unsigned char> vector_test_first(string_test.first.begin(), string_test.first.end());
        if(to_hex_string(Crypto::SHA512(vector_test_first)) != string_test.second) {
            cerr << "FAIL Crypto::SHA512: " << string_test.first << "!=" << string_test.second << endl;
            return 1;
        }
    }
    
    cout << "PASS" << endl;

    return 0;
}

