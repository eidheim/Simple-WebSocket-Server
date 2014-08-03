#ifndef CRYPTO_HPP
#define	CRYPTO_HPP

#include <string>

namespace SimpleWeb {
    namespace Crypto {
        namespace Base64 {
            std::string encode(const std::string&);
            std::string decode(const std::string&);
        }
                    
        std::string MD5(const std::string&);

        std::string SHA1(const std::string&);

        std::string SHA256(const std::string&);

        std::string SHA512(const std::string&);
    }
}
#endif	/* CRYPTO_HPP */

