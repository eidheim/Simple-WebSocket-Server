#ifndef CRYPT_HPP
#define	CRYPT_HPP

#include <string>

namespace SimpleWeb {
    namespace Crypt {
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
#endif	/* CRYPT_HPP */

