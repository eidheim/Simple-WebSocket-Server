#ifndef CRYPTO_HPP
#define	CRYPTO_HPP

#include <string>
#include <cmath>

//Moving these to a seperate namespace for minimal global namespace cluttering does not work with clang++
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/sha.h>
#include <openssl/md5.h>

namespace SimpleWeb {
    //type must support size(), resize() and operator[]
    namespace Crypto {
        namespace Base64 {
            template<class type>
            type encode(const type& ascii) {
                BIO *bio, *b64;
                BUF_MEM *bptr;

                b64 = BIO_new(BIO_f_base64());
                bio = BIO_new(BIO_s_mem());
                BIO_push(b64, bio);
                BIO_get_mem_ptr(b64, &bptr);

                //Write directly to base64-string buffer to avoid copy
                type base64;
                int base64_length=round(4*ceil((double)ascii.size()/3.0));
                base64.resize(base64_length);
                bptr->length=0;
                bptr->max=base64_length+1;
                bptr->data=(char*)&base64[0];

                BIO_write(b64, &ascii[0], ascii.size());
                BIO_flush(b64);

                //To keep &base64[0] through BIO_free_all(b64)
                bptr->length=0;
                bptr->max=0;
                bptr->data=nullptr;

                BIO_free_all(b64);

                return base64;
            }
            
            template<class type>
            type decode(const type& base64) {
                type ascii;
                //Resize resulting ascii-string, however, the size is a up to two bytes too large.
                ascii.resize((6*base64.size())/8);
                BIO *b64, *bio;

                b64 = BIO_new(BIO_f_base64());
                BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
                bio = BIO_new_mem_buf((char*)&base64[0], base64.size());
                bio = BIO_push(b64, bio);

                int decoded_length = BIO_read(bio, &ascii[0], ascii.size());
                ascii.resize(decoded_length);

                BIO_free_all(b64);

                return ascii;
            }
        }
        
        template<class type>
        type MD5(const type& text) {
            type encoded;
            encoded.resize(128/8);

            MD5_CTX context;
            MD5_Init(&context);
            MD5_Update(&context, &text[0], text.size());
            MD5_Final((unsigned char*)&encoded[0], &context);
            return encoded;
        }

        template<class type>
        type SHA1(const type& text) {
            type encoded;
            encoded.resize(160/8);

            SHA_CTX context;
            SHA1_Init(&context);
            SHA1_Update(&context, &text[0], text.size());
            SHA1_Final((unsigned char*)&encoded[0], &context);
            return encoded;
        }

        template<class type>
        type SHA256(const type& text) {
            type encoded;
            encoded.resize(256/8);

            SHA256_CTX context;
            SHA256_Init(&context);
            SHA256_Update(&context, &text[0], text.size());
            SHA256_Final((unsigned char*)&encoded[0], &context);
            return encoded;
        }

        template<class type>
        type SHA512(const type& text) {
            type encoded;
            encoded.resize(512/8);

            SHA512_CTX context;
            SHA512_Init(&context);
            SHA512_Update(&context, &text[0], text.size());
            SHA512_Final((unsigned char*)&encoded[0], &context);
            return encoded;
        }
    }
}
#endif	/* CRYPTO_HPP */

