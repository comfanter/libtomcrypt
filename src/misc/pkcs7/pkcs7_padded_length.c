/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include "tomcrypt.h"

#ifdef LTC_PKCS_7

/**
   Determine the PKCS#7 to-be-padded length

   @param length     [in/out] The size of the data before/after padding
   @param mode       Mask of (LTC_PKCS_7_PAD_xxx | block_length)
   @return CRYPT_OK on success
*/
int pkcs7_padded_length(unsigned long *length, unsigned long mode)
{
   unsigned long padding;
   unsigned char pad, block_length, t;

   LTC_ARGCHK(length != NULL);

   block_length = mode & 0xff;
   padding = mode & LTC_PKCS_7_PAD_MASK;

   switch (padding) {
      case LTC_PKCS_7_PAD_MIN:
         t = 1;
         break;
#ifdef LTC_RNG_GET_BYTES
      case LTC_PKCS_7_PAD_RAND:
         if (rng_get_bytes(&t, sizeof(t), NULL) != sizeof(t)) {
            return CRYPT_ERROR_READPRNG;
         }
         t %= (256 / block_length);
         if (t == 0) t = 1;
         break;
#endif
      default:
         return CRYPT_INVALID_ARG;
   }


   pad = (t * block_length) - (*length % block_length);

   if (pad == 0) {
      pad = block_length;
   }

   *length += pad;

   return CRYPT_OK;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
