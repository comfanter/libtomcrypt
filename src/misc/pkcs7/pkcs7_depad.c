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
   PKCS#7 depad

      This PKCS#7 depads your data.

   @param data     The data to depad
   @param length   [in/out] The size of the data before/after (removing padding)
   @param mode     One of the LTC_PKCS_7_PAD_xx flags
   @return CRYPT_OK on success
*/
int pkcs7_depad(unsigned char *data, unsigned long *length, unsigned long mode)
{
   unsigned long padded_length, unpadded_length, n;
   unsigned char pad;

   LTC_ARGCHK(data   != NULL);
   LTC_ARGCHK(length != NULL);

   padded_length = *length;

   pad = data[padded_length - 1];

   if (pad > padded_length) return CRYPT_INVALID_ARG;

   unpadded_length = padded_length - pad;

#ifdef LTC_RNG_GET_BYTES
   if ((mode & LTC_PKCS_7_PAD_MASK) != LTC_PKCS_7_PAD_RAND)
#endif
   {
      for (n = unpadded_length; n < padded_length; ++n) {
         if (data[n] != pad) return CRYPT_INVALID_ARG;
      }
   }

   *length = unpadded_length;

   return CRYPT_OK;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
