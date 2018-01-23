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
   PKCS#7 pad

      This PKCS#7 pads your data.

   @param data          The data to depad
   @param length        The size of the data before padding
   @param padded_length The size of the data after padding
   @param mode          One of the LTC_PKCS_7_PAD_xx flags
   @return CRYPT_OK on success
*/
int pkcs7_pad(unsigned char *data, unsigned long length, unsigned long padded_length, unsigned long mode)
{
   unsigned long diff;

   LTC_ARGCHK(data != NULL);

   diff = padded_length - length;
   if (length >= padded_length || diff > 255) return CRYPT_INVALID_ARG;

#ifdef LTC_RNG_GET_BYTES
   if ((mode & LTC_PKCS_7_PAD_MASK) == LTC_PKCS_7_PAD_RAND) {
      if (rng_get_bytes(&data[length], diff-1, NULL) != diff-1) {
         return CRYPT_ERROR_READPRNG;
      }
      data[padded_length-1] =  diff;
   } else
#endif
   {
      XMEMSET(&data[length], diff, diff);
   }

   return CRYPT_OK;
}

#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
