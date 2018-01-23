/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include  <tomcrypt_test.h>

#ifdef LTC_PKCS_7

typedef struct {
   unsigned long is, should, max, mode;
   const char* name;
} pkcs7_testcase;

static int _pkcs_7_testrun(const pkcs7_testcase* t, int i)
{
   unsigned long len;
   unsigned char buf[1024];

   len = t->is;
   DO(pkcs7_padded_length(&len, t->mode));
#ifdef LTC_RNG_GET_BYTES
   if ((t->mode & LTC_PKCS_7_PAD_RAND) == LTC_PKCS_7_PAD_RAND) {
      if (len < t->should || len > t->max) return CRYPT_FAIL_TESTVECTOR;
   } else
#endif
   {
      if (compare_testvector(&len, sizeof(len), &t->should, sizeof(t->should), t->name, i) != 0) return CRYPT_FAIL_TESTVECTOR;
   }
   DO(pkcs7_pad(buf, t->is, len, t->mode));
   if (buf[len - 1] != len - t->is) return CRYPT_FAIL_TESTVECTOR;
   DO(pkcs7_depad(buf, &len, t->mode));
   if (len != t->is) return CRYPT_FAIL_TESTVECTOR;
   return CRYPT_OK;
}

static int _pkcs_7_test(void)
{
   pkcs7_testcase cases[] = {
                             {   0,  16,   0, LTC_PKCS_7_PAD_MIN | 16, "0-min" },
                             {   1,  16,   0, LTC_PKCS_7_PAD_MIN | 16, "1-min" },
                             {  15,  16,   0, LTC_PKCS_7_PAD_MIN | 16, "15-min" },
                             {  16,  32,   0, LTC_PKCS_7_PAD_MIN | 16, "16-min" },
                             { 255, 256,   0, LTC_PKCS_7_PAD_MIN | 16, "255-min" },
                             { 256, 272,   0, LTC_PKCS_7_PAD_MIN | 16, "256-min" },
#ifdef LTC_RNG_GET_BYTES
                             {   0,  16, 256, LTC_PKCS_7_PAD_RAND | 16, "0-rand" },
                             {   1,  16, 272, LTC_PKCS_7_PAD_RAND | 16, "1-rand" },
                             {  15,  16, 272, LTC_PKCS_7_PAD_RAND | 16, "15-rand" },
                             {  16,  32, 288, LTC_PKCS_7_PAD_RAND | 16, "16-rand" },
                             { 255, 256, 512, LTC_PKCS_7_PAD_RAND | 16, "255-rand" },
                             { 256, 272, 528, LTC_PKCS_7_PAD_RAND | 16, "256-rand" },
#endif
   };
   unsigned i;
   for (i = 0; i < sizeof(cases)/sizeof(cases[0]); ++i) {
      DOX(_pkcs_7_testrun(&cases[i], i), cases[i].name);
   }

   return CRYPT_OK;
}
#endif

int misc_test(void)
{
#ifdef LTC_HKDF
   DO(hkdf_test());
#endif
#ifdef LTC_PKCS_5
   DO(pkcs_5_test());
#endif
#ifdef LTC_PKCS_7
   DO(_pkcs_7_test());
#endif
#ifdef LTC_BASE64
   DO(base64_test());
#endif
#ifdef LTC_BASE32
   DO(base32_test());
#endif
#ifdef LTC_ADLER32
   DO(adler32_test());
#endif
#ifdef LTC_CRC32
   DO(crc32_test());
#endif
   return 0;
}

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
