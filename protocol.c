/*
 *  seccure  -  Copyright 2006 B. Poettering
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as
 *  published by the Free Software Foundation; either version 2 of the
 *  License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 *  02111-1307 USA
 */

/* 
 *   SECCURE Elliptic Curve Crypto Utility for Reliable Encryption
 *
 *              http://point-at-infinity.org/seccure/
 *
 *
 * seccure implements a selection of asymmetric algorithms based on  
 * elliptic curve cryptography (ECC). See the manpage or the project's  
 * homepage for further details.
 *
 * This code links against the GNU gcrypt library "libgcrypt" (which is
 * part of the GnuPG project). The code compiles successfully with 
 * libgcrypt 1.2.2. Use the included Makefile to build the binary.
 * 
 * Compile with -D NOMEMLOCK if your machine doesn't support memory 
 * locking.
 *
 * Report bugs to: seccure AT point-at-infinity.org
 *
 */

#include <gcrypt.h>
#include <assert.h>

#include "ecc.h"
#include "curves.h"
#include "serialize.h"
#include "protocol.h"

/******************************************************************************/

gcry_mpi_t hash_to_exponent(const char *hash, const struct curve_params *cp)
{
  int bits = gcry_mpi_get_nbits(cp->dp.order);
  int buflen = (bits + 7) / 8;
  gcry_cipher_hd_t ch;
  gcry_error_t err;
  gcry_mpi_t a, b;
  char buf[buflen];

  err = gcry_cipher_open(&ch, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CTR, 0);
  assert(! gcry_err_code(err));

  err = gcry_cipher_setkey(ch, hash, 32);
  assert(! gcry_err_code(err));
  
  err = gcry_cipher_setctr(ch, NULL, 0);
  assert(! gcry_err_code(err));
  
  memset(buf, 0, buflen);

  err = gcry_cipher_encrypt(ch, buf, buflen, NULL, 0);
  assert(! gcry_err_code(err));

  gcry_cipher_close(ch);

  gcry_mpi_scan(&a, GCRYMPI_FMT_USG, buf, buflen, NULL);
  memset(buf, 0, buflen);

  b = gcry_mpi_new(0);
  gcry_mpi_sub_ui(b, cp->dp.order, 1);
  gcry_mpi_mod(a, a, b);
  gcry_mpi_add_ui(a, a, 1);
  gcry_mpi_release(b);
  return a;
}

gcry_mpi_t get_random_exponent(const struct curve_params *cp)
{
  int bits = gcry_mpi_get_nbits(cp->dp.order);
  gcry_mpi_t a;
  a = gcry_mpi_new(0);
  do {
    gcry_mpi_randomize(a, bits, GCRY_STRONG_RANDOM);
    gcry_mpi_clear_highbit(a, bits);
  } while (! gcry_mpi_cmp_ui(a, 0) || gcry_mpi_cmp(a, cp->dp.order) >= 0);
  return a;
}

/******************************************************************************/

void compress_to_string(char *buf, enum disp_format df, 
			const struct affine_point *P, 
			const struct curve_params *cp)
{
  int outlen = (df == DF_COMPACT) ? cp->pk_len_compact : cp->pk_len_bin;
  if (point_compress(P)) {
    gcry_mpi_t x;
    x = gcry_mpi_new(0);
    gcry_mpi_add(x, P->x, cp->dp.m);
    serialize_mpi(buf, outlen, df, x);
    gcry_mpi_release(x);
  }
  else
    serialize_mpi(buf, outlen, df, P->x);
}

int decompress_from_string(struct affine_point *P, const char *buf, 
			   enum disp_format df, const struct curve_params *cp)
{
  gcry_mpi_t x;
  int inlen = (df == DF_COMPACT) ? cp->pk_len_compact : cp->pk_len_bin;
  int res;
  assert(df != DF_COMPACT || inlen == strlen(buf));
  if ((res = deserialize_mpi(&x, df, buf, inlen))) {
    int yflag;
    if ((yflag = (gcry_mpi_cmp(x, cp->dp.m) >= 0)))
      gcry_mpi_sub(x, x, cp->dp.m);
    res = gcry_mpi_cmp_ui(x, 0) >= 0 && gcry_mpi_cmp(x, cp->dp.m) < 0 &&
      point_decompress(P, x, yflag, &cp->dp);
    gcry_mpi_release(x);
  }
  return res;
}

/******************************************************************************/

/* Algorithms 4.29 and 4.30 in the "Guide to Elliptic Curve Cryptography"     */
gcry_mpi_t ECDSA_sign(const char *msg, const gcry_mpi_t d, 
		      const struct curve_params *cp)
{
  struct affine_point p1;
  gcry_mpi_t e, k, r, s;
  r = gcry_mpi_new(0);
  s = gcry_mpi_new(0);
 Step1:
  k = get_random_exponent(cp);
  p1 = pointmul(&cp->dp.base, k, &cp->dp);
  gcry_mpi_mod(r, p1.x, cp->dp.order);
  point_release(&p1);
  if (! gcry_mpi_cmp_ui(r, 0)) {
    gcry_mpi_release(k);
    goto Step1;
  }
  gcry_mpi_scan(&e, GCRYMPI_FMT_USG, msg, 64, NULL);
  gcry_mpi_mod(e, e, cp->dp.order);
  gcry_mpi_mulm(s, d, r, cp->dp.order);
  gcry_mpi_addm(s, s, e, cp->dp.order);
  gcry_mpi_invm(e, k, cp->dp.order);
  gcry_mpi_mulm(s, s, e, cp->dp.order);
  gcry_mpi_release(e);
  gcry_mpi_release(k);
  if (! gcry_mpi_cmp_ui(s, 0))
    goto Step1;
  gcry_mpi_mul(s, s, cp->dp.order);
  gcry_mpi_add(s, s, r);
  gcry_mpi_release(r);
  return s;
}

int ECDSA_verify(const char *msg, const struct affine_point *Q, 
		 const gcry_mpi_t sig, const struct curve_params *cp)
{
  gcry_mpi_t e, r, s;
  struct affine_point X1, X2;
  int res;
  r = gcry_mpi_new(0);
  s = gcry_mpi_new(0);
  gcry_mpi_div(s, r, sig, cp->dp.order, 0);
  if (gcry_mpi_cmp_ui(s, 0) <= 0 || gcry_mpi_cmp(s, cp->dp.order) >= 0 ||
      gcry_mpi_cmp_ui(r, 0) <= 0 || gcry_mpi_cmp(r, cp->dp.order) >= 0) {
    gcry_mpi_release(r);
    gcry_mpi_release(s);
    return 0;
  }
  gcry_mpi_scan(&e, GCRYMPI_FMT_USG, msg, 64, NULL);
  gcry_mpi_mod(e, e, cp->dp.order);
  gcry_mpi_invm(s, s, cp->dp.order);
  gcry_mpi_mulm(e, e, s, cp->dp.order);
  X1 = pointmul(&cp->dp.base, e, &cp->dp);
  gcry_mpi_mulm(e, r, s, cp->dp.order);
  X2 = pointmul(Q, e, &cp->dp);
  point_add(&X1, &X2, &cp->dp);
  point_release(&X2);
  gcry_mpi_release(e);
  if (point_is_zero(&X1)) {
    gcry_mpi_release(r);
    gcry_mpi_release(s);
    point_release(&X1);
    return 0;
  }
  gcry_mpi_mod(s, X1.x, cp->dp.order);
  res = ! gcry_mpi_cmp(s, r);
  gcry_mpi_release(r);
  gcry_mpi_release(s);
  point_release(&X1);
  return res;
}

/******************************************************************************/

/* Algorithms 4.42 and 4.43 in the "Guide to Elliptic Curve Cryptography"     */
static void ECIES_KDF(char *key, const gcry_mpi_t Zx, 
		      const struct affine_point *R, int elemlen)
{
  char buf[3 * elemlen];
  serialize_mpi(buf + 0 * elemlen, elemlen, DF_BIN, Zx);
  serialize_mpi(buf + 1 * elemlen, elemlen, DF_BIN, R->x);
  serialize_mpi(buf + 2 * elemlen, elemlen, DF_BIN, R->y);
  gcry_md_hash_buffer(GCRY_MD_SHA512, key, buf, 3 * elemlen);
}

struct affine_point ECIES_encryption(char *key, const struct affine_point *Q, 
				     const struct curve_params *cp)
{
  struct affine_point Z, R;
  gcry_mpi_t k;
 Step1:
  k = get_random_exponent(cp);
  R = pointmul(&cp->dp.base, k, &cp->dp);
  gcry_mpi_mul_ui(k, k, cp->dp.cofactor);
  Z = pointmul(Q, k, &cp->dp);
  gcry_mpi_release(k);
  if (point_is_zero(&Z)) {
    point_release(&R);
    point_release(&Z);
    goto Step1;
  }
  ECIES_KDF(key, Z.x, &R, cp->elem_len_bin);
  point_release(&Z);
  return R;
}

int ECIES_decryption(char *key, const struct affine_point *R, 
		     const gcry_mpi_t d, const struct curve_params *cp)
{
  struct affine_point Z;
  gcry_mpi_t e;
  if (! embedded_key_validation(R, &cp->dp))
    return 0;
  e = gcry_mpi_new(0);
  gcry_mpi_mul_ui(e, d, cp->dp.cofactor);
  Z = pointmul(R, e, &cp->dp);
  gcry_mpi_release(e);
  if (point_is_zero(&Z)) {
    point_release(&Z);
    return 0;
  }
  ECIES_KDF(key, Z.x, R, cp->elem_len_bin);
  point_release(&Z);
  return 1;
}

/******************************************************************************/

static void DH_KDF(char *key, const struct affine_point *P, int elemlen)
{
  char buf[2 * elemlen];
  serialize_mpi(buf + 0 * elemlen, elemlen, DF_BIN, P->x);
  serialize_mpi(buf + 1 * elemlen, elemlen, DF_BIN, P->y);
  gcry_md_hash_buffer(GCRY_MD_SHA512, key, buf, 2 * elemlen);
}

gcry_mpi_t DH_step1(struct affine_point *A, const struct curve_params *cp)
{
  gcry_mpi_t a;
  a = get_random_exponent(cp);
  *A = pointmul(&cp->dp.base, a, &cp->dp);
  return a;
}

int DH_step2(char *key, const struct affine_point *B, const gcry_mpi_t exp, 
	     const struct curve_params *cp)
{
  struct affine_point P;
  if (! full_key_validation(B, &cp->dp))
    return 0;
  P = pointmul(B, exp, &cp->dp);
  DH_KDF(key, &P, cp->elem_len_bin);
  point_release(&P);
  return 1;
}
