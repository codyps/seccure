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
 * libgcrypt 1.2.1. Use the included Makefile to build the binary.
 * 
 * Compile with -D NOMEMLOCK if your machine doesn't support memory 
 * locking.
 *
 * Report bugs to: seccure AT point-at-infinity.org
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <termios.h>
#include <getopt.h>
#include <sys/mman.h>
#include <gcrypt.h>

#include "curves.h"
#include "protocol.h"
#include "serialize.h"

#define VERSION "0.1"

#define COPYBUF_SIZE (1 << 20)

#define DEFAULT_CURVE "p160"
#define DEFAULT_MAC_LEN 10

int opt_help = 0;
int opt_verbose = 0;
int opt_quiet = 0;
int opt_sigcopy = 0;
int opt_sigbin = 0;
int opt_maclen = -1;
char *opt_infile = NULL;
char *opt_outfile = NULL;
char *opt_curve = NULL;
char *opt_pwfile = NULL;
char *opt_sigfile = NULL;

int opt_fdin = STDIN_FILENO;
int opt_fdout = STDOUT_FILENO;
int opt_fdpw;

/******************************************************************************/

void beep_on_terminal(FILE *term)
{
#if ! NOBEEP
  if (isatty(fileno(term)))
    fputc('\a', term);
#endif
}

void fatal(const char *msg)
{
  beep_on_terminal(stderr);
  fprintf(stderr, "FATAL: %s.\n", msg);
  exit(1);
}

void fatal_errno(const char *msg, int err)
{
  beep_on_terminal(stderr);
  fprintf(stderr, "FATAL: %s: %s.\n", msg, strerror(err));
  exit(1);
}

void fatal_gcrypt(const char *msg, gcry_error_t err)
{
  beep_on_terminal(stderr);
  fprintf(stderr, "FATAL: %s: %s.\n", msg, gcry_strerror(err));
  exit(1);
}

void print_quiet(const char *msg, int beep)
{
  if (! opt_quiet) {
    if (beep)
      beep_on_terminal(stderr);
    fprintf(stderr, "%s", msg);
  }
}

/******************************************************************************/

void write_block(int fd, const char *buf, int len)
{
  ssize_t c;
  while(len) {
    if ((c = write(fd, buf, len)) < 0)
      fatal_errno("Write error", errno);
    buf += c;
    len -= c;
  }
}

int read_block(int fd, char *buf, int len)
{
  ssize_t c;
  while(len) {
    if ((c = read(fd, buf, len)) < 0)
      fatal_errno("Read error", errno);
    if (c == 0)
      return 0;
    buf += c;
    len -= c;
  }
  return 1;
}

void encryption_loop(int fdin, int fdout, gcry_cipher_hd_t *ch, 
		     gcry_md_hd_t *mh)
{
  char buf[COPYBUF_SIZE];
  gcry_error_t err;
  ssize_t t;
  int aligned_ready, fill = 0;
  
  while ((t = read(fdin, buf + fill, COPYBUF_SIZE - fill)) > 0) {
    fill += t;
    aligned_ready = fill & ~0x0f; /* 128 bit block alignement */
    err = gcry_cipher_encrypt(*ch, buf, aligned_ready, NULL, 0);
    assert(! gcry_err_code(err));
    if (mh)
      gcry_md_write(*mh, buf, aligned_ready);
    write_block(fdout, buf, aligned_ready);
    memmove(buf, buf + aligned_ready, fill - aligned_ready);
    fill -= aligned_ready;
  }
  if (t < 0)
    fatal_errno("Read error", errno);

  err = gcry_cipher_encrypt(*ch, buf, fill, NULL, 0);
  assert(! gcry_err_code(err));
  if (mh)
    gcry_md_write(*mh, buf, fill);
  write_block(fdout, buf, fill);
}

void decryption_loop(int fdin, int fdout, gcry_cipher_hd_t *ch, 
		     gcry_md_hd_t *mh, char *mac, int maclen)
{
  char buf[COPYBUF_SIZE];
  gcry_error_t err;
  ssize_t t;
  int aligned_ready, fill = maclen;

  if (! read_block(fdin, buf, maclen))
    fatal("Input too short (no MAC)");

  while ((t = read(fdin, buf + fill, COPYBUF_SIZE - fill)) > 0) {
    fill += t;
    aligned_ready = (fill - maclen) & ~0x0f;
    if (mh)
      gcry_md_write(*mh, buf, aligned_ready);
    err = gcry_cipher_decrypt(*ch, buf, aligned_ready, NULL, 0);
    assert(! gcry_err_code(err));
    write_block(fdout, buf, aligned_ready);
    memmove(buf, buf + aligned_ready, fill - aligned_ready);
    fill -= aligned_ready;
  }
  if (t < 0)
    fatal_errno("Read error", errno);

  fill -= maclen;
  if (mh)
    gcry_md_write(*mh, buf, fill);
  err = gcry_cipher_decrypt(*ch, buf, fill, NULL, 0);
  assert(! gcry_err_code(err));
  write_block(fdout, buf, fill);

  memcpy(mac, buf + fill, maclen);
}

void verisign_loop(int fdin, int fdout, gcry_md_hd_t *mh, int copyflag)
{
  char buf[COPYBUF_SIZE];
  ssize_t c;

  while((c = read(fdin, buf, COPYBUF_SIZE)) > 0) {
    gcry_md_write(*mh, buf, c);
    if (copyflag)
      write_block(fdout, buf, c);
  }
  if (c < 0)
    fatal_errno("Read error", errno);
}

void read_passphrase(const char *prompt, char *hash)
{
  struct termios echo_orig, echo_off;
  gcry_md_hd_t mh;
  gcry_error_t err;
  char *md, ch;
  ssize_t r;

  if (isatty(opt_fdpw)) {
    tcgetattr(opt_fdpw, &echo_orig);
    echo_off = echo_orig;
    echo_off.c_lflag &= ~ECHO;
    tcsetattr(opt_fdpw, TCSANOW, &echo_off);
    print_quiet(prompt, 0);
  }

  err = gcry_md_open(&mh, GCRY_MD_SHA256, 0);
  if (gcry_err_code(err))
    fatal_gcrypt("Cannot initialize hash function", err);

  while (((r = read(opt_fdpw, &ch, 1)) > 0) && (ch != '\n'))
    gcry_md_putc(mh, ch);

  if (r < 0) {
    int err = errno;
    if (isatty(opt_fdpw))
      tcsetattr(opt_fdpw, TCSANOW, &echo_orig);
    fatal_errno("Cannot read text line", err);
  }
  
  gcry_md_final(mh);
  md = (char*)gcry_md_read(mh, 0);
  memcpy(hash, md, 32);
  gcry_md_close(mh);

  if (isatty(opt_fdpw)) {
    tcsetattr(opt_fdpw, TCSANOW, &echo_orig);
    print_quiet("\n", 0);
  }
}

/******************************************************************************/

void app_print_public_key(void)
{
  struct curve_params *cp;
  if (! opt_curve) {
    opt_curve = DEFAULT_CURVE;
    fprintf(stderr, "Assuming curve " DEFAULT_CURVE ".\n");
  }

  if ((cp = curve_by_name(opt_curve))) {
    char pubkey[cp->pk_len_compact + 1];
    char privkey[32];
    struct affine_point P;
    gcry_mpi_t d;

    if (opt_verbose) {
      print_quiet("VERSION: ", 0);
      fprintf(stderr, VERSION "\n"); 
      print_quiet("CURVE: ", 0); 
      fprintf(stderr, "%s\n", cp->name); 
    }

    read_passphrase("Enter private key: ", privkey);
    d = hash_to_exponent(privkey, cp);
    memset(privkey, 0, sizeof(privkey));
    P = pointmul(&cp->dp.base, d, &cp->dp);
    gcry_mpi_release(d);

    compress_to_string(pubkey, DF_COMPACT, &P, cp);
    pubkey[cp->pk_len_compact] = 0;
    if (! opt_quiet)
      printf("The public key is: ");
    printf("%s\n", pubkey);
    point_release(&P);
    curve_release(cp);
  }
  else
    fatal("Invalid curve name");
}

void app_encrypt(const char *pubkey)
{
  struct affine_point P, R;
  struct curve_params *cp;

  if (opt_maclen < 0) {
    opt_maclen = DEFAULT_MAC_LEN;
    fprintf(stderr, "Assuming MAC length of %d bits.\n", 8 * DEFAULT_MAC_LEN);
  }

  if (! opt_curve) {
    if (! (cp = curve_by_pk_len_compact(strlen(pubkey))))
      fatal("Invalid encryption key (wrong length)");
  }
  else
    if (! (cp = curve_by_name(opt_curve)))
      fatal("Invalid curve name");

  if (opt_verbose) {
    print_quiet("VERSION: ", 0);
    fprintf(stderr, VERSION "\n"); 
    print_quiet("CURVE: ", 0); 
    fprintf(stderr, "%s\n", cp->name); 
    print_quiet("MACLEN: ", 0); 
    fprintf(stderr, "%d\n", 8 * opt_maclen); 
  }

  if (strlen(pubkey) != cp->pk_len_compact)
    fatal("Invalid encryption key (wrong length)");
    
  if (decompress_from_string(&P, pubkey, DF_COMPACT, cp)) {
    char rbuf[cp->pk_len_bin];
    char keybuf[64];
    gcry_cipher_hd_t ch;
    gcry_md_hd_t mh;
    gcry_error_t err;

    R = ECIES_encryption(keybuf, &P, cp);
    compress_to_string(rbuf, DF_BIN, &R, cp);
    point_release(&P);
    point_release(&R);

    if (opt_verbose) {
      int i;
      print_quiet("K_ENC: ", 0); 
      for(i = 0; i < 32; i++)
	fprintf(stderr, "%02x", (unsigned char)keybuf[i]);
      fprintf(stderr, "\n");
      print_quiet("K_MAC: ", 0);
      for(i = 32; i < 64; i++)
	fprintf(stderr, "%02x", (unsigned char)keybuf[i]);
      fprintf(stderr, "\n");
    }

    err = gcry_cipher_open(&ch, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CTR, 0);
    if (gcry_err_code(err))
      fatal_gcrypt("Cannot open cipher", err);

    err = gcry_cipher_setkey(ch, keybuf, 32);
    assert(! gcry_err_code(err));

    err = gcry_cipher_setctr(ch, NULL, 0);
    assert(! gcry_err_code(err));

    if (opt_maclen) {
      err = gcry_control(GCRYCTL_INIT_SECMEM, 1);
      if (gcry_err_code(err))
	fatal_gcrypt("Cannot initialize secure memory", err);

      err = gcry_md_open(&mh, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
      if (gcry_err_code(err))
	fatal_gcrypt("Cannot initialize HMAC", err);
  
      err = gcry_md_setkey(mh, keybuf + 32, 32);
      assert(! gcry_err_code(err));
    }
    memset(keybuf, 0, sizeof(keybuf));

    if (isatty(opt_fdin))
      print_quiet("Go ahead and type your message ...\n", 0);

    write_block(opt_fdout, rbuf, cp->pk_len_bin);
    encryption_loop(opt_fdin, opt_fdout, &ch, opt_maclen ? &mh : NULL);

    gcry_cipher_close(ch);

    if (opt_maclen) {
      char *md;
      gcry_md_final(mh);
      md = (char*)gcry_md_read(mh, 0);

      if (opt_verbose) {
	int i;
	print_quiet("HMAC: ", 0); 
	for(i = 0; i < opt_maclen; i++)
	  fprintf(stderr, "%02x", (unsigned char)md[i]);
	fprintf(stderr, "\n");
      }
      
      write_block(opt_fdout, md, opt_maclen);
      gcry_md_close(mh);

      err = gcry_control(GCRYCTL_TERM_SECMEM);
      if (gcry_err_code(err))
	fatal_gcrypt("Cannot release secure memory", err);
    }
  }
  else
    fatal("Invalid encryption key");
  curve_release(cp);
}

int app_decrypt(void)
{
  struct curve_params *cp;
  struct affine_point R;
  gcry_cipher_hd_t ch;
  gcry_md_hd_t mh;
  gcry_error_t err;
  gcry_mpi_t d;
  int res = 1;

  if (opt_maclen < 0) {
    opt_maclen = DEFAULT_MAC_LEN;
    fprintf(stderr, "Assuming MAC length of %d bits.\n", 8 * DEFAULT_MAC_LEN);
  }

  if (! opt_curve) {
    opt_curve = DEFAULT_CURVE;
    fprintf(stderr, "Assuming curve " DEFAULT_CURVE ".\n");
  }

  if ((cp = curve_by_name(opt_curve))) {
    char rbuf[cp->pk_len_bin];
    char privkey[32];
    char keybuf[64];
    char mdbuf[opt_maclen];
    char *md;

    if (opt_verbose) {
      print_quiet("VERSION: ", 0);
      fprintf(stderr, VERSION "\n"); 
      print_quiet("CURVE: ", 0); 
      fprintf(stderr, "%s\n", cp->name); 
      print_quiet("MACLEN: ", 0); 
      fprintf(stderr, "%d\n", 8 * opt_maclen);
    }

    read_passphrase("Enter private key: ", privkey);
    d = hash_to_exponent(privkey, cp);
    memset(privkey, 0, sizeof(privkey));

    if (isatty(opt_fdin))
      print_quiet("Go ahead and enter the ciphertext ...\n", 0);

    if ((res = read_block(opt_fdin, rbuf, cp->pk_len_bin))) {
      if ((res = decompress_from_string(&R, rbuf, DF_BIN, cp))) {
	if ((res = ECIES_decryption(keybuf, &R, d, cp))) {

	  if (opt_verbose) {
	    int i;
	    print_quiet("K_ENC: ", 0); 
	    for(i = 0; i < 32; i++)
	      fprintf(stderr, "%02x", (unsigned char)keybuf[i]);
	    fprintf(stderr, "\n");
	    print_quiet("K_MAC: ", 0); 
	    for(i = 32; i < 64; i++)
	      fprintf(stderr, "%02x", (unsigned char)keybuf[i]);
	    fprintf(stderr, "\n");
	  }
	
	  err = gcry_cipher_open(&ch, GCRY_CIPHER_AES256, 
				 GCRY_CIPHER_MODE_CTR, 0);
	  if (gcry_err_code(err))
	    fatal_gcrypt("Cannot open cipher", err);
	
	  err = gcry_cipher_setkey(ch, keybuf, 32);
	  assert(! gcry_err_code(err));
	
	  err = gcry_cipher_setctr(ch, NULL, 0);
	  assert(! gcry_err_code(err));
	
	  if (opt_maclen) {
	    err = gcry_control(GCRYCTL_INIT_SECMEM, 1);
	    if (gcry_err_code(err))
	      fatal_gcrypt("Cannot initialize secure memory", err);

	    err = gcry_md_open(&mh, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
	    if (gcry_err_code(err))
	      fatal_gcrypt("Cannot initialize HMAC", err);
	  
	    err = gcry_md_setkey(mh, keybuf + 32, 32);
	    assert(! gcry_err_code(err));
	  }
	  memset(keybuf, 0, sizeof(keybuf));
	
	  decryption_loop(opt_fdin, opt_fdout, &ch, 
			  opt_maclen ? &mh : NULL, mdbuf, opt_maclen);

	  gcry_cipher_close(ch);

	  if (opt_maclen) {
	    gcry_md_final(mh);
	    md = (char*)gcry_md_read(mh, 0);

	    if (opt_verbose) {
	      int i;
	      print_quiet("HMAC1: ", 0); 
	      for(i = 0; i < opt_maclen; i++)
		fprintf(stderr, "%02x", (unsigned char)md[i]);
	      fprintf(stderr, "\n");
	      print_quiet("HMAC2: ", 0); 
	      for(i = 0; i < opt_maclen; i++)
		fprintf(stderr, "%02x", (unsigned char)mdbuf[i]);
	      fprintf(stderr, "\n");
	    }
	  
	    if ((res = ! memcmp(mdbuf, md, opt_maclen)))
	      print_quiet("Integrity check successful, message unforged!\n", 0);
	    else
	      print_quiet("Warning: Integrity check failed, message "
			  "forged!\n", 1);

	    gcry_md_close(mh);
	  
	    err = gcry_control(GCRYCTL_TERM_SECMEM);
	    if (gcry_err_code(err))
	      fatal_gcrypt("Cannot release secure memory", err);
	  }
	  else
	    print_quiet("Warning: No MAC available, message integrity cannot "
			"be verified!\n", 0);
	}
	else
	  print_quiet("Abort: Inconsistent encryption header.\n", 1);
	point_release(&R);
      }
      else
	print_quiet("Abort: Inconsistent encryption header.\n", 1);
    }
    else 
      print_quiet("Abort: Inconsistent encryption header (too short).\n", 1);

    gcry_mpi_release(d);
    curve_release(cp);
  }
  else
    fatal("Invalid curve name");
  
  return ! res;
}

void app_sign(void)
{
  struct curve_params *cp;
  char privkey[32];
  char *md;
  gcry_md_hd_t mh;
  gcry_error_t err;
  gcry_mpi_t d, sig;
  FILE *sigfile;

  if (! opt_curve) {
    opt_curve = DEFAULT_CURVE;
    fprintf(stderr, "Assuming curve " DEFAULT_CURVE ".\n");
  }

  if ((cp = curve_by_name(opt_curve))) {

    if (opt_verbose) {
      print_quiet("VERSION: ", 0);
      fprintf(stderr, VERSION "\n"); 
      print_quiet("CURVE: ", 0); 
      fprintf(stderr, "%s\n", cp->name); 
    }

    if (opt_sigfile) {
      if (! (sigfile = fopen(opt_sigfile, "w")))
	fatal_errno("Cannot open signature file", errno);
    }
    else
      sigfile = stderr;

    read_passphrase("Enter private key: ", privkey);
    d = hash_to_exponent(privkey, cp);
    memset(privkey, 0, sizeof(privkey));

    if (isatty(opt_fdin))
      print_quiet("Go ahead and type your message ...\n", 0);

    err = gcry_md_open(&mh, GCRY_MD_SHA512, 0);
    if (gcry_err_code(err))
      fatal_gcrypt("Cannot initialize hash function", err);
    verisign_loop(opt_fdin, opt_fdout, &mh, opt_sigcopy);
    gcry_md_final(mh);
    md = (char*)gcry_md_read(mh, 0);

    if (opt_verbose) {
      int i;
      print_quiet("SHA512: ", 0); 
      for(i = 0; i < 64; i++)
	fprintf(stderr, "%02x", (unsigned char)md[i]);
      fprintf(stderr, "\n");
    }

    sig = ECDSA_sign(md, d, cp);
    gcry_mpi_release(d);

    if (opt_sigbin) {
      char sigbuf[cp->sig_len_bin];
      serialize_mpi(sigbuf, cp->sig_len_bin, DF_BIN, sig);
      if (fwrite(sigbuf, cp->sig_len_bin, 1, sigfile) != 1)
	fatal_errno("Cannot write signature", errno);
    }
    else {
      char sigbuf[cp->sig_len_compact + 1];
      serialize_mpi(sigbuf, cp->sig_len_compact, DF_COMPACT, sig);
      sigbuf[cp->sig_len_compact] = 0;
      if (sigfile == stderr)
	print_quiet("Signature: ", 0);
      if (fprintf(sigfile, "%s\n", sigbuf) < 0)
	fatal_errno("Cannot write signature", errno);
    }

    if (opt_sigfile && fclose(sigfile))
      fatal_errno("Cannot close signature file", errno);
    
    gcry_mpi_release(sig);
    gcry_md_close(mh);
    curve_release(cp);
  }
  else
    fatal("Invalid curve name");
}

int app_verify(const char *pubkey, const char *sig)
{
  struct curve_params *cp;
  struct affine_point Q;
  gcry_mpi_t s;
  char *md;
  gcry_md_hd_t mh;
  gcry_error_t err;
  int res;

  if (sig && opt_sigfile)
    fatal("Two signatures given");
  if (! sig && ! opt_sigfile)
    fatal("No signature given");

  if (opt_curve) {
    if (! (cp = curve_by_name(opt_curve)))
      fatal("Invalid curve name");
  }
  else
    if (! (cp = curve_by_pk_len_compact(strlen(pubkey))))
      fatal("Invalid verification key (wrong length)");

  if (opt_verbose) {
    print_quiet("VERSION: ", 0);
    fprintf(stderr, VERSION "\n"); 
    print_quiet("CURVE: ", 0);
    fprintf(stderr, "%s\n", cp->name); 
  }

  if (strlen(pubkey) != cp->pk_len_compact)
    fatal("Invalid verification key (wrong length)");

  if ((res = decompress_from_string(&Q, pubkey, DF_COMPACT, cp))) {
    if (sig) {
      if ((res = (strlen(sig) == cp->sig_len_compact))) {
	if (! (res = deserialize_mpi(&s, DF_COMPACT, sig, cp->sig_len_compact)))
	  print_quiet("Invalid signature (inconsistent structure)!\n", 1);
      }
      else
	print_quiet("Invalid signature (wrong length)!\n", 1);
    }
    else {
      FILE *sigfile;
      if (! (sigfile = fopen(opt_sigfile, "r")))
	fatal_errno("Cannot open signature file", errno);
      if (opt_sigbin) {
	char sigbuf[cp->sig_len_bin];
	if ((res = (fread(sigbuf, cp->sig_len_bin, 1, sigfile) == 1))) {
	  if (! (res = deserialize_mpi(&s, DF_BIN, sigbuf, cp->sig_len_bin)))
	    print_quiet("Invalid signature (inconsistent structure)!\n", 1);
	}
	else {
	  if (ferror(sigfile))
	    fatal_errno("Cannot read signature", errno);
	  else 
	    print_quiet("Invalid signature (wrong length)!\n", 1);
	}
      }
      else {
	char sigbuf[cp->sig_len_compact + 2];
	sigbuf[0] = '\0';
	if (! fgets(sigbuf, cp->sig_len_compact + 2, sigfile) && 
	    ferror(sigfile))
	  fatal_errno("Cannot read from signature file", errno);
	sigbuf[strcspn(sigbuf, " \r\n")] = '\0';
	if ((res = (strlen(sigbuf) == cp->sig_len_compact))) {
	  if (! (res = deserialize_mpi(&s, DF_COMPACT, sigbuf, 
				       cp->sig_len_compact)))
	    print_quiet("Invalid signature (inconsistent structure)!\n", 1);
	}
	else
	  print_quiet("Invalid signature (wrong length)!\n", 1);
      }
      if (fclose(sigfile))
	fatal_errno("Cannot close signature file", errno);
    }

    if (res) {
      if (isatty(opt_fdin))
	print_quiet("Go ahead and type your message ...\n", 0);
      
      err = gcry_md_open(&mh, GCRY_MD_SHA512, 0);
      if (gcry_err_code(err))
	fatal_gcrypt("Cannot initialize hash function", err);
      verisign_loop(opt_fdin, opt_fdout, &mh, opt_sigcopy);
      gcry_md_final(mh);
      md = (char*)gcry_md_read(mh, 0);
      
      if (opt_verbose) {
	int i;
	print_quiet("SHA512: ", 0);
	for(i = 0; i < 64; i++)
	  fprintf(stderr, "%02x", (unsigned char)md[i]);
	fprintf(stderr, "\n");
      }
      
      if ((res = ECDSA_verify(md, &Q, s, cp)))
	print_quiet("Signature successfully verified!\n", 0);
      else
	print_quiet("Invalid signature!\n", 1);
      
      gcry_md_close(mh);
      gcry_mpi_release(s);
    }
    point_release(&Q);
  }
  else
    fatal("Invalid verification key");
  curve_release(cp);
  return ! res;
}

/******************************************************************************/

int main(int argc, char **argv)
{
  char *progname;
  int res = 0, i;

#if ! NOMEMLOCK
  if (mlockall(MCL_CURRENT | MCL_FUTURE) < 0)
    fatal_errno("Cannot obtain memory lock", errno);
#endif

  if (getuid() != geteuid())
    seteuid(getuid());

  if ((progname = strrchr(argv[0], '/')) == NULL)
    progname = argv[0];

  while((i = getopt(argc, argv, "fbm:i:o:F:s:c:hvq")) != -1)
    switch(i) {
    case 'f': opt_sigcopy = 1; break;
    case 'b': opt_sigbin = 1; break;
    case 'm':
      opt_maclen = atoi(optarg); 
      if (opt_maclen < 0 || opt_maclen > 256 || opt_maclen % 8)
	fatal("Invalid MAC length");
      opt_maclen /= 8;
      break;
    case 'i': opt_infile = optarg; break;
    case 'o': opt_outfile = optarg; break;
    case 'F': opt_pwfile = optarg; break;
    case 's': opt_sigfile = optarg; break;
    case 'c': opt_curve = optarg; break;
    case 'h': opt_help = 1; break;
    case 'v': opt_verbose = 1; break;
    case 'q': opt_quiet = 1; break;
    default:
      exit(1);
    }

  if (opt_infile)
    if ((opt_fdin = open(opt_infile, O_RDONLY)) < 0)
      fatal_errno("Cannot open input file", errno);
  if (opt_outfile) {
    int openmode = strstr(progname, "decrypt") ? 0600 : 0644;
    if ((opt_fdout = 
	 open(opt_outfile, O_WRONLY | O_CREAT | O_TRUNC, openmode)) < 0)
      fatal_errno("Cannot open output file", errno);
  }
  if (opt_pwfile) {
    if ((opt_fdpw = open(opt_pwfile, O_RDONLY)) < 0)
      fatal_errno("Cannot open password file", errno);
  }
  else
    if (opt_infile || isatty(STDIN_FILENO))
      opt_fdpw = STDIN_FILENO;
    else
      if ((opt_fdpw = open("/dev/tty", O_RDONLY)) < 0)
	fatal_errno("Cannot open tty", errno);
  
  if (strstr(progname, "key")) {
    if (opt_help || optind != argc)
      puts("Generate public key from secret key (seccure version " VERSION ").\n"
	   "\n"
	   "seccure-key [-c curve] [-F pwfile]");
    else
      app_print_public_key();
  }
  else if (strstr(progname, "encrypt")) {
    if (opt_help || optind != argc - 1)
      puts("Encrypt using a public key (seccure version " VERSION ").\n"
	   "\n"
	   "seccure-encrypt [-m maclen] [-c curve] [-i infile] [-o outfile] key");
    else
      app_encrypt(argv[optind]);
  }
  else if (strstr(progname, "decrypt")) {
    if (opt_help || optind != argc)
      puts("Decrypt using a secret key (seccure version " VERSION ").\n"
	   "\n"
	   "seccure-decrypt [-m maclen] [-c curve] [-i infile] [-o outfile] [-F pwfile]");
    else
      res = app_decrypt();
  }
  else if (strstr(progname, "sign")) {
    if (opt_help || optind != argc)
      puts("Generate a signature (seccure version " VERSION ").\n"
	   "\n"
	   "seccure-sign [-f] [-b] [-c curve] [-s sigfile] [-i infile] [-o outfile]\n"
	   "             [-F pwfile]");
    else
      app_sign();
  }
  else if (strstr(progname, "verify")) {
    if (opt_help || (optind != argc - 2 && optind != argc - 1))
      puts("Verify a signature (seccure version " VERSION ").\n"
	   "\n"
	   "seccure-verify [-f] [-b] [-c curve] [-s sigfile] [-i infile] [-o outfile]\n" 
	   "               key [signature]");
    else
      res = app_verify(argv[optind], argv[optind + 1]);
  }
  else 
    fatal("Unknown command");

  if (opt_infile)
    close(opt_fdin);
  if (opt_outfile)
    close(opt_fdout);
  if (opt_pwfile || (! opt_infile && ! isatty(STDIN_FILENO)))
    close(opt_fdpw);

  exit(res);
}
