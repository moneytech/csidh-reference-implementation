#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <getopt.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "fp.h"
#include "csidh.h"
#define VERSION 0.1

int main(int argc, char **argv)
{
  private_key priv_stdio;
  public_key pub_stdio;
  public_key shared_stdio;

  unsigned char sk[sizeof(priv_stdio)];
  unsigned char pk[sizeof(pub_stdio)];
  bzero(sk, sizeof(priv_stdio));
  bzero(pk, sizeof(pub_stdio));

  bzero(&priv_stdio, sizeof(priv_stdio));
  bzero(&pub_stdio, sizeof(pub_stdio));
  bzero(&shared_stdio, sizeof(shared_stdio));

  int o = 0;
  size_t v = 0;
  size_t g = 0;
  size_t d = 0;
  size_t p = 0;
  size_t s = 0;
  size_t e = 0;
  char *priv_key_file = NULL;
  char *pub_key_file = NULL;
  FILE *fhandle;
  size_t c = 0;

  while((o = getopt(argc, argv, "hvVgdp:s:")) != -1) {
    switch(o) {
    case 'V':
      fprintf(stderr, "csidh-p%i-util (%i-bit) version: %f\n", BITS, BITS, VERSION);
      return 0;
    case 'h':
      fprintf(stderr, "csidh-p%i-util (%i-bit) version: %f\n", BITS, BITS, VERSION);
      fprintf(stderr, "  -V: print version\n");
      fprintf(stderr, "  -v: increase verbosity\n");
      fprintf(stderr, "  -g: key generation mode\n");
      fprintf(stderr, "  -d: key derivation mode\n");
      fprintf(stderr, "  -p: public key file name\n");
      fprintf(stderr, "  -s: private key file name\n");
      return 0;
    case 'v':
      v += 1;
      break;
    case 'g':
      g = 1;
      if (d) {e+=1;};
      break;
    case 'd':
      d = 1;
      if (g) {e+=1;};
      break;
    case 'p':
      p = 1;
      pub_key_file = optarg;
      if (v) {printf("pub_key_file=%s\n", pub_key_file);};
      break;
    case 's':
      s = 1;
      priv_key_file = optarg;
      if (v) {printf("priv_key_file=%s\n", priv_key_file);};
      break;
    default:
      exit(1);
    }
  }
  if (e != 0) {
    printf("Mutually exclusive options chosen; select operation mode '-g' or '-d'.\n");
    return 1;
  } else { if (v) { if (d) {printf("DH mode\n");} if (g) {printf("Key generation mode\n");}  }; }

  if (g) {
    csidh_private(&priv_stdio);
    assert(csidh(&pub_stdio, &base, &priv_stdio));
    if (s && priv_key_file != NULL) {
      // XXX: check for fopen errors
      fhandle = fopen(priv_key_file, "w");
      for (size_t i = 0; i < sizeof(priv_stdio); ++i)
          fprintf(fhandle ,"%02hhx", i[(uint8_t *) &priv_stdio]);
      fprintf(fhandle, "\n");
      fclose(fhandle);
    } else {
      for (size_t i = 0; i < sizeof(priv_stdio); ++i)
          printf("%02hhx", i[(uint8_t *) &priv_stdio]);
      printf("\n");
    }
    if (p && pub_key_file != NULL) {
      fhandle = fopen(pub_key_file, "w");
      for (size_t i = 0; i < sizeof(pub_stdio); ++i)
          fprintf(fhandle, "%02hhx", i[(uint8_t *) &pub_stdio]);
      fprintf(fhandle, "\n");
      fclose(fhandle);
    } else {
      for (size_t i = 0; i < sizeof(pub_stdio); ++i)
          printf("%02hhx", i[(uint8_t *) &pub_stdio]);
      printf("\n");
    }
    return 0;
  }

  if (d) {
    if (s && priv_key_file != NULL) {
      c = 0;
      fhandle = fopen(priv_key_file, "r");
      for (size_t i = 0; i < (sizeof(priv_stdio)); ++i) {
        c += fscanf(fhandle, "%02hhx", &sk[i]);
      }
      fprintf(fhandle, "\n");
      fclose(fhandle);
    } else {
      for (size_t i = 0; i < (sizeof(priv_stdio)); ++i) {
        c += scanf("%02hhx", &sk[i]);
      }
    }
    memcpy(&priv_stdio.e, sk, sizeof(priv_stdio));
    if (v) {
      printf("Private key (%li bytes):\n", c);
      for (size_t i = 0; i < sizeof(priv_stdio); ++i)
          printf("%02hhx", i[(uint8_t *) &priv_stdio]);
      printf("\n");
    }
    if (p && pub_key_file != NULL) {
      c = 0;
      fhandle = fopen(pub_key_file, "r");
      for (size_t i = 0; i < (sizeof(pub_stdio)); ++i) {
        c += fscanf(fhandle, "%02hhx", &pk[i]);
      }
      fprintf(fhandle, "\n");
      fclose(fhandle);
    } else {
      for (size_t i = 0; i < (sizeof(pub_stdio)); ++i) {
        c += scanf("%02hhx", &pk[i]);
      }
    }
    memcpy(&pub_stdio.A, pk, sizeof(pub_stdio));
    if (v) {
      printf("Public key (%li bytes):\n", c);
      for (size_t i = 0; i < sizeof(pub_stdio); ++i)
          printf("%02hhx", i[(uint8_t *) &pub_stdio]);
      printf("\n");
    }
    assert(csidh(&shared_stdio, &pub_stdio, &priv_stdio));
    if (v) {
      printf("Shared session key (hex):\n");
    }
    for (size_t i = 0; i < sizeof(shared_stdio); ++i)
        printf("%02hhx", i[(uint8_t *) &shared_stdio]);
    printf("\n");
    return 0;
  }

  return 0;
}
