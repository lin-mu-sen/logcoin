#ifndef HASHBLOCK_H
#define HASHBLOCK_H

#include "uint256.h"
#include "uint512.h"
#include "sph_skein.h"

#ifndef QT_NO_DEBUG
#include <string>
#endif

#define _ALIGN(x) __declspec(align(x))

#ifdef GLOBALDEFINED
#define GLOBAL
#else
#define GLOBAL extern
#endif

GLOBAL sph_skein512_context     z_skein;

#define fillz() do { \
    sph_skein512_init(&z_skein); \
} while (0) 

#define ZSKEIN (memcpy(&ctx_skein, &z_skein, sizeof(z_skein)))

template<typename T1>
inline uint256 Hash2(const T1 pbegin, const T1 pend)
//void Hash2(const char *pbegin, char *pend)

{
    sph_skein512_context     ctx_skein;
    static unsigned char pblank[1];
    printf("inside hash2 mark1 %i  %i  ", sizeof(pbegin[0]), (pend-pbegin));
//(pend - pbegin) * sizeof(pbegin[0])

    uint512 hash[2];
    sph_skein512_init(&ctx_skein);    sph_skein512 (&ctx_skein, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), 80);
 //   sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[0]), 64);
    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[0]));


    sph_skein512 (&ctx_skein, static_cast<const void*>(&hash[0]), 64);
    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash[1]));
    
    //printf("ending hash2 with %s", hash[1].trim256().ToString().c_str());

    return hash[1].trim256();
}


void skein2hash(void *output, const void *input)
{
	uint32_t hash[16];

	sph_skein512_context ctx_skein;

	sph_skein512_init(&ctx_skein);
	sph_skein512(&ctx_skein, input, 80);
	sph_skein512_close(&ctx_skein, hash);

	sph_skein512_init(&ctx_skein);
	sph_skein512(&ctx_skein, hash, 64);
	sph_skein512_close(&ctx_skein, hash);

	memcpy(output, hash, 32);
}




#endif // HASHBLOCK_H
