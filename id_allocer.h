#ifndef __ID_ALLOCER_H__
#define __ID_ALLOCER_H__

#include "base_type_define.h"

#define INVALID_ALLOCID	0

#define IDALLOCER_CONSTRUCTOR(max) \
	USHORT	usTotal; \
	USHORT	usAlloc; \
	USHORT	usPos; \
	USHORT	usRsv; \
	ULONG	aucUsed[((max) + 1)/32 + 1];

#define IDALLOCER_INIT(allocer, max) \
do{ \
	memset(&(allocer), 0, sizeof(allocer)); \
	(allocer).usTotal = (max); \
	(allocer).usPos = 1; \
}while(0);

#define IDALLOCER_SIZE(allocer)	(allocer).usTotal
#define IDALLOCER_ALLOCED(allocer)	(allocer).usAlloc
#define IS_IDALLOCER_FULL(allocer)	((allocer).usAlloc >= (allocer).usTotal)
#define ALLOC_FAIL(allocer, allocid)	(INVALID_ALLOCID == (allocid) || (allocid) > (allocer).usTotal)


#define IDALLOCER_SET(icnt, allocer, newid) \
do{ \
	if(IS_IDALLOCER_FULL(allocer)) \
		(newid) = INVALID_ALLOCID; \
	else \
	{ \
		for((icnt) = (allocer).usPos; (icnt) <= (allocer).usTotal; (icnt)++) \
			if(0 == (((allocer).aucUsed)[(icnt)/32] & (1 << ((icnt)%32)))) \
			{ \
				(newid) = (icnt); \
				break; \
			} \
		(allocer).usAlloc++; \
		(allocer).usPos++; \
		if((allocer).usPos == (allocer).usTotal) \
			(allocer).usPos = 1; \
	} \
}while(0);


#define IDALLOCER_RMV(allocer, rmvid) \
do{ \
	if((rmvid) <= (allocer).usTotal) \
		if((allocer).aucUsed[(rmvid)/32] & (1 << ((rmvid)%32))) \
		{ \
			(allocer).aucUsed[(rmvid)/32] &= !(1 << ((rmvid)%32)); \
			(allocer).usAlloc--; \
		} \
}while(0);



#endif
