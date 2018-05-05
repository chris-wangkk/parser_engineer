#ifndef __BITMAP_OPER_H__
#define __BITMAP_OPER_H__

#define SERVICE_SET(aulMap, index)	((aulMap)[(index)/32] |= (1 << ((index)%32)))
#define SERVICE_GET(aulMap, index)	((aulMap)[(index)/32] & (1 << ((index)%32)))
#define SERVICE_CLR(aulMap, index)	((aulMap)[(index)/32] &= !(1 << ((index)%32)))
#define BITMAP_CMP(aulMapA, aulMapB, icnt, range, result) \
do{ \
	for((icnt) = 0; (icnt) <= (range)/32; (icnt)++) \
		(result) = (aulMapA)[(icnt)]&(aulMapB)[(icnt)]; \
		if((result)) \
			break; \
}while(0);


#endif
