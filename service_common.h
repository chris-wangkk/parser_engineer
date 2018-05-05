#ifndef __SERVICE_COMMON_H__
#define __SERVICE_COMMON_H__

#include "observersubject.h"
#include "id_allocer.h"

//the order can not be changed

typedef enum tagMatchResult{
	//succ > fail > not match
	NOT_MATCH_YET,
	MATCH_FAIL,
	MATCH_SUCC,
}MatchResult;

//effective only if match succ and the order can not be changed
typedef enum tagPktAct{
	//mod pkt > drop pkt > pass pkt > noting to do
	NO_ACT,
	ACT_PASS,
	ACT_DROP,
}PktAct;

#define SERVICE_SUBSCRIBER_INTERFACE \
	OBSERVER_INTERFACE \
	UCHAR ucServiceId; \
	UCHAR ucModPkt; \
	UCHAR aucRsv[2]; \
	MatchResult eMatchResult; \
	PktAct		ePktAct;

typedef struct tagServiceSubscriber{
	SERVICE_SUBSCRIBER_INTERFACE
}ServiceSubscriber;

//support 100 services registered yet
#define MAX_SERVICE_ID	100

#define SERVICE_INVALID(SvcId)	((SvcId) > MAX_SERVICE_ID || 0 == (SvcId))

//for allocer
typedef struct tagServiceIdAllocer{
	IDALLOCER_CONSTRUCTOR(MAX_SERVICE_ID)
}ServiceIdAllocer;



#endif
