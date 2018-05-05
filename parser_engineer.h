#ifndef __PARSER_ENGINEER_H__
#define __PARSER_ENGINEER_H__

#include "base_type_define.h"
#include "parser_unit.h"
#include "observersubject.h"
#include "service_common.h"
#include "id_allocer.h"
#include <linux/poll.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/kmod.h>
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/spinlock.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/in.h>
#include <net/sock.h>
#include <linux/sched.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/if_pppox.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/mutex.h>
#include <linux/completion.h>
#include <linux/netfilter_ipv4.h>


//support 100 rfc parsers yet
#define MAX_RFC_PARSERS_NUM	200
//support 1000 featuer parsers yet
#define MAX_FEATURE_PARSERS_NUM	1000


//for return
#define PARSEPROC_RET_OK	0
#define PARSEPROC_RET_ERR	(-1)



typedef struct tagRfcParserIdAllocer{
	IDALLOCER_CONSTRUCTOR(MAX_RFC_PARSERS_NUM)
}RfcParserIdAllocer;

typedef struct tagFeatureParserIdAllocer{
	IDALLOCER_CONSTRUCTOR(MAX_FEATURE_PARSERS_NUM)
}FeatureParserIdAllocer;


typedef struct tagFeatureParser
{
	USHORT	usAllocAppId;	//key
	UCHAR	ucServiceId;
	UCHAR 	ucFeatureLen;
	CHAR 	*pcFeatureValue;
	USHORT	usStartPos;
	USHORT	usScanLen;
	struct	list_head pstlist; 
}FeatureParser;


//for current pkt
typedef struct tagL2Info{
	CHAR	*pcIfname;
	UCHAR	*pucSrcMac;
	USHORT	usL3Prot;	//only support IPv4 yet
}L2Info;

typedef struct tagL3Info{
	UINT	uiSrcIp;
	UINT	uiDstIp;
	USHORT	usPktLen;
	UCHAR 	ucL4Prot;
	UCHAR	ucTTL;
	//...
}L3Info;

typedef struct tagL4Info{
	USHORT	usSrcPort;
	USHORT	usDstPort;
	USHORT	usL7PktLen;
	USHORT	usRsv;
	CHAR 	*pcL7Data; 
	//...
}L4Info;

typedef struct tagL7Info{
	UCHAR		ucL7Prot;
	UCHAR		ucRsv;
	USHORT		usAppId;
	RfcKeyInfo	*pstRfcKeyInfoList;
	//...
}L7Info;

typedef struct tagPktInfo{
	//in
	L2Info		stL2Info;
	L3Info		stL3Info;
	L4Info		stL4Info;
	L7Info		stL7Info;
	//out
	MatchResult	eMatchResult;
	PktAct		ePktAct;
}PktInfo;

typedef struct tagParseNotifier{
	SUBJECT_INTERFACE
	PktInfo 			stPktInfo;
	ServiceIdAllocer	serviceAllocer;
	ULONG	aulServiceMap[MAX_SERVICE_ID/32 + 1];
	ULONG	aulCurServices[MAX_SERVICE_ID/32 + 1];
	ULONG	aulParserUnitMap[MAX_PARSERUNIT_NUM/32 + 1];
}ParseNotifier;

//notify msg follow(new msg can be added at the tail but the order can not be changed):
#define SIMPLE_IDENT_OUTPUT	1
#define L7_IDENT_OUTPUT		2
#define L7_PARSE_OUTPUT		3
#define PARSEPROC_FINISH	4
#define SERVICEPROC_FINISH	5


//for parse proc
typedef enum tagParseState{
	SIMPLE_IDENT_STATE = SIMPLE_IDENT_OUTPUT,
	L7_IDENT_STATE,
	L7_PARSE_STATE,
	BUTT_PARSE_STATE,
}ParseState;

typedef VOID (*ParseFunc)(struct sk_buff *, PktInfo *, ULONG *);

typedef struct tagParseCallBack{
	ParseState	eParseState;
	ParseFunc	pfParseFunc;
}ParseCallBack;

extern UCHAR rfcParserAdd(RfcParserIn	*pstRfcParser);
extern VOID rfcParserDel(UCHAR ucServiceId, UCHAR ucProtId, UCHAR ucAllocId);
extern int featureParserAdd(FeatureParser	*pstFeatureParser);
extern VOID* featureParserDel(USHORT	usAppId);
extern INT app_register_hook(ServiceSubscriber *subscriber, USHORT usPriority);
extern VOID app_unregister_hook(ServiceSubscriber *subscriber);
extern INT parse_register_hook(ParseUnit *pstParseUnit);
extern VOID parse_unregister_hook(UCHAR ucL7Prot);
#endif
