#ifndef __PARSER_UNIT_H__
#define __PARSER_UNIT_H__

#include "base_type_define.h"
#include "bitmap_oper.h"
#include "exception_proc.h"
#include "service_common.h"
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/skbuff.h>


//for return
#define PARSEOPER_RET_OK	0
#define PARSEOPER_RET_ERR	(-1)


//l7 protocol
#define UNKNOWN_PROTOCOL	0x00FF
#define DNS_PROTOCOL		0x0001
#define HTTP_PROTOCOL		0x0002

#define MAX_PARSERUNIT_NUM	50
#define PARSERUNIT_INVALID(protId)	((protId) > MAX_PARSERUNIT_NUM || 0 == (protId))


#define RFC_KEY_MAXLEN	512


typedef struct tagRfcKeyInfo{
	USHORT			usKeyLen;
	UCHAR			ucAllocId;
	UCHAR			ucRsv;
	CHAR			*pcKey;
	struct tagRfcKeyInfo	*pstNext;
}RfcKeyInfo;

//about rfc parser rule
typedef struct tagRfcParserIn{
	UCHAR	ucL7Prot;
	UCHAR	ucRsv;
	UCHAR	ucServiceId;
	UCHAR	ucKeyLen;
	CHAR	aucKeyValue[256];
	struct	list_head pstlist;
}RfcParserIn;

typedef struct tagRfcParser{
	UCHAR	ucL7Prot;
	UCHAR	ucOwners;
	UCHAR	ucAllocId;	//key
	UCHAR	ucKeyLen;
	ULONG	aulParserOwners[MAX_SERVICE_ID/32 + 1];
	CHAR	*pcKeyValue;
	struct	list_head pstlist;
}RfcParser;


typedef BOOL (*ProtoComfirmFunc)(struct sk_buff *skb, USHORT usDstPort, UCHAR ucL4Prot);
typedef RfcKeyInfo* (*ProtoParseFunc)(CHAR *pcL7Data, USHORT usL7PktLen, ULONG *aulServiceMap);
typedef VOID (*ProtoCfgSetFunc)(RfcParserIn	*pstIn, UCHAR *pucAllocId);
typedef BOOL (*ProtoCfgAddFunc)(RfcParserIn	*pstIn);
typedef VOID (*ProtoCfgDelFunc)(UCHAR ucServiceId, UCHAR ucAllocId);


typedef struct tagParseUnit{
	UCHAR				ucL7Prot;	//keep consistant with l7 protocol and must be unique
	UCHAR				ucRsv;
	USHORT 				usPriority;
	USHORT				usCapacity;
	USHORT				usAlloced;
	//ULONG				aulRfcParsersMap[MAX_RFC_PARSERS_NUM/32 + 1];
	ProtoCfgSetFunc		pfProtoRuleSetFunc;
	ProtoCfgAddFunc		pfProtoRuleAddFunc;
	ProtoCfgDelFunc		pfProtoRuleDelFunc;
	ProtoComfirmFunc	pfProtoComfirmFunc;
	ProtoParseFunc		pfProtoParseFunc;
	struct	list_head 	pstlist; 
}ParseUnit;

typedef RfcKeyInfo* (*ParserFunc)(CHAR *pcL7Data, USHORT usL7PktLen, RfcParser	*pstParser);


#define RFC_PARSER_RULE_ATTR_TEMPLATE(protoname) \
	struct list_head g_##protoname##Parser_list_head = LIST_HEAD_INIT(g_##protoname##Parser_list_head); \
	spinlock_t g_##protoname##Parser_lock;

#define RFC_PARSER_RULE_OPER_TEMPLATE(protoname) \
	VOID protoname##ParserSet(RfcParserIn	*pstIn, UCHAR *pucAllocId) \
	{ \
		RfcParser	*pstTmp; \
		*(pucAllocId) = 0; \
		spin_lock_bh(&g_##protoname##Parser_lock); \
		list_for_each_entry(pstTmp, &g_##protoname##Parser_list_head, pstlist) \
		{ \
			if((pstIn)->ucKeyLen == pstTmp->ucKeyLen) \
			{ \
				if(0 == memcmp((const void *)(pstIn)->aucKeyValue, (const void *)pstTmp->pcKeyValue, pstTmp->ucKeyLen)) \
				{ \
					SERVICE_SET(pstTmp->aulParserOwners, pstIn->ucServiceId); \
					pstTmp->ucOwners++; \
					*(pucAllocId) = pstTmp->ucAllocId; \
					break; \
				} \
			} \
		} \
		spin_unlock_bh(&g_##protoname##Parser_lock); \
		return; \
	} \
	BOOL protoname##ParserAdd(RfcParserIn	*pstIn) \
	{ \
		RfcParser	*pstNew; \
		pstNew = (RfcParser *)kmalloc(sizeof(RfcParser), GFP_KERNEL); \
		if(!pstNew) \
		{ \
			spin_unlock_bh(&g_##protoname##Parser_lock); \
			return false; \
		} \
		pstNew->pcKeyValue = (CHAR *)kmalloc(sizeof(UCHAR) * (pstIn->ucKeyLen + 1), GFP_KERNEL); \
		if(!(pstNew->pcKeyValue)) \
		{ \
			kfree((VOID *)pstNew); \
			spin_unlock_bh(&g_##protoname##Parser_lock); \
			return false; \
		} \
		pstNew->ucL7Prot = (pstIn)->ucL7Prot; \
		pstNew->ucOwners = 1; \
		pstNew->ucKeyLen = (pstIn)->ucKeyLen; \
		SERVICE_SET(pstNew->aulParserOwners, pstIn->ucServiceId); \
		memcpy((void *)pstNew->pcKeyValue, (const void *)pstIn->aucKeyValue, pstNew->ucKeyLen); \
		pstNew->pcKeyValue[pstNew->ucKeyLen] = '\0'; \
		spin_lock_bh(&g_##protoname##Parser_lock); \
		list_add_tail(&pstNew->pstlist, &g_##protoname##Parser_list_head); \
		spin_unlock_bh(&g_##protoname##Parser_lock); \
		return true; \
	} \
	VOID protoname##ParserDel(UCHAR ucServiceId, UCHAR ucAllocId) \
	{ \
		RfcParser	*pstTmp = NULL; \
		spin_lock_bh(&g_##protoname##Parser_lock); \
		list_for_each_entry(pstTmp, &g_##protoname##Parser_list_head, pstlist) \
		{ \
			if((ucAllocId) == pstTmp->ucAllocId) \
			{ \
				SERVICE_CLR(pstTmp->aulParserOwners, (ucServiceId)); \
				pstTmp->ucOwners--; \
				if(0 == pstTmp->ucOwners) \
				{ \
					list_del(&pstTmp->pstlist); \
					kfree((VOID *)pstTmp); \
				} \
				break; \
			} \
		} \
		spin_unlock_bh(&g_##protoname##Parser_lock); \
		return; \
	} \
	static VOID commInfoInit(ParseUnit *pstParseUnit) \
	{ \
		spin_lock_init(&g_##protoname##Parser_lock); \
		(pstParseUnit)->pfProtoRuleSetFunc = protoname##ParserSet; \
		(pstParseUnit)->pfProtoRuleAddFunc = protoname##ParserAdd; \
		(pstParseUnit)->pfProtoRuleDelFunc = protoname##ParserDel; \
		return; \
	} \
	static RfcKeyInfo* pktParse(CHAR *pcL7Data, USHORT usL7PktLen, ULONG *aulServiceMap, ParserFunc pfParserFunc) \
	{ \
		RfcKeyInfo *pstNew, *pstResult = NULL; \
		RfcParser	*pstTmp; \
		ULONG ulResult = 0; \
		UINT icnt; \
		USHORT usCntForExp = 0; \
		spin_lock_bh(&g_##protoname##Parser_lock); \
		list_for_each_entry(pstTmp, &g_##protoname##Parser_list_head, pstlist) \
		{ \
			LOOP_EXCEPTION(usCntForExp, MAX_RFC_PARSERS_NUM, __func__) \
			BITMAP_CMP((aulServiceMap), pstTmp->aulParserOwners, icnt, MAX_SERVICE_ID, ulResult) \
			if(0 == ulResult) \
				continue; \
			pstNew = pfParserFunc((pcL7Data), (usL7PktLen), pstTmp); \
			if(NULL != pstNew) \
			{ \
				pstNew->pstNext = pstResult; \
				pstResult = pstNew; \
			} \
		} \
		spin_unlock_bh(&g_##protoname##Parser_lock); \
		return pstResult; \
	}

#define RFC_PARSER_RULE_TEMPLATE(protoname) \
	RFC_PARSER_RULE_ATTR_TEMPLATE(protoname) \
	RFC_PARSER_RULE_OPER_TEMPLATE(protoname)
	

#define COMMINFOINIT commInfoInit
#define PKTPARSE pktParse

#endif
