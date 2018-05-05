#include "parser_engineer.h"
#include "bitmap_oper.h"
#include "exception_proc.h"

struct list_head g_rfcParser_list_head = LIST_HEAD_INIT(g_rfcParser_list_head);  
struct list_head g_featureParser_list_head = LIST_HEAD_INIT(g_featureParser_list_head);
struct list_head g_parserUnit_list_head = LIST_HEAD_INIT(g_parserUnit_list_head);

spinlock_t g_service_lock;
spinlock_t g_parserUnit_lock;
spinlock_t g_rfcParser_lock;                          
spinlock_t g_featureParser_lock;
static RfcParserIdAllocer g_rfcParser_allocer;
static FeatureParserIdAllocer g_featureParser_allocer;

ParseNotifier *g_service_notifier = NULL;


UCHAR rfcParserAdd(RfcParserIn *pstRfcParser)
{
#if 1
	ParseUnit *pstTmp;
	INT	iCnt;
	USHORT usCntForExp = 0;
	UCHAR ucAllocId = INVALID_ALLOCID;
	BOOL bFind = false;

	//check validity
	if(PARSERUNIT_INVALID(pstRfcParser->ucL7Prot) || SERVICE_INVALID(pstRfcParser->ucServiceId))
		return INVALID_ALLOCID;
	if(0 == pstRfcParser->ucKeyLen)
		return INVALID_ALLOCID;
	//error if not support yet
	if(!SERVICE_GET(g_service_notifier->aulParserUnitMap, pstRfcParser->ucL7Prot))
	{
		printk(KERN_EMERG"[rfcParserAdd] parserEngineer not support yet for %d\n", pstRfcParser->ucL7Prot);
		return INVALID_ALLOCID;
	}
	//no resource to alloc
	if(IS_IDALLOCER_FULL(g_rfcParser_allocer))
	{
		printk(KERN_EMERG"[rfcParserAdd] cnt over Cnt = %d\n", IDALLOCER_ALLOCED(g_rfcParser_allocer));
		return INVALID_ALLOCID;
	}	

	list_for_each_entry(pstTmp, &g_parserUnit_list_head, pstlist)
	{
		//for exception
		LOOP_EXCEPTION(usCntForExp, MAX_PARSERUNIT_NUM, __func__)

		if(pstTmp->ucL7Prot == pstRfcParser->ucL7Prot)
		{
			bFind = true;
			break;
		}
	}
	if(false == bFind)
	{
		printk(KERN_EMERG"[rfcParserAdd] not find for %d\n", pstRfcParser->ucL7Prot);
		return INVALID_ALLOCID;
	}

	if(NULL == pstTmp->pfProtoRuleSetFunc)
		return INVALID_ALLOCID;
	pstTmp->pfProtoRuleSetFunc(pstRfcParser, &ucAllocId);

	//mod branch
	if(INVALID_ALLOCID != ucAllocId)
		return ucAllocId;
	//add branch
	if(NULL == pstTmp->pfProtoRuleAddFunc)
		return INVALID_ALLOCID;
	
	IDALLOCER_SET(iCnt, g_rfcParser_allocer, ucAllocId)
	if(ALLOC_FAIL(g_rfcParser_allocer, ucAllocId))
	{
		printk(KERN_EMERG"[rfcParserAdd] alloc id[%d] fail \n", ucAllocId);
		return INVALID_ALLOCID;
	}
	
	if(false == pstTmp->pfProtoRuleAddFunc(pstRfcParser))
	{
		IDALLOCER_RMV(g_rfcParser_allocer, ucAllocId)
		return INVALID_ALLOCID;
	}
	return ucAllocId;
#else
	RfcParser	*pstTmp;
	ParseUnit 	*pstParseUnit;
	INT	iCnt;
	USHORT usCntForExp = 0;

	spin_lock_bh(&g_rfcParser_lock);
	//mod branch
	if(0 != pstRfcParser->ucAllocId)
	{
		list_for_each_entry(pstTmp, &g_rfcParser_list_head, pstlist)
		{
			//for exception
			LOOP_EXCEPTION(usCntForExp, IDALLOCER_SIZE(g_rfcParser_allocer), __func__)

			//find it
			if(pstRfcParser->ucAllocId == pstTmp->ucAllocId)
			{
				//excp(just notice yet)
				if(pstRfcParser->ucServiceId != pstTmp->ucServiceId)
					printk(KERN_EMERG"[rfcParserAdd] exception ucServiceId is inconsistent out[%d] in[%d]\n", 
						pstRfcParser->ucServiceId, pstTmp->ucServiceId);

				list_replace(&(pstTmp->pstlist), &(pstRfcParser->pstlist));
				kfree(pstTmp);
				spin_unlock_bh(&g_rfcParser_lock);
				return PARSEPROC_RET_OK;
			}
		}
	}
	//add branch
	else
	{
		if(IS_IDALLOCER_FULL(g_rfcParser_allocer))
		{
			printk(KERN_EMERG"[rfcParserAdd] cnt over Cnt = %d\n", IDALLOCER_ALLOCED(g_rfcParser_allocer));
			spin_unlock_bh(&g_rfcParser_lock);
			return PARSEPROC_RET_ERR;
		}
		printk(KERN_EMERG"tmp[rfcParserAdd] add branch\n");
		IDALLOCER_SET(iCnt, g_rfcParser_allocer, pstRfcParser->ucAllocId)

		if(ALLOC_FAIL(g_rfcParser_allocer, pstRfcParser->ucAllocId))
		{
			printk(KERN_EMERG"[rfcParserAdd] alloc id[%d] fail \n", pstRfcParser->ucAllocId);
			pstRfcParser->ucAllocId = 0;
			spin_unlock_bh(&g_rfcParser_lock);
			return PARSEPROC_RET_ERR;
		}
		list_add_tail(&pstRfcParser->pstlist, &g_rfcParser_list_head);
	}
	spin_unlock_bh(&g_rfcParser_lock);
	return PARSEPROC_RET_OK;
#endif
}
EXPORT_SYMBOL(rfcParserAdd);

VOID rfcParserDel(UCHAR ucServiceId, UCHAR ucProtId, UCHAR ucAllocId)
{
#if 1
	ParseUnit *pstTmp;
	USHORT usCntForExp = 0;

	//check validity
	if(PARSERUNIT_INVALID(ucProtId) || SERVICE_INVALID(ucServiceId))
		return;
	//error if not support yet
	if(!SERVICE_GET(g_service_notifier->aulParserUnitMap, ucProtId))
	{
		printk(KERN_EMERG"[rfcParserDel] parserEngineer not support yet for %d\n", ucProtId);
		return;
	}

	if(0 == IDALLOCER_ALLOCED(g_rfcParser_allocer))
	{
		printk(KERN_EMERG"[rfcParserDel] cnt is zero\n");
		return;
	}

	list_for_each_entry(pstTmp, &g_parserUnit_list_head, pstlist)
	{
		//for exception
		LOOP_EXCEPTION(usCntForExp, MAX_PARSERUNIT_NUM, __func__)

		if(pstTmp->ucL7Prot == ucProtId)
		{
			if(NULL != pstTmp->pfProtoRuleDelFunc)
				return pstTmp->pfProtoRuleDelFunc(ucServiceId, ucAllocId);
			break;
		}
	}
	return;
#else
	RfcParser	*pstTmp = NULL;
	USHORT usCntForExp = 0;
	spin_lock_bh(&g_rfcParser_lock);
	if(0 == IDALLOCER_ALLOCED(g_rfcParser_allocer))
	{
		printk(KERN_EMERG"[rfcParserDel] cnt is zero\n");
		spin_unlock_bh(&g_rfcParser_lock);
		return NULL;
	}

	list_for_each_entry(pstTmp, &g_rfcParser_list_head, pstlist)
	{
		//for exception
		LOOP_EXCEPTION(usCntForExp, IDALLOCER_SIZE(g_rfcParser_allocer), __func__)

		if(ucProtId == pstTmp->ucAllocId)
		{
			list_del(&pstTmp->pstlist);
			printk(KERN_EMERG"tmp[rfcParserDel] del 1\n");
			//kfree(pstTmp);
			IDALLOCER_RMV(g_rfcParser_allocer, ucProtId)
			break;
		}
	}
	printk(KERN_EMERG"tmp[rfcParserDel] end\n");
	spin_unlock_bh(&g_rfcParser_lock);
	return pstTmp;
#endif
}
EXPORT_SYMBOL(rfcParserDel);

int featureParserAdd(FeatureParser	*pstFeatureParser)
{
	FeatureParser	*pstTmp;
	INT	iCnt;
	USHORT usCntForExp = 0;
	
	spin_lock_bh(&g_featureParser_lock);
	printk(KERN_EMERG"tmp[featureParserAdd] enter\n");
	//mod branch
	if(0 != pstFeatureParser->usAllocAppId)
	{
		list_for_each_entry(pstTmp, &g_featureParser_list_head, pstlist)
		{
			//for exception
			LOOP_EXCEPTION(usCntForExp, IDALLOCER_SIZE(g_featureParser_allocer), __func__)

			//find it
			if(pstFeatureParser->usAllocAppId == pstTmp->usAllocAppId)
			{
				//excp(just notice yet)
				if(pstFeatureParser->ucServiceId != pstTmp->ucServiceId)
					printk(KERN_EMERG"[featureParserAdd] exception ucServiceId is inconsistent out[%d] in[%d]\n", 
						pstFeatureParser->ucServiceId, pstTmp->ucServiceId);

				list_replace(&(pstTmp->pstlist), &(pstFeatureParser->pstlist));
				kfree(pstTmp);
				spin_unlock_bh(&g_featureParser_lock);
				return PARSEPROC_RET_OK;
			}
		}
	}
	//add branch
	else
	{
		IDALLOCER_SET(iCnt, g_featureParser_allocer, pstFeatureParser->usAllocAppId)
		printk(KERN_EMERG"tmp[featureParserAdd] add branch\n");
		if(ALLOC_FAIL(g_featureParser_allocer, pstFeatureParser->usAllocAppId))
		{
			printk(KERN_EMERG"[featureParserAdd] alloc id[%d] fail \n", pstFeatureParser->usAllocAppId);
			pstFeatureParser->usAllocAppId = 0;
			spin_unlock_bh(&g_featureParser_lock);
			return PARSEPROC_RET_ERR;
		}
		list_add_tail(&pstFeatureParser->pstlist, &g_featureParser_list_head);
	}
	printk(KERN_EMERG"tmp[featureParserAdd] end\n");
	spin_unlock_bh(&g_featureParser_lock);
	return PARSEPROC_RET_OK;
}
EXPORT_SYMBOL(featureParserAdd);

VOID* featureParserDel(USHORT	usAppId)
{
	FeatureParser	*pstTmp = NULL;
	USHORT usCntForExp = 0;
	printk(KERN_EMERG"tmp[featureParserDel] enter\n");
	spin_lock_bh(&g_featureParser_lock);
	if(0 == IDALLOCER_ALLOCED(g_featureParser_allocer))
	{
		printk(KERN_EMERG"[featureParserDel] cnt is zero \n");
		spin_unlock_bh(&g_featureParser_lock);
		return NULL;
	}

	list_for_each_entry(pstTmp, &g_featureParser_list_head, pstlist)
	{
		//for exception
		LOOP_EXCEPTION(usCntForExp, IDALLOCER_SIZE(g_featureParser_allocer), __func__)

		if(usAppId == pstTmp->usAllocAppId)
		{
			list_del(&pstTmp->pstlist);
			printk(KERN_EMERG"tmp[featureParserDel] del 1\n");
			//kfree(pstTmp);
			IDALLOCER_RMV(g_featureParser_allocer, usAppId)
			break;
		}
	}
	printk(KERN_EMERG"tmp[featureParserDel] end\n");
	spin_unlock_bh(&g_featureParser_lock);
	return pstTmp;
}
EXPORT_SYMBOL(featureParserDel);

INT app_register_hook(ServiceSubscriber *subscriber, USHORT usPriority)
{
	UCHAR ucNewServiceId = 0;
	INT	iCnt;
	
	if(IS_IDALLOCER_FULL(g_service_notifier->serviceAllocer))
	{
		printk(KERN_EMERG"[app_register_hook] cnt over Cnt = %d\n", IDALLOCER_ALLOCED(g_service_notifier->serviceAllocer));
		return PARSEPROC_RET_ERR;
	}

	if(true == ADD_OBSERVER((SubjectBase *)g_service_notifier, (ObserveBase *)subscriber, usPriority))
	{
		IDALLOCER_SET(iCnt, g_service_notifier->serviceAllocer, ucNewServiceId)
		subscriber->ucServiceId = ucNewServiceId;
		SERVICE_SET(g_service_notifier->aulServiceMap, ucNewServiceId);
		printk(KERN_INFO"[app_register_hook] alloc ServiceId = %d\n", ucNewServiceId);
	}
	
	return PARSEPROC_RET_OK;
}
EXPORT_SYMBOL(app_register_hook);

VOID app_unregister_hook(ServiceSubscriber *subscriber)
{
	if(subscriber->ucServiceId > IDALLOCER_SIZE(g_service_notifier->serviceAllocer))
	{
		printk(KERN_ALERT"[app_unregister_hook] ServiceId = %d is invalid \n", subscriber->ucServiceId);
		return;
	}
	
	printk(KERN_INFO"[app_unregister_hook] release ServiceId = %d\n", subscriber->ucServiceId);
	DEL_OBSERVER((SubjectBase *)g_service_notifier, (ObserveBase *)subscriber);
	SERVICE_CLR(g_service_notifier->aulServiceMap, subscriber->ucServiceId);
	subscriber->ucServiceId = 0;
	return;
}
EXPORT_SYMBOL(app_unregister_hook);

INT parse_register_hook(ParseUnit *pstParseUnit)
{
	ParseUnit *pstNew, *pstTmp;
	USHORT usCntForExp = 0;
	BOOL bInsert = false;

	//check validity
	if(NULL == pstParseUnit->pfProtoComfirmFunc || NULL == pstParseUnit->pfProtoParseFunc
		|| NULL == pstParseUnit->pfProtoRuleAddFunc || NULL == pstParseUnit->pfProtoRuleSetFunc || NULL == pstParseUnit->pfProtoRuleDelFunc)
		return PARSEPROC_RET_ERR;
	if(PARSERUNIT_INVALID(pstParseUnit->ucL7Prot))
		return PARSEPROC_RET_ERR;

	spin_lock_bh(&g_parserUnit_lock);
	//not support reconfig(need unregister in advance)
	if(SERVICE_GET(g_service_notifier->aulParserUnitMap, pstParseUnit->ucL7Prot))
	{
		spin_unlock_bh(&g_parserUnit_lock);
		return PARSEPROC_RET_ERR;
	}
	
	pstNew = (ParseUnit *)kmalloc(sizeof(ParseUnit), GFP_KERNEL);
	if (!pstNew)
		return PARSEPROC_RET_ERR;

	list_for_each_entry(pstTmp, &g_parserUnit_list_head, pstlist)
	{
		//for exception
		LOOP_EXCEPTION(usCntForExp, MAX_PARSERUNIT_NUM, __func__)

		if(pstTmp->usPriority < pstParseUnit->usPriority)
		{
			bInsert = true;
			break;
		}
	}

	pstNew->pfProtoComfirmFunc = pstParseUnit->pfProtoComfirmFunc;
	pstNew->pfProtoParseFunc = pstParseUnit->pfProtoParseFunc;
	pstNew->pfProtoRuleAddFunc = pstParseUnit->pfProtoRuleAddFunc;
	pstNew->pfProtoRuleSetFunc = pstParseUnit->pfProtoRuleSetFunc;
	pstNew->pfProtoRuleDelFunc = pstParseUnit->pfProtoRuleDelFunc;
	pstNew->ucL7Prot = pstParseUnit->ucL7Prot;
	pstNew->usPriority = pstParseUnit->usPriority;
	pstNew->usCapacity = pstParseUnit->usCapacity;
	pstNew->usAlloced = 0;

	if(false == bInsert)
		list_add_tail(&(pstNew->pstlist), &(g_parserUnit_list_head));
	else
		list_add_tail(&(pstNew->pstlist), &(pstTmp->pstlist));
	SERVICE_SET(g_service_notifier->aulParserUnitMap, pstParseUnit->ucL7Prot);
	spin_unlock_bh(&g_parserUnit_lock);
	
	return PARSEPROC_RET_OK;
}
EXPORT_SYMBOL(parse_register_hook);

VOID parse_unregister_hook(UCHAR ucL7Prot)
{
	ParseUnit *pstTmp;
	USHORT usCntForExp = 0;
	
	//check validity
	if(PARSERUNIT_INVALID(ucL7Prot))
		return;

	spin_lock_bh(&g_parserUnit_lock);
	list_for_each_entry(pstTmp, &g_parserUnit_list_head, pstlist)
	{
		//for exception
		LOOP_EXCEPTION(usCntForExp, MAX_PARSERUNIT_NUM, __func__)

		if(pstTmp->ucL7Prot == ucL7Prot)
		{
			list_del(&pstTmp->pstlist);
			kfree((VOID *)pstTmp);
			break;
		}
	}
	SERVICE_CLR(g_service_notifier->aulParserUnitMap, ucL7Prot);
	spin_unlock_bh(&g_parserUnit_lock);
	return;
}
EXPORT_SYMBOL(parse_unregister_hook);


//parse pkt proc
VOID SimpleIdentProc(struct sk_buff *skb, PktInfo *pstPktInfo, ULONG *aulServiceMap)
{
	struct ethhdr *ethh;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;

	//L2 ident proc
	pstPktInfo->stL2Info.usL3Prot = skb->protocol;
	pstPktInfo->stL2Info.pcIfname = skb->dev->name;
	ethh = (struct ethhdr *)skb_mac_header(skb);
	pstPktInfo->stL2Info.pucSrcMac = ethh->h_source;

	//L3 ident proc
	iph = (struct iphdr *)skb_network_header(skb);
	pstPktInfo->stL3Info.uiSrcIp = ntohl(iph->saddr);
	pstPktInfo->stL3Info.uiDstIp = ntohl(iph->daddr);
	pstPktInfo->stL3Info.ucL4Prot = iph->protocol;
	pstPktInfo->stL3Info.ucTTL = iph->ttl;
	pstPktInfo->stL3Info.usPktLen = ntohs(iph->tot_len);

	//L4 ident proc
	if(IPPROTO_TCP == pstPktInfo->stL3Info.ucL4Prot)
	{
		tcph = (struct tcphdr *)((char*)iph + iph->ihl * 4);
		pstPktInfo->stL4Info.usSrcPort = ntohs(tcph->source);
		pstPktInfo->stL4Info.usDstPort = ntohs(tcph->dest);
		pstPktInfo->stL4Info.usL7PktLen = skb->len - iph->ihl * 4 - tcph->doff * 4;
		pstPktInfo->stL4Info.pcL7Data = (char*)tcph + tcph->doff * 4;
	}
	else if(IPPROTO_UDP == pstPktInfo->stL3Info.ucL4Prot)
	{
		udph = (struct udphdr *)((char*)iph + iph->ihl * 4);
		pstPktInfo->stL4Info.usSrcPort = ntohs(udph->source);
		pstPktInfo->stL4Info.usDstPort = ntohs(udph->dest);
		pstPktInfo->stL4Info.usL7PktLen = skb->len - iph->ihl * 4 - sizeof(struct udphdr);
		pstPktInfo->stL4Info.pcL7Data = (char*)udph + sizeof(struct udphdr);
	}
	return;
}


VOID pktParseByRfc(struct sk_buff *skb, PktInfo *pstPktInfo, RfcParser *pstParser)
{
	CHAR *pcStart;
	CHAR *pcCur = pstPktInfo->stL4Info.pcL7Data;
	CHAR *pcEnd = pstPktInfo->stL4Info.pcL7Data + pstPktInfo->stL4Info.usL7PktLen;
	USHORT usKeyLen;
	RfcKeyInfo *pstNew;

	//only parse key info by pattern for [key: value]\r\n
	while(!strncmp(pcCur, pstParser->pcKeyValue, pstParser->ucKeyLen))
	{
		pcCur++;
		if(pcCur > pcEnd - 4)
			return;
	}
	pcCur += pstParser->ucKeyLen;
	pcStart = pcCur;

	while(!strncmp(pcCur, "\r\n", 2))
	{
		pcCur++;
		if(pcCur > pcEnd - 4)
			return;
	}
	usKeyLen = pcCur - pcStart + 1;

	//the length of value is too long
	if(usKeyLen >= RFC_KEY_MAXLEN)
	{
		printk(KERN_EMERG"[pktParseByRfc] exception pkt len = %d\n", usKeyLen);
		return;
	}

	//save in RfcKeyInfo(remember release it later)
	pstNew = (RfcKeyInfo *)kmalloc(sizeof(RfcKeyInfo), GFP_KERNEL);
	if(NULL == pstNew)
		return;
	pstNew->pcKey = pcStart;
	pstNew->usKeyLen = usKeyLen;
	pstNew->ucAllocId = pstParser->ucAllocId;
	pstNew->pstNext = pstPktInfo->stL7Info.pstRfcKeyInfoList;
	pstPktInfo->stL7Info.pstRfcKeyInfoList = pstNew;
	
	return;
}

VOID L7IdentProc(struct sk_buff *skb, PktInfo *pstPktInfo, ULONG *aulServiceMap)
{
#if 1
	ParseUnit *pstTmp;
	RfcKeyInfo *pstNew;
	USHORT usCntForExp = 0;

	pstPktInfo->stL7Info.ucL7Prot = UNKNOWN_PROTOCOL;
	list_for_each_entry(pstTmp, &g_parserUnit_list_head, pstlist)
	{
		//for exception
		LOOP_EXCEPTION(usCntForExp, MAX_PARSERUNIT_NUM, __func__)
		
		if(true == pstTmp->pfProtoComfirmFunc(skb, pstPktInfo->stL4Info.usDstPort, pstPktInfo->stL3Info.ucL4Prot))
		{
			pstPktInfo->stL7Info.ucL7Prot = pstTmp->ucL7Prot;

			pstNew = pstTmp->pfProtoParseFunc(pstPktInfo->stL4Info.pcL7Data, pstPktInfo->stL4Info.usL7PktLen, aulServiceMap);
			pstPktInfo->stL7Info.pstRfcKeyInfoList = pstNew;
			return;
		}	
	}
#else
	//only support identity L7prot by well-known port while L7IdentProc
	if(53 == pstPktInfo->stL4Info.usDstPort && IPPROTO_UDP == pstPktInfo->stL3Info.ucL4Prot)
		pstPktInfo->stL7Info.ucL7Prot = DNS_PROTOCOL;
	else if((80 == pstPktInfo->stL4Info.usDstPort || 8080 == pstPktInfo->stL4Info.usDstPort) && IPPROTO_TCP == pstPktInfo->stL3Info.ucL4Prot)
		pstPktInfo->stL7Info.ucL7Prot = HTTP_PROTOCOL;
	else 
		pstPktInfo->stL7Info.ucL7Prot = UNKNOWN_PROTOCOL;

	//parse by rfc
	if(UNKNOWN_PROTOCOL != pstPktInfo->stL7Info.ucL7Prot)
	{
		spin_lock_bh(&g_rfcParser_lock);
		list_for_each_entry(pstTmpParser, &g_rfcParser_list_head, pstlist)
		{
			//for exception
			LOOP_EXCEPTION(usCntForExp, MAX_RFC_PARSERS_NUM, __func__)
			
			if(!SERVICE_GET(aulServiceMap, pstTmpParser->ucServiceId))
				continue;
			if(pstPktInfo->stL7Info.ucL7Prot != pstTmpParser->ucL7Prot)
				continue;
			if(0 == pstTmpParser->ucKeyLen || NULL == pstTmpParser->pcKeyValue)
				continue;
			
			//optimize in the future using KMP
			pktParseByRfc(skb, pstPktInfo, pstTmpParser);
		}
		spin_unlock_bh(&g_rfcParser_lock);
	}
#endif
	return;
}

CHAR *strstrByFeature(const char *s1, size_t len1, const char *s2, size_t len2)
{
	while (len1 >= len2) {
		len1--;
		if (!memcmp(s1, s2, len2))
			return (char *)s1;
		s1++;
	}
	return NULL;
}

VOID L7ParseProc(struct sk_buff *skb, PktInfo *pstPktInfo, ULONG *aulServiceMap)
{
	FeatureParser	*pstTmp;
	USHORT	usScanlen;
	USHORT usCntForExp = 0;
	
	//parse by featurecode
	spin_lock_bh(&g_featureParser_lock);
	list_for_each_entry(pstTmp, &g_featureParser_list_head, pstlist)
	{
		//for exception
		LOOP_EXCEPTION(usCntForExp, MAX_FEATURE_PARSERS_NUM, __func__)
			
		if(!SERVICE_GET(aulServiceMap, pstTmp->ucServiceId))
			continue;
		if(0 == pstTmp->ucFeatureLen || NULL == pstTmp->pcFeatureValue)
			continue;
		if(pstPktInfo->stL4Info.usL7PktLen <= pstTmp->usStartPos)
			continue;

		if(pstPktInfo->stL4Info.usL7PktLen - pstTmp->usStartPos > pstTmp->usScanLen)
			usScanlen = pstTmp->usScanLen;
		else
			usScanlen = pstPktInfo->stL4Info.usL7PktLen - pstTmp->usStartPos;

		//optimize in the future using KMP
		if(strstrByFeature(pstPktInfo->stL4Info.pcL7Data + pstTmp->usStartPos,
			usScanlen,
			pstTmp->pcFeatureValue,
			pstTmp->ucFeatureLen))
		{
			pstPktInfo->stL7Info.usAppId = pstTmp->usAllocAppId;
			return;
		}
	}
	spin_unlock_bh(&g_featureParser_lock);

	return;
}

ParseCallBack g_ParseTab[BUTT_PARSE_STATE] = {
	{SIMPLE_IDENT_STATE, SimpleIdentProc},
	{L7_IDENT_STATE, L7IdentProc},
	{L7_PARSE_STATE, L7ParseProc},
	//{BUTT_PARSE_STATE, NULL},
};

BOOL matchResultJudge(struct tagObserveBase *observer, struct tagSubjectBase *subject)
{
	ServiceSubscriber *observerImpl = (ServiceSubscriber *)observer;
	ParseNotifier *subjectImpl = (ParseNotifier *)subject;

	if(observerImpl->eMatchResult > subjectImpl->stPktInfo.eMatchResult)
		subjectImpl->stPktInfo.eMatchResult = observerImpl->eMatchResult;
	if(MATCH_SUCC == observerImpl->eMatchResult || MATCH_FAIL == observerImpl->eMatchResult)
		SERVICE_CLR(subjectImpl->aulCurServices, observerImpl->ucServiceId);
	
	return false;
}

BOOL serviceResultJudge(struct tagObserveBase *observer, struct tagSubjectBase *subject)
{
	ServiceSubscriber *observerImpl = (ServiceSubscriber *)observer;
	ParseNotifier *subjectImpl = (ParseNotifier *)subject;

	if(1 == observerImpl->ucModPkt)
	{
		subjectImpl->stPktInfo.ePktAct = observerImpl->ePktAct;
		return true;
	}
		
	if(observerImpl->ePktAct > subjectImpl->stPktInfo.ePktAct)
		subjectImpl->stPktInfo.ePktAct = observerImpl->ePktAct;
	
	return false;
}

VOID parserEngineerGC(VOID)
{
	RfcKeyInfo	*pstTmp;

	while(NULL != g_service_notifier->stPktInfo.stL7Info.pstRfcKeyInfoList)
	{
		pstTmp = g_service_notifier->stPktInfo.stL7Info.pstRfcKeyInfoList;
		g_service_notifier->stPktInfo.stL7Info.pstRfcKeyInfoList = pstTmp->pstNext;
		kfree(pstTmp);
	}
		
	return;
}

unsigned int parser_engineer_process(const struct nf_hook_ops *ops,
			       struct sk_buff *skb,
			       const struct nf_hook_state *state)
{
	UINT iCnt;
	UINT iResult = NF_ACCEPT;
	
	//no service register
	if(0 == IDALLOCER_ALLOCED(g_service_notifier->serviceAllocer))
		return NF_ACCEPT;

	spin_lock_bh(&g_service_lock);
	memcpy((VOID *)g_service_notifier->aulCurServices, (const VOID *)g_service_notifier->aulServiceMap, sizeof(ULONG) * (MAX_SERVICE_ID/32 + 1));
	memset(&(g_service_notifier->stPktInfo), 0, sizeof(PktInfo));
	for(iCnt = SIMPLE_IDENT_STATE; iCnt < BUTT_PARSE_STATE; iCnt++)
	{
		if(NULL != g_ParseTab[iCnt].pfParseFunc)
			g_ParseTab[iCnt].pfParseFunc(skb, &(g_service_notifier->stPktInfo), (ULONG *)g_service_notifier->aulCurServices);
		
		NOTIFY((SubjectBase *)g_service_notifier, (UCHAR)(g_ParseTab[iCnt].eParseState), matchResultJudge);
	}

	if(MATCH_SUCC == g_service_notifier->stPktInfo.eMatchResult)
	{
		printk(KERN_DEBUG"[parser_engineer_process] match succ \n");
		NOTIFY((SubjectBase *)g_service_notifier, PARSEPROC_FINISH, serviceResultJudge);
		if(ACT_PASS == g_service_notifier->stPktInfo.ePktAct)
		{
			printk(KERN_DEBUG"[parser_engineer_process] get pass action \n");
			iResult = NF_ACCEPT;
		}
		else if(ACT_DROP == g_service_notifier->stPktInfo.ePktAct)
		{
			printk(KERN_DEBUG"[parser_engineer_process] get drop action \n");
			iResult = NF_DROP;
		}
	}
	else
	{
		printk(KERN_DEBUG"[parser_engineer_process] match fail or not match \n");
		NOTIFY((SubjectBase *)g_service_notifier, SERVICEPROC_FINISH, NULL);
	}

	parserEngineerGC();
	spin_unlock_bh(&g_service_lock);
	return iResult;
}

static struct nf_hook_ops parser_engineer_ops[] __read_mostly = {   
	{     
		.hook =     parser_engineer_process,        
		.owner =  THIS_MODULE,
		.pf =       PF_INET,
		.hooknum =  NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_NAT_DST + 10,    
	},
};

INT serviceNotifierInit(VOID)
{
	g_service_notifier = (ParseNotifier *)SubjectConstruct(sizeof(ParseNotifier), MAX_SERVICE_ID);
	if(!g_service_notifier)
		return (-1);

	IDALLOCER_INIT(g_service_notifier->serviceAllocer, MAX_SERVICE_ID)
	return 0;
}

static int  __init parser_engineer_init(void)
{ 
	int err = 0;

	printk(KERN_EMERG"parser_engineer_init start\n");
	spin_lock_init(&g_service_lock);
	spin_lock_init(&g_parserUnit_lock);
	//spin_lock_init(&g_rfcParser_lock);
	spin_lock_init(&g_featureParser_lock);
	IDALLOCER_INIT(g_rfcParser_allocer, MAX_RFC_PARSERS_NUM)
	IDALLOCER_INIT(g_featureParser_allocer, MAX_FEATURE_PARSERS_NUM)

	err = serviceNotifierInit();
	if (err)
	{
		printk(KERN_ALERT"[parser_engineer_init] serviceNotifierInit error %d\n", err);
		return err;
	}
	
	err = nf_register_hooks(parser_engineer_ops, ARRAY_SIZE(parser_engineer_ops));
	if (err) 
	{        
		printk(KERN_ALERT"[parser_engineer_init] nf_register_hooks error %d\n", err);    
	}
    return err;
}

VOID serviceNotifierDeinit(VOID)
{
	ParseUnit *pstTmp;
	USHORT usCntForExp = 0;
	
	list_for_each_entry(pstTmp, &g_parserUnit_list_head, pstlist)
	{
		//for exception
		LOOP_EXCEPTION(usCntForExp, MAX_PARSERUNIT_NUM, __func__)

		list_del(&pstTmp->pstlist);
		kfree((VOID *)pstTmp);
	}
	kfree((VOID *)g_service_notifier);
	return;
}

static void  __exit parser_engineer_exit(void)
{
	serviceNotifierDeinit();
	nf_unregister_hooks(parser_engineer_ops, ARRAY_SIZE(parser_engineer_ops));
}

module_init(parser_engineer_init);
module_exit(parser_engineer_exit);

MODULE_AUTHOR("CIOT");
MODULE_DESCRIPTION("PARSER ENGINEER");
MODULE_LICENSE("GPL");
