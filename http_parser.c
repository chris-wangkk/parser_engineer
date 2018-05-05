#include "parser_unit.h"
#include "parser_engineer.h"

RFC_PARSER_RULE_TEMPLATE(HTTP)


BOOL HTTPProtoComfirmFunc(struct sk_buff *skb, USHORT usDstPort, UCHAR ucL4Prot)
{
	if((80 == usDstPort || 8080 == usDstPort) && IPPROTO_TCP == ucL4Prot)
		return true;
	return false;
}

RfcKeyInfo* HTTPParser(CHAR *pcL7Data, USHORT usL7PktLen, RfcParser	*pstParser)
{
	RfcKeyInfo *pstNew;
	CHAR *pcStart;
	CHAR *pcCur = pcL7Data;
	CHAR *pcEnd = pcL7Data + usL7PktLen;
	USHORT usKeyLen;

	//only parse key info by pattern for [key: value]\r\n
	while(!strncmp(pcCur, pstParser->pcKeyValue, pstParser->ucKeyLen))
	{
		pcCur++;
		if(pcCur > pcEnd - 4)
			return NULL;
	}
	pcCur += pstParser->ucKeyLen;
	pcStart = pcCur;

	while(!strncmp(pcCur, "\r\n", 2))
	{
		pcCur++;
		if(pcCur > pcEnd - 4)
			return NULL;
	}
	usKeyLen = pcCur - pcStart + 1;

	//the length of value is too long
	if(usKeyLen >= RFC_KEY_MAXLEN)
	{
		printk(KERN_EMERG"[HTTPParser] exception pkt len = %d\n", usKeyLen);
		return NULL;
	}

	//save in RfcKeyInfo(remember release it later)
	pstNew = (RfcKeyInfo *)kmalloc(sizeof(RfcKeyInfo), GFP_KERNEL);
	if(NULL == pstNew)
		return NULL;
	pstNew->pcKey = pcStart;
	pstNew->usKeyLen = usKeyLen;
	pstNew->ucAllocId = pstParser->ucAllocId;
	return pstNew;
}


RfcKeyInfo* HTTPProtoParseFunc(CHAR *pcL7Data, USHORT usL7PktLen, ULONG *aulServiceMap)
{
	return PKTPARSE(pcL7Data, usL7PktLen, aulServiceMap, HTTPParser);
}

static int  __init http_parser_init(void)
{
	int err = 0;
	ParseUnit stHttpParseUnit = {0};

	COMMINFOINIT(&stHttpParseUnit);
	stHttpParseUnit.usCapacity = 10;
	stHttpParseUnit.usAlloced = 0;
	stHttpParseUnit.ucL7Prot = HTTP_PROTOCOL;
	stHttpParseUnit.usPriority = 1;
	stHttpParseUnit.pfProtoComfirmFunc = HTTPProtoComfirmFunc;
	stHttpParseUnit.pfProtoParseFunc = HTTPProtoParseFunc;
	
	err = parse_register_hook(&stHttpParseUnit);
	if (err) 
	{        
		printk(KERN_ALERT"[http_parser_init] parse_register_hook error %d\n", err);
		return err;
	}
	return err;
}

static void  __exit http_parser_exit(void)
{
	parse_unregister_hook(HTTP_PROTOCOL);
}



module_init(http_parser_init);
module_exit(http_parser_exit);

MODULE_AUTHOR("CIOT");
MODULE_DESCRIPTION("HTTP PARSER");
MODULE_LICENSE("GPL");

