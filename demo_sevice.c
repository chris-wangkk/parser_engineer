#include "parser_engineer.h"


ServiceSubscriber *g_demo_service = NULL;

int DemorfcParserAdd(void __user  *buffer)
{
	RfcParserIn	*pstRfcParser;
	const CHAR *pcTmp = "HOST: ";
	
	pstRfcParser = (RfcParserIn *)kmalloc(sizeof(RfcParserIn), GFP_KERNEL);
	if (!pstRfcParser)
		return PARSEPROC_RET_ERR;
	memset(pstRfcParser, 0, sizeof(RfcParserIn));
	pstRfcParser->ucServiceId = g_demo_service->ucServiceId;
	pstRfcParser->ucKeyLen = strlen(pcTmp);
	pstRfcParser->ucL7Prot = HTTP_PROTOCOL;
	memcpy(pstRfcParser->aucKeyValue, pcTmp, pstRfcParser->ucKeyLen);
	pstRfcParser->aucKeyValue[pstRfcParser->ucKeyLen] = '\0';
	
	printk(KERN_EMERG"tmp[DemorfcParserAdd] enter\n");
	if(PARSEPROC_RET_OK != rfcParserAdd(pstRfcParser))
	{
		printk(KERN_EMERG"[DemorfcParserAdd] rfcParserAdd error\n");
		kfree(pstRfcParser);
		return PARSEPROC_RET_ERR;
	}
	kfree(pstRfcParser);
	return PARSEPROC_RET_OK;
}
EXPORT_SYMBOL(DemorfcParserAdd);

int DemorfcParserDel(void __user  *buffer)
{
	UCHAR	ucProtId;
	UCHAR	ucAllocId;
	if (copy_from_user(&ucProtId, buffer,sizeof(UCHAR)))
	{
		printk(KERN_EMERG"[DemorfcParserDel]get_id is error\n");
		return PARSEPROC_RET_ERR;
	}
	ucAllocId = 1;
	printk(KERN_EMERG"tmp[DemorfcParserDel] enter\n");
	rfcParserDel(g_demo_service->ucServiceId, ucProtId, ucAllocId);
	return PARSEPROC_RET_OK;
}
EXPORT_SYMBOL(DemorfcParserDel);

int DemofeatureParserAdd(void __user  *buffer)
{
	FeatureParser	*pstFeatureParser;
	const CHAR *pcTmp = "CDCDCD";
	
	pstFeatureParser = (FeatureParser *)kmalloc(sizeof(FeatureParser), GFP_KERNEL);
	if (!pstFeatureParser)
		return PARSEPROC_RET_ERR;
	memset(pstFeatureParser, 0, sizeof(FeatureParser));
	pstFeatureParser->ucFeatureLen = strlen(pcTmp);
	pstFeatureParser->ucServiceId = g_demo_service->ucServiceId;
	pstFeatureParser->usStartPos = 0;
	pstFeatureParser->usScanLen = 20;

	pstFeatureParser->pcFeatureValue = (CHAR *)kmalloc(pstFeatureParser->ucFeatureLen, GFP_KERNEL);
	if(NULL == pstFeatureParser->pcFeatureValue)
	{
		printk(KERN_EMERG"[DemofeatureParserAdd] kmalloc pcKeyValue error\n");
		kfree(pstFeatureParser);
		return PARSEPROC_RET_ERR;
	}
	memcpy(pstFeatureParser->pcFeatureValue, pcTmp, pstFeatureParser->ucFeatureLen);
	pstFeatureParser->pcFeatureValue[pstFeatureParser->ucFeatureLen] = '\0';
	printk(KERN_EMERG"tmp[DemofeatureParserAdd] enter\n");
	if(PARSEPROC_RET_OK != featureParserAdd(pstFeatureParser))
	{
		printk(KERN_EMERG"[DemofeatureParserAdd] rfcParserAdd error\n");
		kfree(pstFeatureParser->pcFeatureValue);
		kfree(pstFeatureParser);
		return PARSEPROC_RET_ERR;
	}
	
	return PARSEPROC_RET_OK;
}
EXPORT_SYMBOL(DemofeatureParserAdd);

int DemofeatureParserDel(void __user  *buffer)
{
	USHORT	usAppId;
	if (copy_from_user(&usAppId, buffer,sizeof(USHORT)))
	{
		printk(KERN_EMERG"[DemofeatureParserDel]get_id is error\n");
		return PARSEPROC_RET_ERR;
	}
	printk(KERN_EMERG"tmp[DemofeatureParserDel] enter\n");
	if(PARSEPROC_RET_OK != featureParserDel(usAppId))
	{
		printk(KERN_EMERG"[DemofeatureParserDel] featureParserDel error\n");
		return PARSEPROC_RET_ERR;
	}
	
	return PARSEPROC_RET_OK;
}
EXPORT_SYMBOL(DemofeatureParserDel);

VOID SimpleIdentMsgRcvProc(struct tagObserveBase *observer, struct tagSubjectBase *subject)
{
	printk(KERN_ALERT"[SimpleIdentMsgRcvProc] enter \n");
	return;
}
VOID L7IdentMsgRcvProc(struct tagObserveBase *observer, struct tagSubjectBase *subject)
{
	printk(KERN_ALERT"[L7IdentMsgRcvProc] enter \n");
	return;
}
VOID L7ParseMsgRcvProc(struct tagObserveBase *observer, struct tagSubjectBase *subject)
{
	printk(KERN_ALERT"[L7ParseMsgRcvProc] enter \n");
	return;
}
VOID ParseFinishMsgRcvProc(struct tagObserveBase *observer, struct tagSubjectBase *subject)
{
	printk(KERN_ALERT"[ParseFinishMsgRcvProc] enter \n");
	return;
}
VOID ServiceProcMsgRcvProc(struct tagObserveBase *observer, struct tagSubjectBase *subject)
{
	printk(KERN_ALERT"[ServiceProcMsgRcvProc] enter \n");
	return;
}


static int  __init demo_service_init(void)
{
	int err = 0;

	g_demo_service = (ServiceSubscriber *)ObserverConstruct(sizeof(ServiceSubscriber));
	if(!g_demo_service)
		return (-1);

	err = app_register_hook(g_demo_service, (USHORT)1);
	if (err) 
	{        
		printk(KERN_ALERT"[app_register_hook] parse_register_hook error %d\n", err);
		return err;
	}
	(VOID)ADD_MSGPROC((struct tagObserveBase *)g_demo_service, SIMPLE_IDENT_OUTPUT, SimpleIdentMsgRcvProc);
	(VOID)ADD_MSGPROC((struct tagObserveBase *)g_demo_service, L7_IDENT_OUTPUT, L7IdentMsgRcvProc);
	(VOID)ADD_MSGPROC((struct tagObserveBase *)g_demo_service, L7_PARSE_OUTPUT, L7ParseMsgRcvProc);
	(VOID)ADD_MSGPROC((struct tagObserveBase *)g_demo_service, PARSEPROC_FINISH, ParseFinishMsgRcvProc);
	(VOID)ADD_MSGPROC((struct tagObserveBase *)g_demo_service, SERVICEPROC_FINISH, ServiceProcMsgRcvProc);
	return err;
}

static void  __exit demo_service_exit(void)
{
	(VOID)DEL_MSGPROC((struct tagObserveBase *)g_demo_service, SIMPLE_IDENT_OUTPUT);
	(VOID)DEL_MSGPROC((struct tagObserveBase *)g_demo_service, L7_IDENT_OUTPUT);
	(VOID)DEL_MSGPROC((struct tagObserveBase *)g_demo_service, L7_PARSE_OUTPUT);
	(VOID)DEL_MSGPROC((struct tagObserveBase *)g_demo_service, PARSEPROC_FINISH);
	(VOID)DEL_MSGPROC((struct tagObserveBase *)g_demo_service, SERVICEPROC_FINISH);
	app_unregister_hook(g_demo_service);
	ObserverDestruct((ObserveBase *)g_demo_service);
	g_demo_service = NULL;
}


module_init(demo_service_init);
module_exit(demo_service_exit);

MODULE_AUTHOR("CIOT");
MODULE_DESCRIPTION("DEMO SERVICE");
MODULE_LICENSE("GPL");
