#include "observersubject.h"

#if 1
#define OBSERVER_PART
#endif 
//observer
BOOL addMsgProc(struct tagObserveBase *observer, UCHAR ucMsgId, MsgRcvProc pfMsgRcvProc)
{
	UINT	uiCnt;
	if(observer->ucMsgRegNum >= SUBJECT_MAX_MSG)
		return false;
	for(uiCnt = 0; uiCnt < SUBJECT_MAX_MSG; uiCnt++)
	{
		if(0 == observer->subjectMsgRegTab[uiCnt].ucReg)
		{
			observer->subjectMsgRegTab[uiCnt].ucReg = 1;
			observer->subjectMsgRegTab[uiCnt].ucMsgId = (ucMsgId);
			observer->subjectMsgRegTab[uiCnt].pfMsgRcvProc = (pfMsgRcvProc);
			observer->ucMsgRegNum++;
			return true;
		}
	}
	return false;
}

VOID delMsgProc(struct tagObserveBase *observer, UCHAR ucMsgId)
{
	UINT	uiCnt;
	if(0 == observer->ucMsgRegNum)
		return;
	for(uiCnt = 0; uiCnt < SUBJECT_MAX_MSG; uiCnt++)
	{
		if(ucMsgId == observer->subjectMsgRegTab[uiCnt].ucMsgId)
		{
			observer->subjectMsgRegTab[uiCnt].ucReg = 0;
			observer->subjectMsgRegTab[uiCnt].ucMsgId = 0;
			observer->subjectMsgRegTab[uiCnt].pfMsgRcvProc = NULL;
			observer->ucMsgRegNum--;
			return;
		}
	}
	return;
}

VOID updateProc(struct tagObserveBase *observer, struct tagSubjectBase *subject, UCHAR ucMsgId)
{
	UINT	uiCnt;
	if(0 == observer->ucMsgRegNum)
		return;
	
	for(uiCnt = 0; uiCnt < SUBJECT_MAX_MSG; uiCnt++)
	{
		if(ucMsgId == observer->subjectMsgRegTab[uiCnt].ucMsgId
			&& 1 == observer->subjectMsgRegTab[uiCnt].ucReg)
		{
			if(NULL != observer->subjectMsgRegTab[uiCnt].pfMsgRcvProc)
				observer->subjectMsgRegTab[uiCnt].pfMsgRcvProc(observer, subject);
		}
	}
	return;
}

ObserveBase* ObserverConstruct(USHORT ulObserverSize)
{
	ObserveBase *observer = NULL;;

	//check
	if(ulObserverSize < sizeof(ObserveBase))
		return NULL;

	observer = (ObserveBase *)kmalloc(ulObserverSize, GFP_KERNEL);
	if(!observer)
		return NULL;

	memset(observer, 0, ulObserverSize);
	observer->ucMsgRegNum = 0;
	observer->usPriv = ulObserverSize - sizeof(ObserveBase);
	observer->pfAddMsgProc = addMsgProc;
	observer->pfDelMsgProc = delMsgProc;
	observer->pfUpdateProc = updateProc;
	return observer;
}

VOID ObserverDestruct(ObserveBase *observer)
{
	kfree((VOID *)observer);
	return;
}

#if 1
#define SUBJECT_PART
#endif 
//subject
BOOL addObserver(struct tagSubjectBase *subject, struct tagObserveBase *observer, USHORT usPriority)
{
	ObserverRegItem *pstObserverRegItem = NULL;
	ObserverRegItem *pstTmp;
	USHORT usCntForExp = 0;
	BOOL bFind = false;

	pstObserverRegItem = (ObserverRegItem *)kmalloc(sizeof(ObserverRegItem), GFP_KERNEL);
	if (!pstObserverRegItem)
		return false;

	memset((CHAR *)pstObserverRegItem, 0, sizeof(ObserverRegItem));
	pstObserverRegItem->observer = observer;
	pstObserverRegItem->usPriority = usPriority;
	
	list_for_each_entry(pstTmp, &(subject->observer_list_head), pstlist)
	{
		//for exception
		LOOP_EXCEPTION(usCntForExp, subject->ulObserverNum, __func__)

		if(pstTmp->usPriority < pstObserverRegItem->usPriority)
		{
			list_add_tail(&(pstObserverRegItem->pstlist), &(pstTmp->pstlist));
			bFind = true;
			break;
		}
	}

	if(false == bFind)
		list_add_tail(&(pstObserverRegItem->pstlist), &(subject->observer_list_head));
	
	return true;
}

VOID delObserver(struct tagSubjectBase *subject, struct tagObserveBase *observer)
{
	ObserverRegItem *pstTmp;
	USHORT usCntForExp = 0;

	list_for_each_entry(pstTmp, &(subject->observer_list_head), pstlist)
	{
		//for exception
		LOOP_EXCEPTION(usCntForExp, subject->ulObserverNum, __func__)

		if(pstTmp->observer == observer)
		{
			list_del(&pstTmp->pstlist);
			kfree((VOID *)pstTmp);
			break;
		}
	}
	return;
}

VOID notify(struct tagSubjectBase *subject, UCHAR ucMsgId, InterruptProc pfInterruptProc)
{
	ObserverRegItem *pstTmp;
	USHORT usCntForExp = 0;

	list_for_each_entry(pstTmp, &(subject->observer_list_head), pstlist)
	{
		//for exception
		LOOP_EXCEPTION(usCntForExp, subject->ulObserverNum, __func__)

		if(NULL != pstTmp->observer && NULL != pstTmp->observer->pfUpdateProc)
		{
			pstTmp->observer->pfUpdateProc(pstTmp->observer, subject, ucMsgId);

			if(NULL != pfInterruptProc)
			{
				if(true == pfInterruptProc(pstTmp->observer, subject))
					break;
			}
		}
	}
	
	return;
}

SubjectBase* SubjectConstruct(ULONG ulSubjectSize, ULONG ulObserverNum)
{
	SubjectBase* subject = NULL;

	//check
	if(ulSubjectSize < sizeof(SubjectBase) || 0 == ulObserverNum)
		return NULL;

	subject = (SubjectBase *)kmalloc(ulSubjectSize, GFP_KERNEL);
	if(!subject)
		return NULL;

	memset((CHAR *)subject, 0, ulSubjectSize);
	subject->ulObserverNum = ulObserverNum;
	subject->ulPriv = ulSubjectSize - sizeof(SubjectBase);
	subject->pfAddObserver = addObserver;
	subject->pfDelObserver = delObserver;
	subject->pfNotify = notify;
	INIT_LIST_HEAD(&(subject->observer_list_head));
	
	return subject;
}

VOID SubjectDestruct(SubjectBase *subject)
{
	ObserverRegItem *pstTmp;
	USHORT usCntForExp = 0;

	list_for_each_entry(pstTmp, &(subject->observer_list_head), pstlist)
	{
		//for exception
		LOOP_EXCEPTION(usCntForExp, subject->ulObserverNum, __func__)

		list_del(&pstTmp->pstlist);
		kfree((VOID *)pstTmp);
	}
	kfree((VOID *)subject);
	return;
}
