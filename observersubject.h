#ifndef __OBSERVERSUBJECT_H__
#define __OBSERVERSUBJECT_H__

#include "base_type_define.h"
#include "exception_proc.h"
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/string.h>


struct tagObserveBase;
struct tagSubjectBase;

//observer
typedef VOID (*MsgRcvProc)(struct tagObserveBase *, struct tagSubjectBase *);

typedef struct tagSubjectMsgItem{
	UCHAR		ucMsgId;
	UCHAR		ucReg;
	UCHAR		aucRsv[2];
	MsgRcvProc	pfMsgRcvProc;
}SubjectMsgItem;

#define SUBJECT_MAX_MSG	16	//yet

#define OBSERVER_INTERFACE \
	UCHAR			ucMsgRegNum; \
	UCHAR			ucRsv; \
	USHORT			usPriv; \
	SubjectMsgItem	subjectMsgRegTab[SUBJECT_MAX_MSG]; \
	BOOL (*pfAddMsgProc)(struct tagObserveBase *, UCHAR, MsgRcvProc); \
	VOID (*pfDelMsgProc)(struct tagObserveBase *, UCHAR); \
	VOID (*pfUpdateProc)(struct tagObserveBase *, struct tagSubjectBase *, UCHAR);

typedef struct tagObserveBase{
	OBSERVER_INTERFACE
}ObserveBase;

#define ADD_MSGPROC(observer, msgId, pfProc)	(observer)->pfAddMsgProc((observer), (msgId), (pfProc))
#define DEL_MSGPROC(observer, msgId)	(observer)->pfDelMsgProc((observer), (msgId))
//#define UPDATE(observer, subject, msgId)	(observer)->pfUpdateProc((observer), (subject), (msgId))


//subject
typedef BOOL (*InterruptProc)(struct tagObserveBase *, struct tagSubjectBase *);


typedef struct tagObserverRegItem{
	ObserveBase		*observer;
	USHORT			usPriority;	//the value higher, the priority higher 
	USHORT			usRsv;
	struct	list_head pstlist;
}ObserverRegItem;

#define SUBJECT_INTERFACE \
	struct list_head observer_list_head; \
	ULONG			ulObserverNum; \
	ULONG			ulPriv; \
	BOOL (*pfAddObserver)(struct tagSubjectBase *, struct tagObserveBase *, USHORT); \
	VOID (*pfDelObserver)(struct tagSubjectBase *, struct tagObserveBase *); \
	VOID (*pfNotify)(struct tagSubjectBase *, UCHAR, InterruptProc); 

typedef struct tagSubjectBase{
	SUBJECT_INTERFACE
}SubjectBase;

#define ADD_OBSERVER(subject, observer, Priority)	(subject)->pfAddObserver((subject), (observer), (Priority))
#define DEL_OBSERVER(subject, observer)	(subject)->pfDelObserver((subject), (observer))
#define NOTIFY(subject, msgId, InterruptProc)	(subject)->pfNotify((subject), (msgId), (InterruptProc))


extern ObserveBase* ObserverConstruct(USHORT ulObserverSize);
extern VOID ObserverDestruct(ObserveBase *observer);
extern SubjectBase* SubjectConstruct(ULONG ulSubjectSize, ULONG ulObserverNum);
extern VOID SubjectDestruct(SubjectBase *subject);

#endif
