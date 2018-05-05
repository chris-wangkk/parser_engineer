#ifndef __EXCEPTION_PROC_H__
#define __EXCEPTION_PROC_H__

#define LOOP_EXCEPTION(cntForExp, maxValue, funcname) \
	if((cntForExp) >= (maxValue) * 2) \
		{ \
			printk(KERN_EMERG"[%s] exception occur cnt = %d\n", (funcname), (cntForExp)); \
			break; \
		} \
		(cntForExp)++;

#endif
