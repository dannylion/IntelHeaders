/**
* MIT License
*
* Copyright (c) 2017 Viral Security Group
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*
* @file		log.h
* @section	Logging facilities for debugging the library and/or seeing what it does
*			during runtime execution.
*/

#ifndef __INTEL_DEBUG_LOG_H__
#define __INTEL_DEBUG_LOG_H__

#include "ntdatatypes.h"

/**
 * Write a message to log using the given format and parameters list.
 * We don't implement the log-write function ourselves so the user can supply
 * his own function that will output the log message to screen/serial/etc...
 * as he sees fit.
 * @param pvContext - context passed to every call of log function, can be NULL
 * @param pszFmt - message format string
 * @param tVaList - parameters list. use __VA_ARG__ macro to get parameters from it
 * @return TRUE on success, else FALSE
 */
typedef
BOOLEAN
(*PFN_LOG_WRITE)(
	IN const PVOID pvContext,
	IN const char * pszFmt,
	IN __VA_LIST__ tVaList
);

// Define a priority for log messages so we can filter out priorities we don't want
// NOTE: When adding your own log priorities, don't use the below values
typedef enum _LOG_PRIORITY
{
	LOG_ERROR = 1 << 0,
	LOG_WARN = 1 << 1,
	LOG_INFO = 1 << 2,
	LOG_DEBUG = 1 << 3,
	LOG_TRACE = 1 << 4,
	LOG_PRIORITY_ALL = UINT32_MAX // See all messages
} LOG_PRIORITY, *PLOG_PRIORITY;

// Define a modules mask for log messages so we can filter out modules we don't want
// NOTE: When adding your own log modules, don't use the below values
typedef enum _LOG_MODULE
{
	LOG_MODULE_PAGING = 1 << 0,
	LOG_MODULE_ALL = UINT32_MAX // See all messages
} LOG_MODULE, *PLOG_MODULE;

typedef struct _LOG_HANDLE
{
	PFN_LOG_WRITE pfnLogWrite;
	PVOID pvContext;
	LOG_PRIORITY ePriorityFilterMask;
	LOG_MODULE eModulesFilterMask;
} LOG_HANDLE, *PLOG_HANDLE;

/**
* Initialize log handle structure
* @param ptLog - log handle structure to initialize
* @param pfnLogWrite - Log write function
* @param pvContext - Context structure to pass to pfnLogWrite function calls
* @param eModulesFilterMask - Only messages from set modules will be printed
* @param ePriorityFilterMask - Only messages with set priorities will be printed
* @return TRUE on success, else FALSE
*/
__forceinline
BOOLEAN
LOG_InitHandle(
	OUT PLOG_HANDLE ptLog,
	IN const PFN_LOG_WRITE pfnLogWrite,
	IN const PVOID pvContext,
	IN const LOG_MODULE eModulesFilterMask,
	IN const LOG_PRIORITY ePriorityFilterMask
)
{
	if (	(NULL == ptLog)
		||	(NULL == pfnLogWrite))
	{
		return FALSE;
	}

	ptLog->pfnLogWrite = pfnLogWrite;
	ptLog->pvContext = pvContext;
	ptLog->eModulesFilterMask = eModulesFilterMask;
	ptLog->ePriorityFilterMask = ePriorityFilterMask;
	return TRUE;
}

// NOTE: It's recommended to use the LOG_WRITE macro and not this function directly
/**
* Write a message to log using the given format and parameters list.
* We don't implement the log-write function ourselves so the user can supply
* his own function that will output the log message to screen/serial/etc...
* as he sees fit.
* @param ptLog - log handle structure
* @param pszFmt - message format string
* @return TRUE on success, else FALSE
*/
__inline
BOOLEAN
LOG_Write(
	IN const PLOG_HANDLE ptLog,
	IN const char * pszFmt,
	...
)
{
	BOOLEAN bSuccess = FALSE;
	__VA_LIST__ tVaList;

	if (	(NULL == ptLog)
		||	(NULL == pszFmt))
	{
		return FALSE;
	}

	__VA_START__(tVaList, pszFmt);
	bSuccess = (*ptLog->pfnLogWrite)(ptLog->pvContext, pszFmt, tVaList);
	__VA_END__(tVaList);
	return bSuccess;
}

// Define __INTEL_HEADERS_DISABLE_LOG__ to remove log writes done with LOG_WRITE
// macro from the code
#ifndef __INTEL_HEADERS_DISABLE_LOG__
/**
* Write a message to log and add a filename+line prefix and a "\r\n" suffix to it
* @param ptLog - log handle structure pointer. MUST NOT BE NULL
* @param eModule - log message originating module
* @param ePriority - log message priority
* @param pszFmt - message format string
*/
#define LOG_WRITE(ptLog, eModule, ePriority, pszFmt, ...) \
	do { \
		if (	(0 == ((ptLog)->ePriorityFilterMask & (ePriority))) \
			||	(0 == ((ptLog)->eModulesFilterMask & (eModule)))) \
		{ \
			break; \
		} \
		\
		(VOID)LOG_Write((ptLog), "%s:%d ", __FILE__, __LINE__); \
		(VOID)LOG_Write((ptLog), (pszFmt), __VA_ARGS__); \
		(VOID)LOG_Write((ptLog), "\r\n"); \
	} while(FALSE);
#else
#define LOG_WRITE(ptLog, pszFmt, ...)
#endif

#endif /* __INTEL_DEBUG_LOG_H__ */
