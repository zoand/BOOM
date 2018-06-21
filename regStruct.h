#ifndef _REG_STRUCT_H
#define _REG_STRUCT_H

#define MAX_ALTITUDE_BUFFER_LENGTH 10


typedef struct _RMCALLBACK_CONTEXT {

	//
	// A bit mask of all transaction notifications types that the RM Callback is 
	// notified of.
	//
	ULONG Notification;

	//
	// The handle to an enlistment
	//
	HANDLE Enlistment;

} RMCALLBACK_CONTEXT, *PRMCALLBACK_CONTEXT;

//
// List of callback modes
//
typedef enum _CALLBACK_MODE {
	CALLBACK_MODE_PRE_NOTIFICATION_BLOCK,
	CALLBACK_MODE_PRE_NOTIFICATION_BYPASS,
	CALLBACK_MODE_POST_NOTIFICATION_OVERRIDE_ERROR,
	CALLBACK_MODE_POST_NOTIFICATION_OVERRIDE_SUCCESS,
	CALLBACK_MODE_TRANSACTION_REPLAY,
	CALLBACK_MODE_TRANSACTION_ENLIST,
	CALLBACK_MODE_MULTIPLE_ALTITUDE_BLOCK_DURING_PRE,
	CALLBACK_MODE_MULTIPLE_ALTITUDE_INTERNAL_INVOCATION,
	CALLBACK_MODE_MULTIPLE_ALTITUDE_MONITOR,
	CALLBACK_MODE_SET_CALL_CONTEXT,
	CALLBACK_MODE_SET_OBJECT_CONTEXT,
	CALLBACK_MODE_CAPTURE,
	CALLBACK_MODE_VERSION_BUGCHECK,
	CALLBACK_MODE_VERSION_CREATE_OPEN_V1,
} CALLBACK_MODE;


typedef struct _CALLBACK_CONTEXT {

	//
	// List of callback contexts currently active
	//
	LIST_ENTRY CallbackCtxList;

	//
	// Specifies which callback helper method to use
	//
	CALLBACK_MODE CallbackMode;

	//
	// Records the current ProcessId to filter out registry operation from
	// other processes.
	//
	HANDLE ProcessId;

	//
	// Records the altitude that the callback was registered at
	//
	UNICODE_STRING Altitude;
	WCHAR AltitudeBuffer[MAX_ALTITUDE_BUFFER_LENGTH];

	//
	// Records the cookie returned by the registry when the callback was 
	// registered
	//
	LARGE_INTEGER Cookie;

	//
	// A pointer to the context for the transaction callback. 
	// Used to enlist on a transaction. Only used in the transaction samples.
	//
	PRMCALLBACK_CONTEXT RMCallbackCtx;

	//
	// These fields record information for verifying the behavior of the
	// certain samples. They are not used in all samples
	//

	//
	// Number of times the RegNtCallbackObjectContextCleanup 
	// notification was received
	//
	LONG ContextCleanupCount;

	//
	// Number of times the callback saw a notification with the call or
	// object context set correctly.
	//
	LONG NotificationWithContextCount;

	//
	// Number of times callback saw a notirication without call or without
	// object context set correctly
	//
	LONG NotificationWithNoContextCount;

	//
	// Number of pre-notifications received
	//
	LONG PreNotificationCount;

	//
	// Number of post-notifications received
	//
	LONG PostNotificationCount;

} CALLBACK_CONTEXT, *PCALLBACK_CONTEXT;


#endif
