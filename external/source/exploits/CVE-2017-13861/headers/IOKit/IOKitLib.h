/*
 * Copyright (c) 1998-2014 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * HISTORY
 *
 */

/*
 * IOKit user library
 */

#ifndef _IOKIT_IOKITLIB_H
#define _IOKIT_IOKITLIB_H

#ifdef KERNEL
#error This file is not for kernel use
#endif

#include <sys/cdefs.h>
#include <sys/types.h>

#include <mach/mach_types.h>
#include <mach/mach_init.h>

#include <CoreFoundation/CFBase.h>
#include <CoreFoundation/CFDictionary.h>
#include <CoreFoundation/CFRunLoop.h>

#include <IOKit/IOTypes.h>
#include <IOKit/IOKitKeys.h>

#include <IOKit/OSMessageNotification.h>

#include <AvailabilityMacros.h>

#include <dispatch/dispatch.h>

__BEGIN_DECLS

/*! @header IOKitLib
IOKitLib implements non-kernel task access to common IOKit object types - IORegistryEntry, IOService, IOIterator etc. These functions are generic - families may provide API that is more specific.<br>
IOKitLib represents IOKit objects outside the kernel with the types io_object_t, io_registry_entry_t, io_service_t, & io_connect_t. Function names usually begin with the type of object they are compatible with - eg. IOObjectRelease can be used with any io_object_t. Inside the kernel, the c++ class hierarchy allows the subclasses of each object type to receive the same requests from user level clients, for example in the kernel, IOService is a subclass of IORegistryEntry, which means any of the IORegistryEntryXXX functions in IOKitLib may be used with io_service_t's as well as io_registry_t's. There are functions available to introspect the class of the kernel object which any io_object_t et al. represents.
IOKit objects returned by all functions should be released with IOObjectRelease.
*/
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

typedef struct IONotificationPort * IONotificationPortRef;


/*! @typedef IOServiceMatchingCallback
    @abstract Callback function to be notified of IOService publication.
    @param refcon The refcon passed when the notification was installed.
    @param iterator The notification iterator which now has new objects.
*/
typedef void
(*IOServiceMatchingCallback)(
	void *			refcon,
	io_iterator_t		iterator );

/*! @typedef IOServiceInterestCallback
    @abstract Callback function to be notified of changes in state of an IOService.
    @param refcon The refcon passed when the notification was installed.
    @param service The IOService whose state has changed.
    @param messageType A messageType enum, defined by IOKit/IOMessage.h or by the IOService's family.
    @param messageArgument An argument for the message, dependent on the messageType.  If the message data is larger than sizeof(void*), then messageArgument contains a pointer to the message data; otherwise, messageArgument contains the message data.
*/

typedef void
(*IOServiceInterestCallback)(
	void *			refcon,
	io_service_t		service,
	uint32_t		messageType,
	void *			messageArgument );

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*! @const kIOMasterPortDefault
    @abstract The default mach port used to initiate communication with IOKit.
    @discussion When specifying a master port to IOKit functions, the NULL argument indicates "use the default". This is a synonym for NULL, if you'd rather use a named constant.
*/

extern
const mach_port_t kIOMasterPortDefault;

/*! @function IOMasterPort
    @abstract Returns the mach port used to initiate communication with IOKit.
    @discussion Functions that don't specify an existing object require the IOKit master port to be passed. This function obtains that port.
    @param bootstrapPort Pass MACH_PORT_NULL for the default.
    @param masterPort The master port is returned.
    @result A kern_return_t error code. */

kern_return_t
IOMasterPort( mach_port_t	bootstrapPort,
	      mach_port_t *	masterPort );


/*! @function IONotificationPortCreate
    @abstract Creates and returns a notification object for receiving IOKit notifications of new devices or state changes.
    @discussion Creates the notification object to receive notifications from IOKit of new device arrivals or state changes. The notification object can be supply a CFRunLoopSource, or mach_port_t to be used to listen for events.
    @param masterPort The master port obtained from IOMasterPort(). Pass kIOMasterPortDefault to look up the default master port.
    @result A reference to the notification object. */

IONotificationPortRef
IONotificationPortCreate(
	mach_port_t		masterPort );

/*! @function IONotificationPortDestroy
    @abstract Destroys a notification object created with IONotificationPortCreate.
                Also destroys any mach_port's or CFRunLoopSources obatined from 
                <code>@link IONotificationPortGetRunLoopSource @/link</code>
                or <code>@link IONotificationPortGetMachPort @/link</code>
    @param notify A reference to the notification object. */

void
IONotificationPortDestroy(
	IONotificationPortRef	notify );

/*! @function IONotificationPortGetRunLoopSource
    @abstract Returns a CFRunLoopSource to be used to listen for notifications.
    @discussion A notification object may deliver notifications to a CFRunLoop 
                by adding the run loop source returned by this function to the run loop.

                The caller should not release this CFRunLoopSource. Just call 
                <code>@link IONotificationPortDestroy @/link</code> to dispose of the
                IONotificationPortRef and the CFRunLoopSource when done.
    @param notify The notification object.
    @result A CFRunLoopSourceRef for the notification object. */

CFRunLoopSourceRef
IONotificationPortGetRunLoopSource(
	IONotificationPortRef	notify );

/*! @function IONotificationPortGetMachPort
    @abstract Returns a mach_port to be used to listen for notifications.
    @discussion A notification object may deliver notifications to a mach messaging client 
                if they listen for messages on the port obtained from this function. 
                Callbacks associated with the notifications may be delivered by calling 
                IODispatchCalloutFromMessage with messages received.
                
                The caller should not release this mach_port_t. Just call 
                <code>@link IONotificationPortDestroy @/link</code> to dispose of the
                mach_port_t and IONotificationPortRef when done.
    @param notify The notification object.
    @result A mach_port for the notification object. */

mach_port_t
IONotificationPortGetMachPort(
	IONotificationPortRef	notify );

/*! @function IONotificationPortSetDispatchQueue
    @abstract Sets a dispatch queue to be used to listen for notifications.
    @discussion A notification object may deliver notifications to a dispatch client.
    @param notify The notification object.
    @param queue A dispatch queue. */

void
IONotificationPortSetDispatchQueue(
	IONotificationPortRef notify, dispatch_queue_t queue )
__OSX_AVAILABLE_STARTING(__MAC_10_6, __IPHONE_4_3);

/*! @function IODispatchCalloutFromMessage
    @abstract Dispatches callback notifications from a mach message.
    @discussion A notification object may deliver notifications to a mach messaging client, 
                which should call this function to generate the callbacks associated with the notifications arriving on the port.
    @param unused Not used, set to zero.
    @param msg A pointer to the message received.
    @param reference Pass the IONotificationPortRef for the object. */

void
IODispatchCalloutFromMessage(
        void 			*unused,
        mach_msg_header_t	*msg,
        void			*reference );

/*! @function IOCreateReceivePort
    @abstract Creates and returns a mach port suitable for receiving IOKit messages of the specified type.
    @discussion In the future IOKit may use specialized messages and ports
    instead of the standard ports created by mach_port_allocate(). Use this
    function instead of mach_port_allocate() to ensure compatibility with future
    revisions of IOKit.
    @param msgType Type of message to be sent to this port
    (kOSNotificationMessageID or kOSAsyncCompleteMessageID)
    @param recvPort The created port is returned.
    @result A kern_return_t error code. */

kern_return_t
IOCreateReceivePort( uint32_t msgType, mach_port_t * recvPort );

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*
 * IOObject
 */

/*! @function IOObjectRelease
    @abstract Releases an object handle previously returned by IOKitLib.
    @discussion All objects returned by IOKitLib should be released with this function when access to them is no longer needed. Using the object after it has been released may or may not return an error, depending on how many references the task has to the same object in the kernel.
    @param object The IOKit object to release.
    @result A kern_return_t error code. */

kern_return_t
IOObjectRelease(
	io_object_t	object );

/*! @function IOObjectRetain
    @abstract Retains an object handle previously returned by IOKitLib.
    @discussion Gives the caller an additional reference to an existing object handle previously returned by IOKitLib.
    @param object The IOKit object to retain.
    @result A kern_return_t error code. */

kern_return_t
IOObjectRetain(
	io_object_t	object );

/*! @function IOObjectGetClass
    @abstract Return the class name of an IOKit object.
    @discussion This function uses the OSMetaClass system in the kernel to derive the name of the class the object is an instance of.
    @param object The IOKit object.
    @param className Caller allocated buffer to receive the name string.
    @result A kern_return_t error code. */

kern_return_t
IOObjectGetClass(
	io_object_t	object,
	io_name_t	className );
	
/*! @function IOObjectCopyClass
    @abstract Return the class name of an IOKit object.
	@discussion This function does the same thing as IOObjectGetClass, but returns the result as a CFStringRef.
	@param object The IOKit object.
	@result The resulting CFStringRef. This should be released by the caller. If a valid object is not passed in, then NULL is returned.*/
	
CFStringRef 
IOObjectCopyClass(io_object_t object)
AVAILABLE_MAC_OS_X_VERSION_10_4_AND_LATER;

/*! @function IOObjectCopySuperclassForClass
    @abstract Return the superclass name of the given class.
    @discussion This function uses the OSMetaClass system in the kernel to derive the name of the superclass of the class.
	@param classname The name of the class as a CFString.
	@result The resulting CFStringRef. This should be released by the caller. If there is no superclass, or a valid class name is not passed in, then NULL is returned.*/

CFStringRef 
IOObjectCopySuperclassForClass(CFStringRef classname)
AVAILABLE_MAC_OS_X_VERSION_10_4_AND_LATER;

/*! @function IOObjectCopyBundleIdentifierForClass
    @abstract Return the bundle identifier of the given class.
	@discussion This function uses the OSMetaClass system in the kernel to derive the name of the kmod, which is the same as the bundle identifier.
	@param classname The name of the class as a CFString.
	@result The resulting CFStringRef. This should be released by the caller. If a valid class name is not passed in, then NULL is returned.*/

CFStringRef 
IOObjectCopyBundleIdentifierForClass(CFStringRef classname)
AVAILABLE_MAC_OS_X_VERSION_10_4_AND_LATER;

/*! @function IOObjectConformsTo
    @abstract Performs an OSDynamicCast operation on an IOKit object.
    @discussion This function uses the OSMetaClass system in the kernel to determine if the object will dynamic cast to a class, specified as a C-string. In other words, if the object is of that class or a subclass.
    @param object An IOKit object.
    @param className The name of the class, as a C-string.
    @result If the object handle is valid, and represents an object in the kernel that dynamic casts to the class true is returned, otherwise false. */

boolean_t
IOObjectConformsTo(
	io_object_t	object,
	const io_name_t	className );

/*! @function IOObjectIsEqualTo
    @abstract Checks two object handles to see if they represent the same kernel object.
    @discussion If two object handles are returned by IOKitLib functions, this function will compare them to see if they represent the same kernel object.
    @param object An IOKit object.
    @param anObject Another IOKit object.
    @result If both object handles are valid, and represent the same object in the kernel true is returned, otherwise false. */

boolean_t
IOObjectIsEqualTo(
	io_object_t	object,
	io_object_t	anObject );

/*! @function IOObjectGetKernelRetainCount
    @abstract Returns kernel retain count of an IOKit object.
    @discussion This function may be used in diagnostics to determine the current retain count of the kernel object at the kernel level.
    @param object An IOKit object.
    @result If the object handle is valid, the kernel objects retain count is returned, otherwise zero is returned. */

uint32_t
IOObjectGetKernelRetainCount(
	io_object_t	object )
AVAILABLE_MAC_OS_X_VERSION_10_6_AND_LATER;

/*! @function IOObjectGetUserRetainCount
    @abstract Returns the retain count for the current process of an IOKit object.
    @discussion This function may be used in diagnostics to determine the current retain count for the calling process of the kernel object.
    @param object An IOKit object.
    @result If the object handle is valid, the objects user retain count is returned, otherwise zero is returned. */

uint32_t
IOObjectGetUserRetainCount(
	io_object_t	object )
AVAILABLE_MAC_OS_X_VERSION_10_6_AND_LATER;

/*! @function IOObjectGetRetainCount
    @abstract Returns kernel retain count of an IOKit object. Identical to IOObjectGetKernelRetainCount() but available prior to Mac OS 10.6.
    @discussion This function may be used in diagnostics to determine the current retain count of the kernel object at the kernel level.
    @param object An IOKit object.
    @result If the object handle is valid, the kernel objects retain count is returned, otherwise zero is returned. */

uint32_t
IOObjectGetRetainCount(
	io_object_t	object );


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*
 * IOIterator, subclass of IOObject
 */

/*! @function IOIteratorNext
    @abstract Returns the next object in an iteration.
    @discussion This function returns the next object in an iteration, or zero if no more remain or the iterator is invalid.
    @param iterator An IOKit iterator handle.
    @result If the iterator handle is valid, the next element in the iteration is returned, otherwise zero is returned. The element should be released by the caller when it is finished. */

io_object_t
IOIteratorNext(
	io_iterator_t	iterator );

/*! @function IOIteratorReset
    @abstract Resets an iteration back to the beginning.
    @discussion If an iterator is invalid, or if the caller wants to start over, IOIteratorReset will set the iteration back to the beginning.
    @param iterator An IOKit iterator handle. */

void
IOIteratorReset(
	io_iterator_t	iterator );

/*! @function IOIteratorIsValid
    @abstract Checks an iterator is still valid.
    @discussion Some iterators will be made invalid if changes are made to the structure they are iterating over. This function checks the iterator is still valid and should be called when IOIteratorNext returns zero. An invalid iterator can be reset and the iteration restarted.
    @param iterator An IOKit iterator handle.
    @result True if the iterator handle is valid, otherwise false is returned. */

boolean_t
IOIteratorIsValid(
	io_iterator_t	iterator );

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*
 * IOService, subclass of IORegistryEntry
 */

/*!
    @function IOServiceGetMatchingService
    @abstract Look up a registered IOService object that matches a matching dictionary.
    @discussion This is the preferred method of finding IOService objects currently registered by IOKit (that is, objects that have had their registerService() methods invoked). To find IOService objects that aren't yet registered, use an iterator as created by IORegistryEntryCreateIterator(). IOServiceAddMatchingNotification can also supply this information and install a notification of new IOServices. The matching information used in the matching dictionary may vary depending on the class of service being looked up.
    @param masterPort The master port obtained from IOMasterPort(). Pass kIOMasterPortDefault to look up the default master port.
    @param matching A CF dictionary containing matching information, of which one reference is always consumed by this function (Note prior to the Tiger release there was a small chance that the dictionary might not be released if there was an error attempting to serialize the dictionary). IOKitLib can construct matching dictionaries for common criteria with helper functions such as IOServiceMatching, IOServiceNameMatching, IOBSDNameMatching.
    @result The first service matched is returned on success. The service must be released by the caller.
  */

io_service_t
IOServiceGetMatchingService(
	mach_port_t	masterPort,
	CFDictionaryRef	matching CF_RELEASES_ARGUMENT);

/*! @function IOServiceGetMatchingServices
    @abstract Look up registered IOService objects that match a matching dictionary.
    @discussion This is the preferred method of finding IOService objects currently registered by IOKit (that is, objects that have had their registerService() methods invoked). To find IOService objects that aren't yet registered, use an iterator as created by IORegistryEntryCreateIterator(). IOServiceAddMatchingNotification can also supply this information and install a notification of new IOServices. The matching information used in the matching dictionary may vary depending on the class of service being looked up.
    @param masterPort The master port obtained from IOMasterPort(). Pass kIOMasterPortDefault to look up the default master port.
    @param matching A CF dictionary containing matching information, of which one reference is always consumed by this function (Note prior to the Tiger release there was a small chance that the dictionary might not be released if there was an error attempting to serialize the dictionary). IOKitLib can construct matching dictionaries for common criteria with helper functions such as IOServiceMatching, IOServiceNameMatching, IOBSDNameMatching.
    @param existing An iterator handle is returned on success, and should be released by the caller when the iteration is finished.
    @result A kern_return_t error code. */

kern_return_t
IOServiceGetMatchingServices(
	mach_port_t	masterPort,
	CFDictionaryRef	matching CF_RELEASES_ARGUMENT,
	io_iterator_t * existing );


kern_return_t
IOServiceAddNotification(
	mach_port_t	masterPort,
	const io_name_t	notificationType,
	CFDictionaryRef	matching,
	mach_port_t	wakePort,
	uintptr_t	reference,
	io_iterator_t *	notification )  DEPRECATED_ATTRIBUTE;

/*! @function IOServiceAddMatchingNotification
    @abstract Look up registered IOService objects that match a matching dictionary, and install a notification request of new IOServices that match.
    @discussion This is the preferred method of finding IOService objects that may arrive at any time. The type of notification specifies the state change the caller is interested in, on IOService's that match the match dictionary. Notification types are identified by name, and are defined in IOKitKeys.h. The matching information used in the matching dictionary may vary depending on the class of service being looked up.
    @param notifyPort A IONotificationPortRef object that controls how messages will be sent when the armed notification is fired. When the notification is delivered, the io_iterator_t representing the notification should be iterated through to pick up all outstanding objects. When the iteration is finished the notification is rearmed. See IONotificationPortCreate.
    @param notificationType A notification type from IOKitKeys.h
<br>	kIOPublishNotification Delivered when an IOService is registered.
<br>	kIOFirstPublishNotification Delivered when an IOService is registered, but only once per IOService instance. Some IOService's may be reregistered when their state is changed.
<br>	kIOMatchedNotification Delivered when an IOService has had all matching drivers in the kernel probed and started.
<br>	kIOFirstMatchNotification Delivered when an IOService has had all matching drivers in the kernel probed and started, but only once per IOService instance. Some IOService's may be reregistered when their state is changed.
<br>	kIOTerminatedNotification Delivered after an IOService has been terminated.
    @param matching A CF dictionary containing matching information, of which one reference is always consumed by this function (Note prior to the Tiger release there was a small chance that the dictionary might not be released if there was an error attempting to serialize the dictionary). IOKitLib can construct matching dictionaries for common criteria with helper functions such as IOServiceMatching, IOServiceNameMatching, IOBSDNameMatching.
    @param callback A callback function called when the notification fires.
    @param refCon A reference constant for the callbacks use.
    @param notification An iterator handle is returned on success, and should be released by the caller when the notification is to be destroyed. The notification is armed when the iterator is emptied by calls to IOIteratorNext - when no more objects are returned, the notification is armed. Note the notification is not armed when first created.
    @result A kern_return_t error code. */

kern_return_t
IOServiceAddMatchingNotification(
	IONotificationPortRef	notifyPort,
	const io_name_t		notificationType,
	CFDictionaryRef		matching CF_RELEASES_ARGUMENT,
        IOServiceMatchingCallback callback,
        void *			refCon,
	io_iterator_t * 	notification );

/*! @function IOServiceAddInterestNotification
    @abstract Register for notification of state changes in an IOService.
    @discussion IOService objects deliver notifications of their state changes to their clients via the IOService::messageClients API, and to other interested parties including callers of this function. Message types are defined IOKit/IOMessage.h.
    @param notifyPort A IONotificationPortRef object that controls how messages will be sent when the notification is fired. See IONotificationPortCreate.
    @param interestType A notification type from IOKitKeys.h
<br>	kIOGeneralInterest General state changes delivered via the IOService::messageClients API.
<br>	kIOBusyInterest Delivered when the IOService changes its busy state to or from zero. The message argument contains the new busy state causing the notification.
    @param callback A callback function called when the notification fires, with messageType and messageArgument for the state change.
    @param refCon A reference constant for the callbacks use.
    @param notification An object handle is returned on success, and should be released by the caller when the notification is to be destroyed.
    @result A kern_return_t error code. */

kern_return_t
IOServiceAddInterestNotification(
	IONotificationPortRef	notifyPort,
        io_service_t		service,
	const io_name_t 	interestType,
        IOServiceInterestCallback callback,
        void *			refCon,
        io_object_t *		notification );

/*! @function IOServiceMatchPropertyTable
    @abstract Match an IOService objects with matching dictionary.
    @discussion This function calls the matching method of an IOService object and returns the boolean result.
    @param service The IOService object to match.
    @param matching A CF dictionary containing matching information. IOKitLib can construct matching dictionaries for common criteria with helper functions such as IOServiceMatching, IOServiceNameMatching, IOBSDNameMatching.
    @param matches The boolean result is returned.
    @result A kern_return_t error code. */

kern_return_t
IOServiceMatchPropertyTable(
        io_service_t	service,
        CFDictionaryRef matching,
        boolean_t *	matches );

/*! @function IOServiceGetBusyState
    @abstract Returns the busyState of an IOService.
    @discussion Many activities in IOService are asynchronous. When registration, matching, or termination is in progress on an IOService, its busyState is increased by one. Change in busyState to or from zero also changes the IOService's provider's busyState by one, which means that an IOService is marked busy when any of the above activities is ocurring on it or any of its clients.
    @param service The IOService whose busyState to return.
    @param busyState The busyState count is returned.
    @result A kern_return_t error code. */

kern_return_t
IOServiceGetBusyState(
	io_service_t    service,
	uint32_t *	busyState );

/*! @function IOServiceWaitQuiet
    @abstract Wait for an IOService's busyState to be zero.
    @discussion Blocks the caller until an IOService is non busy, see IOServiceGetBusyState.
    @param service The IOService wait on.
    @param waitTime Specifies a maximum time to wait.
    @result Returns an error code if mach synchronization primitives fail, kIOReturnTimeout, or kIOReturnSuccess. */

kern_return_t
IOServiceWaitQuiet(
	io_service_t      service,
	mach_timespec_t * waitTime );

/*! @function IOKitGetBusyState
    @abstract Returns the busyState of all IOServices.
    @discussion Many activities in IOService are asynchronous. When registration, matching, or termination is in progress on an IOService, its busyState is increased by one. Change in busyState to or from zero also changes the IOService's provider's busyState by one, which means that an IOService is marked busy when any of the above activities is ocurring on it or any of its clients. IOKitGetBusyState returns the busy state of the root of the service plane which reflects the busy state of all IOServices.
    @param masterPort The master port obtained from IOMasterPort(). Pass kIOMasterPortDefault to look up the default master port.
    @param busyState The busyState count is returned.
    @result A kern_return_t error code. */

kern_return_t
IOKitGetBusyState(
	mach_port_t	masterPort,
	uint32_t *	busyState );

/*! @function IOKitWaitQuiet
    @abstract Wait for a all IOServices' busyState to be zero.
    @discussion Blocks the caller until all IOServices are non busy, see IOKitGetBusyState.
    @param masterPort The master port obtained from IOMasterPort(). Pass kIOMasterPortDefault to look up the default master port.
    @param waitTime Specifies a maximum time to wait.
    @result Returns an error code if mach synchronization primitives fail, kIOReturnTimeout, or kIOReturnSuccess. */

kern_return_t
IOKitWaitQuiet(
	mach_port_t	  masterPort,
	mach_timespec_t * waitTime );

/*! @function IOServiceOpen
    @abstract A request to create a connection to an IOService.
    @discussion A non kernel client may request a connection be opened via the IOServiceOpen() library function, which will call IOService::newUserClient in the kernel. The rules & capabilities of user level clients are family dependent, the default IOService implementation returns kIOReturnUnsupported.
    @param service The IOService object to open a connection to, usually obtained via the IOServiceGetMatchingServices or IOServiceAddNotification APIs.
    @param owningTask The mach task requesting the connection.
    @param type A constant specifying the type of connection to be created,  interpreted only by the IOService's family.
    @param connect An io_connect_t handle is returned on success, to be used with the IOConnectXXX APIs. It should be destroyed with IOServiceClose().
    @result A return code generated by IOService::newUserClient. */

kern_return_t
IOServiceOpen(
	io_service_t    service,
	task_port_t	owningTask,
	uint32_t	type,
	io_connect_t  *	connect );

/*! @function IOServiceRequestProbe
    @abstract A request to rescan a bus for device changes.
    @discussion A non kernel client may request a bus or controller rescan for added or removed devices, if the bus family does automatically notice such changes. For example, SCSI bus controllers do not notice device changes. The implementation of this routine is family dependent, and the default IOService implementation returns kIOReturnUnsupported.
    @param service The IOService object to request a rescan, usually obtained via the IOServiceGetMatchingServices or IOServiceAddNotification APIs.
    @param options An options mask, interpreted only by the IOService's family.
    @result A return code generated by IOService::requestProbe. */

kern_return_t
IOServiceRequestProbe(
	io_service_t    service,
	uint32_t	options );

// options for IOServiceAuthorize()
enum {
    kIOServiceInteractionAllowed	= 0x00000001
};

/*! @function IOServiceAuthorize
    @abstract Authorize access to an IOService.
    @discussion Determine whether this application is authorized to invoke IOServiceOpen() for a given IOService, either by confirming that it has been previously authorized by the user, or by soliciting the console user.
    @param service The IOService object to be authorized, usually obtained via the IOServiceGetMatchingServices or IOServiceAddNotification APIs.
    @param options kIOServiceInteractionAllowed may be set to permit user interaction, if required.
    @result kIOReturnSuccess if the IOService is authorized, kIOReturnNotPermitted if the IOService is not authorized. */

kern_return_t
IOServiceAuthorize(
	io_service_t	service,
	uint32_t	options );

int
IOServiceOpenAsFileDescriptor(
	io_service_t	service,
	int		oflag );

/* * * * * * * * * * * * * * *ff * * * * * * * * * * * * * * * * * * * * * * */

/*
 * IOService connection
 */

/*! @function IOServiceClose
    @abstract Close a connection to an IOService and destroy the connect handle.
    @discussion A connection created with the IOServiceOpen should be closed when the connection is no longer to be used with IOServiceClose.
    @param connect The connect handle created by IOServiceOpen. It will be destroyed by this function, and should not be released with IOObjectRelease.
    @result A kern_return_t error code. */

kern_return_t
IOServiceClose(
	io_connect_t	connect );

/*! @function IOConnectAddRef
    @abstract Adds a reference to the connect handle.
    @discussion Adds a reference to the connect handle.
    @param connect The connect handle created by IOServiceOpen.
    @result A kern_return_t error code. */

kern_return_t
IOConnectAddRef(
	io_connect_t	connect );

/*! @function IOConnectRelease
    @abstract Remove a reference to the connect handle.
    @discussion Removes a reference to the connect handle.  If the last reference is removed an implicit IOServiceClose is performed.
    @param connect The connect handle created by IOServiceOpen.
    @result A kern_return_t error code. */

kern_return_t
IOConnectRelease(
	io_connect_t	connect );

/*! @function IOConnectGetService
    @abstract Returns the IOService a connect handle was opened on.
    @discussion Finds the service object a connection was opened on.
    @param connect The connect handle created by IOServiceOpen.
    @param service On succes, the service handle the connection was opened on, which should be released with IOObjectRelease.
    @result A kern_return_t error code. */

kern_return_t
IOConnectGetService(
	io_connect_t	connect,
	io_service_t  *	service );

/*! @function IOConnectSetNotificationPort
    @abstract Set a port to receive family specific notifications.
    @discussion This is a generic method to pass a mach port send right to be be used by family specific notifications. 
    @param connect The connect handle created by IOServiceOpen.
    @param type The type of notification requested, not interpreted by IOKit and family defined.
    @param port The port to which to send notifications.
    @param reference Some families may support passing a reference parameter for the callers use with the notification.
    @result A kern_return_t error code. */

kern_return_t
IOConnectSetNotificationPort(
	io_connect_t	connect,
	uint32_t	type,
	mach_port_t	port,
	uintptr_t	reference );

/*! @function IOConnectMapMemory
    @abstract Map hardware or shared memory into the caller's task.
    @discussion This is a generic method to create a mapping in the callers task. The family will interpret the type parameter to determine what sort of mapping is being requested. Cache modes and placed mappings may be requested by the caller.
    @param connect The connect handle created by IOServiceOpen.
    @param memoryType What is being requested to be mapped, not interpreted by IOKit and family defined. The family may support physical hardware or shared memory mappings.
    @param intoTask The task port for the task in which to create the mapping. This may be different to the task which the opened the connection.
    @param atAddress An in/out parameter - if the kIOMapAnywhere option is not set, the caller should pass the address where it requests the mapping be created, otherwise nothing need to set on input. The address of the mapping created is passed back on sucess.
    @param ofSize The size of the mapping created is passed back on success.
    @result A kern_return_t error code. */

#if !__LP64__ || defined(IOCONNECT_MAPMEMORY_10_6)

kern_return_t
IOConnectMapMemory(
	io_connect_t	connect,
	uint32_t	memoryType,
	task_port_t	intoTask,
	vm_address_t	*atAddress,
	vm_size_t	*ofSize,
	IOOptionBits	 options );

#else

kern_return_t
IOConnectMapMemory(
	 io_connect_t		connect,
	 uint32_t		memoryType,
	 task_port_t		intoTask,
	 mach_vm_address_t	*atAddress,
	 mach_vm_size_t		*ofSize,
	 IOOptionBits		 options );

#endif /* !__LP64__ || defined(IOCONNECT_MAPMEMORY_10_6) */


/*! @function IOConnectMapMemory64
    @abstract Map hardware or shared memory into the caller's task.
    @discussion This is a generic method to create a mapping in the callers task. The family will interpret the type parameter to determine what sort of mapping is being requested. Cache modes and placed mappings may be requested by the caller.
    @param connect The connect handle created by IOServiceOpen.
    @param memoryType What is being requested to be mapped, not interpreted by IOKit and family defined. The family may support physical hardware or shared memory mappings.
    @param intoTask The task port for the task in which to create the mapping. This may be different to the task which the opened the connection.
    @param atAddress An in/out parameter - if the kIOMapAnywhere option is not set, the caller should pass the address where it requests the mapping be created, otherwise nothing need to set on input. The address of the mapping created is passed back on sucess.
    @param ofSize The size of the mapping created is passed back on success.
    @result A kern_return_t error code. */

kern_return_t IOConnectMapMemory64(
	 io_connect_t		connect,
	 uint32_t		memoryType,
	 task_port_t		intoTask,
	 mach_vm_address_t	*atAddress,
	 mach_vm_size_t		*ofSize,
	 IOOptionBits		 options );

/*! @function IOConnectUnmapMemory
    @abstract Remove a mapping made with IOConnectMapMemory.
    @discussion This is a generic method to remove a mapping in the callers task.
    @param connect The connect handle created by IOServiceOpen.
    @param memoryType The memory type originally requested in IOConnectMapMemory.
    @param fromTask The task port for the task in which to remove the mapping. This may be different to the task which the opened the connection.
    @param atAddress The address of the mapping to be removed.
    @result A kern_return_t error code. */

#if !__LP64__ || defined(IOCONNECT_MAPMEMORY_10_6)

kern_return_t
IOConnectUnmapMemory(
	io_connect_t	connect,
	uint32_t	memoryType,
	task_port_t	fromTask,
	vm_address_t	atAddress );

#else

kern_return_t
IOConnectUnmapMemory(
	io_connect_t	connect,
	uint32_t	memoryType,
	task_port_t	fromTask,
	mach_vm_address_t	atAddress );


#endif /* !__LP64__ || defined(IOCONNECT_MAPMEMORY_10_6) */

/*! @function IOConnectUnmapMemory64
    @abstract Remove a mapping made with IOConnectMapMemory64.
    @discussion This is a generic method to remove a mapping in the callers task.
    @param connect The connect handle created by IOServiceOpen.
    @param memoryType The memory type originally requested in IOConnectMapMemory.
    @param fromTask The task port for the task in which to remove the mapping. This may be different to the task which the opened the connection.
    @param atAddress The address of the mapping to be removed.
    @result A kern_return_t error code. */

kern_return_t IOConnectUnmapMemory64(
	io_connect_t		connect,
	 uint32_t		memoryType,
	 task_port_t		fromTask,
	 mach_vm_address_t	atAddress );


/*! @function IOConnectSetCFProperties
    @abstract Set CF container based properties on a connection.
    @discussion This is a generic method to pass a CF container of properties to the connection. The properties are interpreted by the family and commonly represent configuration settings, but may be interpreted as anything.
    @param connect The connect handle created by IOServiceOpen.
    @param properties A CF container - commonly a CFDictionary but this is not enforced. The container should consist of objects which are understood by IOKit - these are currently : CFDictionary, CFArray, CFSet, CFString, CFData, CFNumber, CFBoolean, and are passed in the kernel as the corresponding OSDictionary etc. objects.
    @result A kern_return_t error code returned by the family. */

kern_return_t
IOConnectSetCFProperties(
	io_connect_t	connect,
	CFTypeRef	properties );

/*! @function IOConnectSetCFProperty
    @abstract Set a CF container based property on a connection.
    @discussion This is a generic method to pass a CF property to the connection. The property is interpreted by the family and commonly represent configuration settings, but may be interpreted as anything.
    @param connect The connect handle created by IOServiceOpen.
    @param propertyName The name of the property as a CFString.
    @param property A CF container - should consist of objects which are understood by IOKit - these are currently : CFDictionary, CFArray, CFSet, CFString, CFData, CFNumber, CFBoolean, and are passed in the kernel as the corresponding OSDictionary etc. objects.
    @result A kern_return_t error code returned by the object. */

kern_return_t
IOConnectSetCFProperty(
	io_connect_t	connect,
        CFStringRef	propertyName,
	CFTypeRef	property );

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// Combined LP64 & ILP32 Extended IOUserClient::externalMethod

kern_return_t
IOConnectCallMethod(
	mach_port_t	 connection,		// In
	uint32_t	 selector,		// In
	const uint64_t	*input,			// In
	uint32_t	 inputCnt,		// In
	const void      *inputStruct,		// In
	size_t		 inputStructCnt,	// In
	uint64_t	*output,		// Out
	uint32_t	*outputCnt,		// In/Out
	void		*outputStruct,		// Out
	size_t		*outputStructCnt)	// In/Out
AVAILABLE_MAC_OS_X_VERSION_10_5_AND_LATER;

kern_return_t
IOConnectCallAsyncMethod(
	mach_port_t	 connection,		// In
	uint32_t	 selector,		// In
	mach_port_t	 wake_port,		// In
	uint64_t	*reference,		// In
	uint32_t	 referenceCnt,		// In
	const uint64_t	*input,			// In
	uint32_t	 inputCnt,		// In
	const void	*inputStruct,		// In
	size_t		 inputStructCnt,	// In
	uint64_t	*output,		// Out
	uint32_t	*outputCnt,		// In/Out
	void		*outputStruct,		// Out
	size_t		*outputStructCnt)	// In/Out
AVAILABLE_MAC_OS_X_VERSION_10_5_AND_LATER;

kern_return_t
IOConnectCallStructMethod(
	mach_port_t	 connection,		// In
	uint32_t	 selector,		// In
	const void	*inputStruct,		// In
	size_t		 inputStructCnt,	// In
	void		*outputStruct,		// Out
	size_t		*outputStructCnt)	// In/Out
AVAILABLE_MAC_OS_X_VERSION_10_5_AND_LATER;

kern_return_t
IOConnectCallAsyncStructMethod(
	mach_port_t	 connection,		// In
	uint32_t	 selector,		// In
	mach_port_t	 wake_port,		// In
	uint64_t	*reference,		// In
	uint32_t	 referenceCnt,		// In
	const void	*inputStruct,		// In
	size_t		 inputStructCnt,	// In
	void		*outputStruct,		// Out
	size_t		*outputStructCnt)	// In/Out
AVAILABLE_MAC_OS_X_VERSION_10_5_AND_LATER;

kern_return_t
IOConnectCallScalarMethod(
	mach_port_t	 connection,		// In
	uint32_t	 selector,		// In
	const uint64_t	*input,			// In
	uint32_t	 inputCnt,		// In
	uint64_t	*output,		// Out
	uint32_t	*outputCnt)		// In/Out
AVAILABLE_MAC_OS_X_VERSION_10_5_AND_LATER;

kern_return_t
IOConnectCallAsyncScalarMethod(
	mach_port_t	 connection,		// In
	uint32_t	 selector,		// In
	mach_port_t	 wake_port,		// In
	uint64_t	*reference,		// In
	uint32_t	 referenceCnt,		// In
	const uint64_t	*input,			// In
	uint32_t	 inputCnt,		// In
	uint64_t	*output,		// Out
	uint32_t	*outputCnt)		// In/Out
AVAILABLE_MAC_OS_X_VERSION_10_5_AND_LATER;

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

kern_return_t
IOConnectTrap0(io_connect_t	connect,
	       uint32_t		index );

kern_return_t
IOConnectTrap1(io_connect_t	connect,
	       uint32_t		index,
	       uintptr_t	p1 );

kern_return_t
IOConnectTrap2(io_connect_t	connect,
	       uint32_t		index,
	       uintptr_t	p1,
	       uintptr_t	p2);

kern_return_t
IOConnectTrap3(io_connect_t	connect,
	       uint32_t		index,
	       uintptr_t	p1,
	       uintptr_t	p2,
	       uintptr_t	p3);

kern_return_t
IOConnectTrap4(io_connect_t	connect,
	       uint32_t		index,
	       uintptr_t	p1,
	       uintptr_t	p2,
	       uintptr_t	p3,
	       uintptr_t	p4);

kern_return_t
IOConnectTrap5(io_connect_t	connect,
	       uint32_t		index,
	       uintptr_t	p1,
	       uintptr_t	p2,
	       uintptr_t	p3,
	       uintptr_t	p4,
	       uintptr_t	p5);

kern_return_t
IOConnectTrap6(io_connect_t	connect,
	       uint32_t		index,
	       uintptr_t	p1,
	       uintptr_t	p2,
	       uintptr_t	p3,
	       uintptr_t	p4,
	       uintptr_t	p5,
	       uintptr_t	p6);

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*! @function IOConnectAddClient
    @abstract Inform a connection of a second connection.
    @discussion This is a generic method to inform a family connection of a second connection, and is rarely used.
    @param connect The connect handle created by IOServiceOpen.
    @param client Another connect handle created by IOServiceOpen.
    @result A kern_return_t error code returned by the family. */

kern_return_t
IOConnectAddClient(
	io_connect_t	connect,
	io_connect_t	client );

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*
 * IORegistry accessors
 */

/*! @function IORegistryGetRootEntry
    @abstract Return a handle to the registry root.
    @discussion This method provides an accessor to the root of the registry for the machine. The root may be passed to a registry iterator when iterating a plane, and contains properties that describe the available planes, and diagnostic information for IOKit.
    @param masterPort The master port obtained from IOMasterPort(). Pass kIOMasterPortDefault to look up the default master port.
    @result A handle to the IORegistryEntry root instance, to be released with IOObjectRelease by the caller, or MACH_PORT_NULL on failure. */

io_registry_entry_t
IORegistryGetRootEntry(
	mach_port_t	masterPort );

/*! @function IORegistryEntryFromPath
    @abstract Looks up a registry entry by path.
    @discussion This function parses paths to lookup registry entries. The path should begin with '<plane name>:' If there are characters remaining unparsed after an entry has been looked up, this is considered an invalid lookup. Paths are further documented in IORegistryEntry.h
    @param masterPort The master port obtained from IOMasterPort(). Pass kIOMasterPortDefault to look up the default master port.
    @param path A C-string path.
    @result A handle to the IORegistryEntry witch was found with the path, to be released with IOObjectRelease by the caller, or MACH_PORT_NULL on failure. */

io_registry_entry_t
IORegistryEntryFromPath(
	mach_port_t		masterPort,
	const io_string_t	path );


/*! @function IORegistryEntryFromPathCFString
    @abstract Looks up a registry entry by path.
    @discussion This function parses paths to lookup registry entries. The path should begin with '<plane name>:' If there are characters remaining unparsed after an entry has been looked up, this is considered an invalid lookup. Paths are further documented in IORegistryEntry.h
    @param masterPort The master port obtained from IOMasterPort(). Pass kIOMasterPortDefault to look up the default master port.
    @param path A CFString path.
    @result A handle to the IORegistryEntry witch was found with the path, to be released with IOObjectRelease by the caller, or MACH_PORT_NULL on failure. */

io_registry_entry_t
IORegistryEntryCopyFromPath(
	mach_port_t	masterPort,
	CFStringRef	path )
#if defined(__MAC_10_11)
__OSX_AVAILABLE_STARTING(__MAC_10_11, __IPHONE_9_0)
#endif
;

// options for IORegistryCreateIterator(), IORegistryEntryCreateIterator, IORegistryEntrySearchCFProperty()
enum {
    kIORegistryIterateRecursively	= 0x00000001,
    kIORegistryIterateParents		= 0x00000002
};

/*! @function IORegistryCreateIterator
    @abstract Create an iterator rooted at the registry root.
    @discussion This method creates an IORegistryIterator in the kernel that is set up with options to iterate children of the registry root entry, and to recurse automatically into entries as they are returned, or only when instructed with calls to IORegistryIteratorEnterEntry. The iterator object keeps track of entries that have been recursed into previously to avoid loops.
    @param masterPort The master port obtained from IOMasterPort(). Pass kIOMasterPortDefault to look up the default master port.
    @param plane The name of an existing registry plane. Plane names are defined in IOKitKeys.h, eg. kIOServicePlane.
    @param options kIORegistryIterateRecursively may be set to recurse automatically into each entry as it is returned from IOIteratorNext calls on the registry iterator. 
    @param iterator A created iterator handle, to be released by the caller when it has finished with it.
    @result A kern_return_t error code. */

kern_return_t
IORegistryCreateIterator(
	mach_port_t	masterPort,
	const io_name_t	plane,
	IOOptionBits	options,
	io_iterator_t * iterator );

/*! @function IORegistryEntryCreateIterator
    @abstract Create an iterator rooted at a given registry entry.
    @discussion This method creates an IORegistryIterator in the kernel that is set up with options to iterate children or parents of a root entry, and to recurse automatically into entries as they are returned, or only when instructed with calls to IORegistryIteratorEnterEntry. The iterator object keeps track of entries that have been recursed into previously to avoid loops.
    @param entry The root entry to begin the iteration at.
    @param plane The name of an existing registry plane. Plane names are defined in IOKitKeys.h, eg. kIOServicePlane.
    @param options kIORegistryIterateRecursively may be set to recurse automatically into each entry as it is returned from IOIteratorNext calls on the registry iterator. kIORegistryIterateParents may be set to iterate the parents of each entry, by default the children are iterated.
    @param iterator A created iterator handle, to be released by the caller when it has finished with it.
    @result A kern_return_t error code. */

kern_return_t
IORegistryEntryCreateIterator(
	io_registry_entry_t	entry,
	const io_name_t		plane,
	IOOptionBits		options,
	io_iterator_t 	      * iterator );

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*
 * IORegistryIterator, subclass of IOIterator
 */

/*! @function IORegistryIteratorEnterEntry
    @abstract Recurse into the current entry in the registry iteration.
    @discussion This method makes the current entry, ie. the last entry returned by IOIteratorNext, the root in a new level of recursion.
    @result A kern_return_t error code. */

kern_return_t
IORegistryIteratorEnterEntry(
	io_iterator_t	iterator );

/*! @function IORegistryIteratorExitEntry
    @abstract Exits a level of recursion, restoring the current entry.
    @discussion This method undoes an IORegistryIteratorEnterEntry, restoring the current entry. If there are no more levels of recursion to exit false is returned, otherwise true is returned.
    @result kIOReturnSuccess if a level of recursion was undone, kIOReturnNoDevice if no recursive levels are left in the iteration. */

kern_return_t
IORegistryIteratorExitEntry(
	io_iterator_t	iterator );

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*
 * IORegistryEntry, subclass of IOObject
 */

/*! @function IORegistryEntryGetName
    @abstract Returns a C-string name assigned to a registry entry.
    @discussion Registry entries can be named in a particular plane, or globally. This function returns the entry's global name. The global name defaults to the entry's meta class name if it has not been named.
    @param entry The registry entry handle whose name to look up.
    @param name The caller's buffer to receive the name.
    @result A kern_return_t error code. */

kern_return_t
IORegistryEntryGetName(
	io_registry_entry_t	entry,
	io_name_t 	        name );

/*! @function IORegistryEntryGetNameInPlane
    @abstract Returns a C-string name assigned to a registry entry, in a specified plane.
    @discussion Registry entries can be named in a particular plane, or globally. This function returns the entry's name in the specified plane or global name if it has not been named in that plane. The global name defaults to the entry's meta class name if it has not been named.
    @param entry The registry entry handle whose name to look up.
    @param plane The name of an existing registry plane. Plane names are defined in IOKitKeys.h, eg. kIOServicePlane.
    @param name The caller's buffer to receive the name.
    @result A kern_return_t error code. */

kern_return_t
IORegistryEntryGetNameInPlane(
	io_registry_entry_t	entry,
	const io_name_t 	plane,
	io_name_t 	        name );

/*! @function IORegistryEntryGetLocationInPlane
    @abstract Returns a C-string location assigned to a registry entry, in a specified plane.
    @discussion Registry entries can given a location string in a particular plane, or globally. If the entry has had a location set in the specified plane that location string will be returned, otherwise the global location string is returned. If no global location string has been set, an error is returned.
    @param entry The registry entry handle whose name to look up.
    @param plane The name of an existing registry plane. Plane names are defined in IOKitKeys.h, eg. kIOServicePlane.
    @param location The caller's buffer to receive the location string.
    @result A kern_return_t error code. */

kern_return_t
IORegistryEntryGetLocationInPlane(
	io_registry_entry_t	entry,
	const io_name_t 	plane,
	io_name_t 	        location );

/*! @function IORegistryEntryGetPath
    @abstract Create a path for a registry entry.
    @discussion The path for a registry entry is copied to the caller's buffer. The path describes the entry's attachment in a particular plane, which must be specified. The path begins with the plane name followed by a colon, and then followed by '/' separated path components for each of the entries between the root and the registry entry. An alias may also exist for the entry, and will be returned if available.
    @param entry The registry entry handle whose path to look up.
    @param plane The name of an existing registry plane. Plane names are defined in IOKitKeys.h, eg. kIOServicePlane.
    @param path A char buffer allocated by the caller.
    @result IORegistryEntryGetPath will fail if the entry is not attached in the plane, or if the buffer is not large enough to contain the path. */

kern_return_t
IORegistryEntryGetPath(
	io_registry_entry_t	entry,
	const io_name_t         plane,
	io_string_t		path );

/*! @function IORegistryEntryCopyPath
    @abstract Create a path for a registry entry.
    @discussion The path for a registry entry is returned as a CFString The path describes the entry's attachment in a particular plane, which must be specified. The path begins with the plane name followed by a colon, and then followed by '/' separated path components for each of the entries between the root and the registry entry. An alias may also exist for the entry, and will be returned if available.
    @param entry The registry entry handle whose path to look up.
    @param plane The name of an existing registry plane. Plane names are defined in IOKitKeys.h, eg. kIOServicePlane.
    @result An instance of CFString on success, to be released by the caller. IORegistryEntryCopyPath will fail if the entry is not attached in the plane. */

CFStringRef
IORegistryEntryCopyPath(
	io_registry_entry_t	entry,
	const io_name_t         plane)
#if defined(__MAC_10_11)
__OSX_AVAILABLE_STARTING(__MAC_10_11, __IPHONE_9_0)
#endif
;

/*! @function IORegistryEntryGetRegistryEntryID
    @abstract Returns an ID for the registry entry that is global to all tasks.
    @discussion The entry ID returned by IORegistryEntryGetRegistryEntryID can be used to identify a registry entry across all tasks. A registry entry may be looked up by its entryID by creating a matching dictionary with IORegistryEntryIDMatching() to be used with the IOKit matching functions. The ID is valid only until the machine reboots.
    @param entry The registry entry handle whose ID to look up.
    @param entryID The resulting ID.
    @result A kern_return_t error code. */

kern_return_t
IORegistryEntryGetRegistryEntryID(
	io_registry_entry_t	entry,
	uint64_t *		entryID );

/*! @function IORegistryEntryCreateCFProperties
    @abstract Create a CF dictionary representation of a registry entry's property table.
    @discussion This function creates an instantaneous snapshot of a registry entry's property table, creating a CFDictionary analogue in the caller's task. Not every object available in the kernel is represented as a CF container; currently OSDictionary, OSArray, OSSet, OSSymbol, OSString, OSData, OSNumber, OSBoolean are created as their CF counterparts. 
    @param entry The registry entry handle whose property table to copy.
    @param properties A CFDictionary is created and returned the caller on success. The caller should release with CFRelease.
    @param allocator The CF allocator to use when creating the CF containers.
    @param options No options are currently defined.
    @result A kern_return_t error code. */

kern_return_t
IORegistryEntryCreateCFProperties(
	io_registry_entry_t	entry,
	CFMutableDictionaryRef * properties,
        CFAllocatorRef		allocator,
	IOOptionBits		options );

/*! @function IORegistryEntryCreateCFProperty
    @abstract Create a CF representation of a registry entry's property.
    @discussion This function creates an instantaneous snapshot of a registry entry property, creating a CF container analogue in the caller's task. Not every object available in the kernel is represented as a CF container; currently OSDictionary, OSArray, OSSet, OSSymbol, OSString, OSData, OSNumber, OSBoolean are created as their CF counterparts. 
    @param entry The registry entry handle whose property to copy.
    @param key A CFString specifying the property name.
    @param allocator The CF allocator to use when creating the CF container.
    @param options No options are currently defined.
    @result A CF container is created and returned the caller on success. The caller should release with CFRelease. */

CFTypeRef
IORegistryEntryCreateCFProperty(
	io_registry_entry_t	entry,
	CFStringRef		key,
        CFAllocatorRef		allocator,
	IOOptionBits		options );

/*! @function IORegistryEntrySearchCFProperty
    @abstract Create a CF representation of a registry entry's property.
    @discussion This function creates an instantaneous snapshot of a registry entry property, creating a CF container analogue in the caller's task. Not every object available in the kernel is represented as a CF container; currently OSDictionary, OSArray, OSSet, OSSymbol, OSString, OSData, OSNumber, OSBoolean are created as their CF counterparts. 
This function will search for a property, starting first with specified registry entry's property table, then iterating recusively through either the parent registry entries or the child registry entries of this entry. Once the first occurrence is found, it will lookup and return the value of the property, using the same semantics as IORegistryEntryCreateCFProperty. The iteration keeps track of entries that have been recursed into previously to avoid loops.
    @param entry The registry entry at which to start the search.
    @param plane The name of an existing registry plane. Plane names are defined in IOKitKeys.h, eg. kIOServicePlane.
    @param key A CFString specifying the property name.
    @param allocator The CF allocator to use when creating the CF container.
    @param options kIORegistryIterateRecursively may be set to recurse automatically into the registry hierarchy. Without this option, this method degenerates into the standard IORegistryEntryCreateCFProperty() call. kIORegistryIterateParents may be set to iterate the parents of the entry, in place of the children.
    @result A CF container is created and returned the caller on success. The caller should release with CFRelease. */

CFTypeRef
IORegistryEntrySearchCFProperty(
	io_registry_entry_t	entry,
	const io_name_t		plane,
	CFStringRef		key,
        CFAllocatorRef		allocator,
	IOOptionBits		options ) CF_RETURNS_RETAINED;

/*  @function IORegistryEntryGetProperty - deprecated,
    use IORegistryEntryCreateCFProperty */

kern_return_t
IORegistryEntryGetProperty(
	io_registry_entry_t	entry,
	const io_name_t		propertyName,
	io_struct_inband_t	buffer,
	uint32_t	      * size );

/*! @function IORegistryEntrySetCFProperties
    @abstract Set CF container based properties in a registry entry.
    @discussion This is a generic method to pass a CF container of properties to an object in the registry. Setting properties in a registry entry is not generally supported, it is more common to support IOConnectSetCFProperties for connection based property setting. The properties are interpreted by the object.
    @param entry The registry entry whose properties to set.
    @param properties A CF container - commonly a CFDictionary but this is not enforced. The container should consist of objects which are understood by IOKit - these are currently : CFDictionary, CFArray, CFSet, CFString, CFData, CFNumber, CFBoolean, and are passed in the kernel as the corresponding OSDictionary etc. objects.
    @result A kern_return_t error code returned by the object. */

kern_return_t
IORegistryEntrySetCFProperties(
	io_registry_entry_t	entry,
	CFTypeRef	 	properties );

/*! @function IORegistryEntrySetCFProperty
    @abstract Set a CF container based property in a registry entry.
    @discussion This is a generic method to pass a CF container as a property to an object in the registry. Setting properties in a registry entry is not generally supported, it is more common to support IOConnectSetCFProperty for connection based property setting. The property is interpreted by the object.
    @param entry The registry entry whose property to set.
    @param propertyName The name of the property as a CFString.
    @param property A CF container - should consist of objects which are understood by IOKit - these are currently : CFDictionary, CFArray, CFSet, CFString, CFData, CFNumber, CFBoolean, and are passed in the kernel as the corresponding OSDictionary etc. objects.
    @result A kern_return_t error code returned by the object. */

kern_return_t
IORegistryEntrySetCFProperty(
	io_registry_entry_t	entry,
        CFStringRef		propertyName,
	CFTypeRef	 	property );

/*! @function IORegistryEntryGetChildIterator
    @abstract Returns an iterator over an registry entry's child entries in a plane.
    @discussion This method creates an iterator which will return each of a registry entry's child entries in a specified plane.
    @param entry The registry entry whose children to iterate over.
    @param plane The name of an existing registry plane. Plane names are defined in IOKitKeys.h, eg. kIOServicePlane.
    @param iterator The created iterator over the children of the entry, on success. The iterator must be released when the iteration is finished.
    @result A kern_return_t error code. */

kern_return_t
IORegistryEntryGetChildIterator(
	io_registry_entry_t	entry,
	const io_name_t		plane,
	io_iterator_t	      * iterator );

/*! @function IORegistryEntryGetChildEntry
    @abstract Returns the first child of a registry entry in a plane.
    @discussion This function will return the child which first attached to a registry entry in a plane.
    @param entry The registry entry whose child to look up.
    @param plane The name of an existing registry plane. Plane names are defined in IOKitKeys.h, eg. kIOServicePlane.
    @param child The first child of the registry entry, on success. The child must be released by the caller.
    @result A kern_return_t error code. */

kern_return_t
IORegistryEntryGetChildEntry(
	io_registry_entry_t	entry,
	const io_name_t		plane,
	io_registry_entry_t   * child );

/*! @function IORegistryEntryGetParentIterator
    @abstract Returns an iterator over an registry entry's parent entries in a plane.
    @discussion This method creates an iterator which will return each of a registry entry's parent entries in a specified plane.
    @param entry The registry entry whose parents to iterate over.
    @param plane The name of an existing registry plane. Plane names are defined in IOKitKeys.h, eg. kIOServicePlane.
    @param iterator The created iterator over the parents of the entry, on success. The iterator must be released when the iteration is finished.
    @result A kern_return_t error. */

kern_return_t
IORegistryEntryGetParentIterator(
	io_registry_entry_t	entry,
	const io_name_t		plane,
	io_iterator_t	      * iterator );

/*! @function IORegistryEntryGetParentEntry
    @abstract Returns the first parent of a registry entry in a plane.
    @discussion This function will return the parent to which the registry entry was first attached in a plane.
    @param entry The registry entry whose parent to look up.
    @param plane The name of an existing registry plane. Plane names are defined in IOKitKeys.h, eg. kIOServicePlane.
    @param parent The first parent of the registry entry, on success. The parent must be released by the caller.
    @result A kern_return_t error code. */

kern_return_t
IORegistryEntryGetParentEntry(
	io_registry_entry_t	entry,
	const io_name_t		plane,
	io_registry_entry_t   * parent );

/*! @function IORegistryEntryInPlane
    @abstract Determines if the registry entry is attached in a plane.
    @discussion This method determines if the entry is attached in a plane to any other entry.
    @param entry The registry entry.
    @param plane The name of an existing registry plane. Plane names are defined in IOKitKeys.h, eg. kIOServicePlane.
    @result If the entry has a parent in the plane, true is returned, otherwise false is returned. */

boolean_t
IORegistryEntryInPlane(
	io_registry_entry_t	entry,
	const io_name_t		plane );

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*
 * Matching dictionary creation helpers
 */

/*! @function IOServiceMatching
    @abstract Create a matching dictionary that specifies an IOService class match.
    @discussion A very common matching criteria for IOService is based on its class. IOServiceMatching will create a matching dictionary that specifies any IOService of a class, or its subclasses. The class is specified by C-string name.
    @param name The class name, as a const C-string. Class matching is successful on IOService's of this class or any subclass.
    @result The matching dictionary created, is returned on success, or zero on failure. The dictionary is commonly passed to IOServiceGetMatchingServices or IOServiceAddNotification which will consume a reference, otherwise it should be released with CFRelease by the caller. */

CFMutableDictionaryRef
IOServiceMatching(
	const char *	name ) CF_RETURNS_RETAINED;

/*! @function IOServiceNameMatching
    @abstract Create a matching dictionary that specifies an IOService name match.
    @discussion A common matching criteria for IOService is based on its name. IOServiceNameMatching will create a matching dictionary that specifies an IOService with a given name. Some IOServices created from the device tree will perform name matching on the standard compatible, name, model properties.
    @param name The IOService name, as a const C-string.
    @result The matching dictionary created, is returned on success, or zero on failure. The dictionary is commonly passed to IOServiceGetMatchingServices or IOServiceAddNotification which will consume a reference, otherwise it should be released with CFRelease by the caller. */

CFMutableDictionaryRef
IOServiceNameMatching(
	const char *	name ) CF_RETURNS_RETAINED;

/*! @function IOBSDNameMatching
    @abstract Create a matching dictionary that specifies an IOService match based on BSD device name.
    @discussion IOServices that represent BSD devices have an associated BSD name. This function creates a matching dictionary that will match IOService's with a given BSD name.
    @param masterPort The master port obtained from IOMasterPort(). Pass kIOMasterPortDefault to look up the default master port.
    @param options No options are currently defined.
    @param bsdName The BSD name, as a const char *.
    @result The matching dictionary created, is returned on success, or zero on failure. The dictionary is commonly passed to IOServiceGetMatchingServices or IOServiceAddNotification which will consume a reference, otherwise it should be released with CFRelease by the caller. */

CFMutableDictionaryRef
IOBSDNameMatching(
	mach_port_t	masterPort,
	uint32_t	options,
	const char *	bsdName ) CF_RETURNS_RETAINED;

CFMutableDictionaryRef
IOOpenFirmwarePathMatching(
	mach_port_t	masterPort,
	uint32_t	options,
	const char *	path ) DEPRECATED_ATTRIBUTE;

/*! @function IORegistryEntryIDMatching
    @abstract Create a matching dictionary that specifies an IOService match based on a registry entry ID.
    @discussion This function creates a matching dictionary that will match a registered, active IOService found with the given registry entry ID. The entry ID for a registry entry is returned by IORegistryEntryGetRegistryEntryID().
    @param entryID The registry entry ID to be found. 
    @result The matching dictionary created, is returned on success, or zero on failure. The dictionary is commonly passed to IOServiceGetMatchingServices or IOServiceAddNotification which will consume a reference, otherwise it should be released with CFRelease by the caller. */

CFMutableDictionaryRef
IORegistryEntryIDMatching(
	uint64_t	entryID ) CF_RETURNS_RETAINED;

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

kern_return_t
IOServiceOFPathToBSDName(mach_port_t		masterPort,
                         const io_name_t	openFirmwarePath,
                         io_name_t		bsdName) DEPRECATED_ATTRIBUTE;
						 
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*! @typedef IOAsyncCallback0
    @abstract standard callback function for asynchronous I/O requests with
    no extra arguments beyond a refcon and result code.
    @param refcon The refcon passed into the original I/O request
    @param result The result of the I/O operation
*/
typedef void (*IOAsyncCallback0)(void *refcon, IOReturn result);

/*! @typedef IOAsyncCallback1
    @abstract standard callback function for asynchronous I/O requests with
    one extra argument beyond a refcon and result code.
    This is often a count of the number of bytes transferred
    @param refcon The refcon passed into the original I/O request
    @param result The result of the I/O operation
    @param arg0	Extra argument
*/
typedef void (*IOAsyncCallback1)(void *refcon, IOReturn result, void *arg0);

/*! @typedef IOAsyncCallback2
    @abstract standard callback function for asynchronous I/O requests with
    two extra arguments beyond a refcon and result code.
    @param refcon The refcon passed into the original I/O request
    @param result The result of the I/O operation
    @param arg0	Extra argument
    @param arg1	Extra argument
*/
typedef void (*IOAsyncCallback2)(void *refcon, IOReturn result, void *arg0, void *arg1);

/*! @typedef IOAsyncCallback
    @abstract standard callback function for asynchronous I/O requests with
    lots of extra arguments beyond a refcon and result code.
    @param refcon The refcon passed into the original I/O request
    @param result The result of the I/O operation
    @param args	Array of extra arguments
    @param numArgs Number of extra arguments
*/
typedef void (*IOAsyncCallback)(void *refcon, IOReturn result, void **args,
                                uint32_t numArgs);


/* Internal use */

kern_return_t
OSGetNotificationFromMessage(
	mach_msg_header_t     * msg,
	uint32_t	  	index,
        uint32_t    	      * type,
        uintptr_t	      * reference,
	void		     ** content,
        vm_size_t	      * size );

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/* Internal use */

kern_return_t
IOCatalogueSendData(
        mach_port_t             masterPort,
        uint32_t                flag,
        const char             *buffer,
        uint32_t                size );

kern_return_t
IOCatalogueTerminate(
        mach_port_t		masterPort,
        uint32_t                flag,
	io_name_t		description );

kern_return_t
IOCatalogueGetData(
        mach_port_t             masterPort,
        uint32_t                flag,
        char                  **buffer,
        uint32_t               *size );

kern_return_t
IOCatalogueModuleLoaded(
        mach_port_t             masterPort,
        io_name_t               name );

/* Use IOCatalogueSendData(), with kIOCatalogResetDrivers, to replace catalogue
 * rather than emptying it. Doing so keeps instance counts down by uniquing
 * existing personalities.
 */
kern_return_t
IOCatalogueReset(
        mach_port_t             masterPort,
        uint32_t                flag );

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// obsolete API

#if !defined(__LP64__)

// for Power Mgt

typedef struct IOObject IOObject;

// for MacOS.app

kern_return_t
IORegistryDisposeEnumerator(
	io_enumerator_t	enumerator ) DEPRECATED_ATTRIBUTE;

kern_return_t
IOMapMemory(
	io_connect_t	connect,
	uint32_t	memoryType,
	task_port_t	intoTask,
	vm_address_t *	atAddress,
	vm_size_t    *	ofSize,
	uint32_t	flags ) DEPRECATED_ATTRIBUTE;

// for CGS

kern_return_t
IOCompatibiltyNumber(
	mach_port_t	connect,
	uint32_t *	objectNumber ) DEPRECATED_ATTRIBUTE;

// Traditional IOUserClient transport routines
kern_return_t
IOConnectMethodScalarIScalarO( 
	io_connect_t	connect,
        uint32_t	index,
        IOItemCount	scalarInputCount,
        IOItemCount	scalarOutputCount,
        ... ) AVAILABLE_MAC_OS_X_VERSION_10_0_AND_LATER_BUT_DEPRECATED_IN_MAC_OS_X_VERSION_10_5;

kern_return_t
IOConnectMethodScalarIStructureO(
	io_connect_t	connect,
        uint32_t	index,
        IOItemCount	scalarInputCount,
        IOByteCount *	structureSize,
        ... ) AVAILABLE_MAC_OS_X_VERSION_10_0_AND_LATER_BUT_DEPRECATED_IN_MAC_OS_X_VERSION_10_5;

kern_return_t
IOConnectMethodScalarIStructureI(
	io_connect_t	connect,
        uint32_t	index,
        IOItemCount	scalarInputCount,
        IOByteCount	structureSize,
        ... ) AVAILABLE_MAC_OS_X_VERSION_10_0_AND_LATER_BUT_DEPRECATED_IN_MAC_OS_X_VERSION_10_5;

kern_return_t
IOConnectMethodStructureIStructureO(
	io_connect_t	connect,
        uint32_t	index,
        IOItemCount	structureInputSize,
        IOByteCount *	structureOutputSize,
        void *		inputStructure,
        void *		ouputStructure ) AVAILABLE_MAC_OS_X_VERSION_10_0_AND_LATER_BUT_DEPRECATED_IN_MAC_OS_X_VERSION_10_5;

// Compatability with earlier Mig interface routines
#if IOCONNECT_NO_32B_METHODS

kern_return_t
io_connect_map_memory(
	io_connect_t		connect,
	uint32_t		memoryType,
	task_port_t		intoTask,
	vm_address_t		*atAddress,
	vm_size_t		*ofSize,
	IOOptionBits		options) DEPRECATED_ATTRIBUTE;

kern_return_t
io_connect_unmap_memory(
	io_connect_t		connect,
	uint32_t		memoryType,
	task_port_t		fromTask,
	vm_address_t		atAddress) DEPRECATED_ATTRIBUTE;

kern_return_t
io_connect_method_scalarI_scalarO(
	mach_port_t connection,
	int selector,
	io_scalar_inband_t input,
	mach_msg_type_number_t inputCnt,
	io_scalar_inband_t output,
	mach_msg_type_number_t *outputCnt) DEPRECATED_ATTRIBUTE;

kern_return_t
io_connect_method_scalarI_structureO(
	mach_port_t connection,
	int selector,
	io_scalar_inband_t input,
	mach_msg_type_number_t inputCnt,
	io_struct_inband_t output,
	mach_msg_type_number_t *outputCnt) DEPRECATED_ATTRIBUTE;

kern_return_t
io_connect_method_scalarI_structureI(
	mach_port_t connection,
	int selector,
	io_scalar_inband_t input,
	mach_msg_type_number_t inputCnt,
	io_struct_inband_t inputStruct,
	mach_msg_type_number_t inputStructCnt) DEPRECATED_ATTRIBUTE;

kern_return_t
io_connect_method_structureI_structureO(
	mach_port_t connection,
	int selector,
	io_struct_inband_t input,
	mach_msg_type_number_t inputCnt,
	io_struct_inband_t output,
	mach_msg_type_number_t *outputCnt) DEPRECATED_ATTRIBUTE;

kern_return_t
io_async_method_scalarI_scalarO(
	mach_port_t connection,
	mach_port_t wake_port,
	io_async_ref_t reference,
	mach_msg_type_number_t referenceCnt,
	int selector,
	io_scalar_inband_t input,
	mach_msg_type_number_t inputCnt,
	io_scalar_inband_t output,
	mach_msg_type_number_t *outputCnt) DEPRECATED_ATTRIBUTE;

kern_return_t
io_async_method_scalarI_structureO(
	mach_port_t connection,
	mach_port_t wake_port,
	io_async_ref_t reference,
	mach_msg_type_number_t referenceCnt,
	int selector,
	io_scalar_inband_t input,
	mach_msg_type_number_t inputCnt,
	io_struct_inband_t output,
	mach_msg_type_number_t *outputCnt) DEPRECATED_ATTRIBUTE;

kern_return_t
io_async_method_scalarI_structureI(
	mach_port_t connection,
	mach_port_t wake_port,
	io_async_ref_t reference,
	mach_msg_type_number_t referenceCnt,
	int selector,
	io_scalar_inband_t input,
	mach_msg_type_number_t inputCnt,
	io_struct_inband_t inputStruct,
	mach_msg_type_number_t inputStructCnt) DEPRECATED_ATTRIBUTE;

kern_return_t
io_async_method_structureI_structureO(
	mach_port_t connection,
	mach_port_t wake_port,
	io_async_ref_t reference,
	mach_msg_type_number_t referenceCnt,
	int selector,
	io_struct_inband_t input,
	mach_msg_type_number_t inputCnt,
	io_struct_inband_t output,
	mach_msg_type_number_t *outputCnt) DEPRECATED_ATTRIBUTE;
#endif // IOCONNECT_NO_32B_METHODS

#endif /* defined(__LP64__) */

__END_DECLS

#endif /* ! _IOKIT_IOKITLIB_H */
