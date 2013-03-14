/*****************************************************************************

$Id$

File:     pipe.cpp
Date:     30May07

Copyright (C) 2006-07 by Francis Cianfrocca. All Rights Reserved.
Gmail: blackhedd

This program is free software; you can redistribute it and/or modify
it under the terms of either: 1) the GNU General Public License
as published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version; or 2) Ruby's License.

See the file COPYING for complete licensing information.

*****************************************************************************/

#include "project.h"


#ifdef OS_UNIX
// THIS ENTIRE FILE IS ONLY COMPILED ON UNIX-LIKE SYSTEMS.

/******************************
PipeDescriptor::PipeDescriptor
******************************/

PipeDescriptor::PipeDescriptor (int fd, pid_t subpid, EventMachine_t *parent_em):
	EventableDescriptor (fd, parent_em),
	bReadAttemptedAfterClose (false),
	OutboundDataSize (0),
	SubprocessPid (subpid)
{
	#ifdef HAVE_EPOLL
	EpollEvent.events = EPOLLIN;
	#endif
	#ifdef HAVE_KQUEUE
	MyEventMachine->ArmKqueueReader (this);
	#endif
}


/*******************************
PipeDescriptor::~PipeDescriptor
*******************************/

PipeDescriptor::~PipeDescriptor()
{
	// Run down any stranded outbound data.
	for (size_t i=0; i < OutboundPages.size(); i++)
		OutboundPages[i].Free();

	/* As a virtual destructor, we come here before the base-class
	 * destructor that closes our file-descriptor.
	 * We have to make sure the subprocess goes down (if it's not
	 * already down) and we have to reap the zombie.
	 *
	 * This implementation is PROVISIONAL and will surely be improved.
	 * The intention here is that we never block, hence the highly
	 * undesirable sleeps. But if we can't reap the subprocess even
	 * after sending it SIGKILL, then something is wrong and we
	 * throw a fatal exception, which is also not something we should
	 * be doing.
	 *
	 * Eventually the right thing to do will be to have the reactor
	 * core respond to SIGCHLD by chaining a handler on top of the
	 * one Ruby may have installed, and dealing with a list of dead
	 * children that are pending cleanup.
	 *
	 * Since we want to have a signal processor integrated into the
	 * client-visible API, let's wait until that is done before cleaning
	 * this up.
	 *
	 * Added a very ugly hack to support passing the subprocess's exit
	 * status to the user. It only makes logical sense for user code to access
	 * the subprocess exit status in the unbind callback. But unbind is called
	 * back during the EventableDescriptor destructor. So by that time there's
	 * no way to call back this object through an object binding, because it's
	 * already been cleaned up. We might have added a parameter to the unbind
	 * callback, but that would probably break a huge amount of existing code.
	 * So the hack-solution is to define an instance variable in the EventMachine
	 * object and stick the exit status in there, where it can easily be accessed
	 * with an accessor visible to user code.
	 * User code should ONLY access the exit status from within the unbind callback.
	 * Otherwise there's no guarantee it'll be valid.
	 * This hack won't make it impossible to run multiple EventMachines in a single
	 * process, but it will make it impossible to reliably nest unbind calls
	 * within other unbind calls. (Not sure if that's even possible.)
	 */

	assert (MyEventMachine);

	/* Another hack to make the SubprocessPid available to get_subprocess_status */
	MyEventMachine->SubprocessPid = SubprocessPid;

	/* 01Mar09: Updated to use a small nanosleep in a loop. When nanosleep is interrupted by SIGCHLD,
	 * it resumes the system call after processing the signal (resulting in unnecessary latency).
	 * Calling nanosleep in a loop avoids this problem.
	 */
	struct timespec req = {0, 50000000}; // 0.05s
	int n;

	// wait 0.5s for the process to die
	for (n=0; n<10; n++) {
		if (waitpid (SubprocessPid, &(MyEventMachine->SubprocessExitStatus), WNOHANG) != 0) return;
		nanosleep (&req, NULL);
	}

	// send SIGTERM and wait another 1s
	kill (SubprocessPid, SIGTERM);
	for (n=0; n<20; n++) {
		nanosleep (&req, NULL);
		if (waitpid (SubprocessPid, &(MyEventMachine->SubprocessExitStatus), WNOHANG) != 0) return;
	}

	// send SIGKILL and wait another 5s
	kill (SubprocessPid, SIGKILL);
	for (n=0; n<100; n++) {
		nanosleep (&req, NULL);
		if (waitpid (SubprocessPid, &(MyEventMachine->SubprocessExitStatus), WNOHANG) != 0) return;
	}

	// still not dead, give up!
	throw std::runtime_error ("unable to reap subprocess");
}



/********************
PipeDescriptor::Read
********************/

void PipeDescriptor::Read()
{
	int sd = GetSocket();
	if (sd == INVALID_SOCKET) {
		assert (!bReadAttemptedAfterClose);
		bReadAttemptedAfterClose = true;
		return;
	}

	LastActivity = MyEventMachine->GetCurrentLoopTime();

	int total_bytes_read = 0;
	char readbuffer [16 * 1024];

	for (int i=0; i < 10; i++) {
		// Don't read just one buffer and then move on. This is faster
		// if there is a lot of incoming.
		// But don't read indefinitely. Give other sockets a chance to run.
		// NOTICE, we're reading one less than the buffer size.
		// That's so we can put a guard byte at the end of what we send
		// to user code.
		// Use read instead of recv, which on Linux gives a "socket operation
		// on nonsocket" error.
		

		int r = read (sd, readbuffer, sizeof(readbuffer) - 1);
		//cerr << "<R:" << r << ">";

		if (r > 0) {
			total_bytes_read += r;

			// Add a null-terminator at the the end of the buffer
			// that we will send to the callback.
			// DO NOT EVER CHANGE THIS. We want to explicitly allow users
			// to be able to depend on this behavior, so they will have
			// the option to do some things faster. Additionally it's
			// a security guard against buffer overflows.
			readbuffer [r] = 0;
			_GenericInboundDispatch(readbuffer, r);
			}
		else if (r == 0) {
			break;
		}
		else {
			// Basically a would-block, meaning we've read everything there is to read.
			break;
		}

	}


	if (total_bytes_read == 0) {
		// If we read no data on a socket that selected readable,
		// it generally means the other end closed the connection gracefully.
		ScheduleClose (false);
		//bCloseNow = true;
	}

}

/*********************
PipeDescriptor::Write
*********************/

void PipeDescriptor::Write()
{
	int sd = GetSocket();
	assert (sd != INVALID_SOCKET);

	LastActivity = MyEventMachine->GetCurrentLoopTime();
	char output_buffer [16 * 1024];
	size_t nbytes = 0;

	while ((OutboundPages.size() > 0) && (nbytes < sizeof(output_buffer))) {
		OutboundPage *op = &(OutboundPages[0]);
		if ((nbytes + op->Length - op->Offset) < sizeof (output_buffer)) {
			memcpy (output_buffer + nbytes, op->Buffer + op->Offset, op->Length - op->Offset);
			nbytes += (op->Length - op->Offset);
			op->Free();
			OutboundPages.pop_front();
		}
		else {
			int len = sizeof(output_buffer) - nbytes;
			memcpy (output_buffer + nbytes, op->Buffer + op->Offset, len);
			op->Offset += len;
			nbytes += len;
		}
	}

	// We should never have gotten here if there were no data to write,
	// so assert that as a sanity check.
	// Don't bother to make sure nbytes is less than output_buffer because
	// if it were we probably would have crashed already.
	assert (nbytes > 0);

	assert (GetSocket() != INVALID_SOCKET);
	int bytes_written = write (GetSocket(), output_buffer, nbytes);

	if (bytes_written > 0) {
		OutboundDataSize -= bytes_written;
		if ((size_t)bytes_written < nbytes) {
			int len = nbytes - bytes_written;
			char *buffer = (char*) malloc (len + 1);
			if (!buffer)
				throw std::runtime_error ("bad alloc throwing back data");
			memcpy (buffer, output_buffer + bytes_written, len);
			buffer [len] = 0;
			OutboundPages.push_front (OutboundPage (buffer, len));
		}
		#ifdef HAVE_EPOLL
		EpollEvent.events = (EPOLLIN | (SelectForWrite() ? EPOLLOUT : 0));
		assert (MyEventMachine);
		MyEventMachine->Modify (this);
		#endif
	}
	else {
		#ifdef OS_UNIX
		if ((errno != EINPROGRESS) && (errno != EWOULDBLOCK) && (errno != EINTR))
		#endif
		#ifdef OS_WIN32
		if ((errno != WSAEINPROGRESS) && (errno != WSAEWOULDBLOCK))
		#endif
			Close();
	}
}


/*************************
PipeDescriptor::Heartbeat
*************************/

void PipeDescriptor::Heartbeat()
{
	// If an inactivity timeout is defined, then check for it.
	if (InactivityTimeout && ((MyEventMachine->GetCurrentLoopTime() - LastActivity) >= InactivityTimeout))
		ScheduleClose (false);
		//bCloseNow = true;
}


/*****************************
PipeDescriptor::SelectForRead
*****************************/

bool PipeDescriptor::SelectForRead()
{
	/* Pipe descriptors, being local by definition, don't have
	 * a pending state, so this is simpler than for the
	 * ConnectionDescriptor object.
	 */
	return bPaused ? false : true;
}

/******************************
PipeDescriptor::SelectForWrite
******************************/

bool PipeDescriptor::SelectForWrite()
{
	/* Pipe descriptors, being local by definition, don't have
	 * a pending state, so this is simpler than for the
	 * ConnectionDescriptor object.
	 */
	return (GetOutboundDataSize() > 0) && !bPaused ? true : false;
}




/********************************
PipeDescriptor::SendOutboundData
********************************/

int PipeDescriptor::SendOutboundData (const char *data, int length)
{
	//if (bCloseNow || bCloseAfterWriting)
	if (IsCloseScheduled())
		return 0;

	if (!data && (length > 0))
		throw std::runtime_error ("bad outbound data");
	char *buffer = (char *) malloc (length + 1);
	if (!buffer)
		throw std::runtime_error ("no allocation for outbound data");
	memcpy (buffer, data, length);
	buffer [length] = 0;
	OutboundPages.push_back (OutboundPage (buffer, length));
	OutboundDataSize += length;
	#ifdef HAVE_EPOLL
	EpollEvent.events = (EPOLLIN | EPOLLOUT);
	assert (MyEventMachine);
	MyEventMachine->Modify (this);
	#endif
	return length;
}

/********************************
PipeDescriptor::GetSubprocessPid
********************************/

bool PipeDescriptor::GetSubprocessPid (pid_t *pid)
{
	bool ok = false;
	if (pid && (SubprocessPid > 0)) {
		*pid = SubprocessPid;
		ok = true;
	}
	return ok;
}


#endif // OS_UNIX

