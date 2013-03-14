/*****************************************************************************

$Id$

File:     ed.h
Date:     06Apr06

Copyright (C) 2006-07 by Francis Cianfrocca. All Rights Reserved.
Gmail: blackhedd

This program is free software; you can redistribute it and/or modify
it under the terms of either: 1) the GNU General Public License
as published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version; or 2) Ruby's License.

See the file COPYING for complete licensing information.

*****************************************************************************/

#ifndef __EventableDescriptor__H_
#define __EventableDescriptor__H_


class EventMachine_t; // forward reference
#ifdef WITH_SSL
class SslBox_t; // forward reference
#endif

bool SetSocketNonblocking (SOCKET);


/*************************
class EventableDescriptor
*************************/

class EventableDescriptor: public Bindable_t
{
	public:
		EventableDescriptor (int, EventMachine_t*);
		virtual ~EventableDescriptor();

		int GetSocket() {return MySocket;}
		void SetSocketInvalid() { MySocket = INVALID_SOCKET; }
		void Close();

		virtual void Read() = 0;
		virtual void Write() = 0;
		virtual void Heartbeat() = 0;

		// These methods tell us whether the descriptor
		// should be selected or polled for read/write.
		virtual bool SelectForRead() = 0;
		virtual bool SelectForWrite() = 0;

		// are we scheduled for a close, or in an error state, or already closed?
		bool ShouldDelete();
		// Do we have any data to write? This is used by ShouldDelete.
		virtual int GetOutboundDataSize() {return 0;}
		virtual bool IsWatchOnly(){ return bWatchOnly; }

		virtual void ScheduleClose (bool after_writing);
		bool IsCloseScheduled();
		virtual void HandleError(){ ScheduleClose (false); }

		void SetEventCallback (EMCallback);

		virtual bool GetPeername (struct sockaddr*, socklen_t*) {return false;}
		virtual bool GetSockname (struct sockaddr*, socklen_t*) {return false;}
		virtual bool GetSubprocessPid (pid_t*) {return false;}

		virtual void StartTls() {}
		virtual void SetTlsParms (const char *privkey_filename, const char *certchain_filename, bool verify_peer) {}

		#ifdef WITH_SSL
		virtual X509 *GetPeerCert() {return NULL;}
		#endif

		virtual uint64_t GetCommInactivityTimeout() {return 0;}
		virtual int SetCommInactivityTimeout (uint64_t value) {return 0;}
		uint64_t GetPendingConnectTimeout();
		int SetPendingConnectTimeout (uint64_t value);
		uint64_t GetLastActivity() { return LastActivity; }

		#ifdef HAVE_EPOLL
		struct epoll_event *GetEpollEvent() { return &EpollEvent; }
		#endif

		virtual void StartProxy(const unsigned long, const unsigned long, const unsigned long);
		virtual void StopProxy();
		virtual unsigned long GetProxiedBytes(){ return ProxiedBytes; };
		virtual void SetProxiedFrom(EventableDescriptor*, const unsigned long);
		virtual int SendOutboundData(const char*,int){ return -1; }
		virtual bool IsPaused(){ return bPaused; }
		virtual bool Pause(){ bPaused = true; return bPaused; }
		virtual bool Resume(){ bPaused = false; return bPaused; }

		void SetUnbindReasonCode(int code){ UnbindReasonCode = code; }
		virtual int ReportErrorStatus(){ return 0; }
		virtual bool IsConnectPending(){ return false; }
		virtual uint64_t GetNextHeartbeat();

	private:
		bool bCloseNow;
		bool bCloseAfterWriting;

	protected:
		int MySocket;
		bool bAttached;
		bool bWatchOnly;

		EMCallback EventCallback;
		void _GenericInboundDispatch(const char*, int);

		uint64_t CreatedAt;
		bool bCallbackUnbind;
		int UnbindReasonCode;

		unsigned long BytesToProxy;
		EventableDescriptor *ProxyTarget;
		EventableDescriptor *ProxiedFrom;
		unsigned long ProxiedBytes;

		unsigned long MaxOutboundBufSize;

		#ifdef HAVE_EPOLL
		struct epoll_event EpollEvent;
		#endif

		EventMachine_t *MyEventMachine;
		uint64_t PendingConnectTimeout;
		uint64_t InactivityTimeout;
		uint64_t LastActivity;
		uint64_t NextHeartbeat;
		bool bPaused;
};



/*************************
class LoopbreakDescriptor
*************************/

class LoopbreakDescriptor: public EventableDescriptor
{
	public:
		LoopbreakDescriptor (int, EventMachine_t*);
		virtual ~LoopbreakDescriptor() {}

		virtual void Read();
		virtual void Write();
		virtual void Heartbeat() {}

		virtual bool SelectForRead() {return true;}
		virtual bool SelectForWrite() {return false;}
};


/**************************
class ConnectionDescriptor
**************************/

class ConnectionDescriptor: public EventableDescriptor
{
	public:
		ConnectionDescriptor (int, EventMachine_t*);
		virtual ~ConnectionDescriptor();

		int SendOutboundData (const char*, int);

		void SetConnectPending (bool f);
		virtual void ScheduleClose (bool after_writing);
		virtual void HandleError();

		void SetNotifyReadable (bool);
		void SetNotifyWritable (bool);
		void SetAttached (bool);
		void SetWatchOnly (bool);

		bool Pause();
		bool Resume();

		bool IsNotifyReadable(){ return bNotifyReadable; }
		bool IsNotifyWritable(){ return bNotifyWritable; }

		virtual void Read();
		virtual void Write();
		virtual void Heartbeat();

		virtual bool SelectForRead();
		virtual bool SelectForWrite();

		// Do we have any data to write? This is used by ShouldDelete.
		virtual int GetOutboundDataSize() {return OutboundDataSize;}

		virtual void StartTls();
		virtual void SetTlsParms (const char *privkey_filename, const char *certchain_filename, bool verify_peer);

		#ifdef WITH_SSL
		virtual X509 *GetPeerCert();
		virtual bool VerifySslPeer(const char*);
		virtual void AcceptSslPeer();
		#endif

		void SetServerMode() {bIsServer = true;}

		virtual bool GetPeername (struct sockaddr*, socklen_t*);
		virtual bool GetSockname (struct sockaddr*, socklen_t*);

		virtual uint64_t GetCommInactivityTimeout();
		virtual int SetCommInactivityTimeout (uint64_t value);

		virtual int ReportErrorStatus();
		virtual bool IsConnectPending(){ return bConnectPending; }

	protected:
		struct OutboundPage {
			OutboundPage (const char *b, int l, int o=0): Buffer(b), Length(l), Offset(o) {}
			void Free() {if (Buffer) free ((char*)Buffer); }
			const char *Buffer;
			int Length;
			int Offset;
		};

	protected:
		bool bConnectPending;

		bool bNotifyReadable;
		bool bNotifyWritable;

		bool bReadAttemptedAfterClose;
		bool bWriteAttemptedAfterClose;

		deque<OutboundPage> OutboundPages;
		int OutboundDataSize;

		#ifdef WITH_SSL
		SslBox_t *SslBox;
		std::string CertChainFilename;
		std::string PrivateKeyFilename;
		bool bHandshakeSignaled;
		bool bSslVerifyPeer;
		bool bSslPeerAccepted;
		#endif

		#ifdef HAVE_KQUEUE
		bool bGotExtraKqueueEvent;
		#endif

		bool bIsServer;

	private:
		void _UpdateEvents();
		void _UpdateEvents(bool, bool);
		void _WriteOutboundData();
		void _DispatchInboundData (const char *buffer, int size);
		void _DispatchCiphertext();
		int _SendRawOutboundData (const char*, int);
		void _CheckHandshakeStatus();

};


/************************
class DatagramDescriptor
************************/

class DatagramDescriptor: public EventableDescriptor
{
	public:
		DatagramDescriptor (int, EventMachine_t*);
		virtual ~DatagramDescriptor();

		virtual void Read();
		virtual void Write();
		virtual void Heartbeat();

		virtual bool SelectForRead() {return true;}
		virtual bool SelectForWrite();

		int SendOutboundData (const char*, int);
		int SendOutboundDatagram (const char*, int, const char*, int);

		// Do we have any data to write? This is used by ShouldDelete.
		virtual int GetOutboundDataSize() {return OutboundDataSize;}

		virtual bool GetPeername (struct sockaddr*, socklen_t*);
		virtual bool GetSockname (struct sockaddr*, socklen_t*);

		virtual uint64_t GetCommInactivityTimeout();
		virtual int SetCommInactivityTimeout (uint64_t value);

	protected:
		struct OutboundPage {
			OutboundPage (const char *b, int l, struct sockaddr_in f, int o=0): Buffer(b), Length(l), Offset(o), From(f) {}
			void Free() {if (Buffer) free ((char*)Buffer); }
			const char *Buffer;
			int Length;
			int Offset;
			struct sockaddr_in From;
		};

		deque<OutboundPage> OutboundPages;
		int OutboundDataSize;

		struct sockaddr_in ReturnAddress;
};


/************************
class AcceptorDescriptor
************************/

class AcceptorDescriptor: public EventableDescriptor
{
	public:
		AcceptorDescriptor (int, EventMachine_t*);
		virtual ~AcceptorDescriptor();

		virtual void Read();
		virtual void Write();
		virtual void Heartbeat();

		virtual bool SelectForRead() {return true;}
		virtual bool SelectForWrite() {return false;}

		virtual bool GetSockname (struct sockaddr*, socklen_t*);

		static void StopAcceptor (const unsigned long binding);
};

/********************
class PipeDescriptor
********************/

#ifdef OS_UNIX
class PipeDescriptor: public EventableDescriptor
{
	public:
		PipeDescriptor (int, pid_t, EventMachine_t*);
		virtual ~PipeDescriptor();

		virtual void Read();
		virtual void Write();
		virtual void Heartbeat();

		virtual bool SelectForRead();
		virtual bool SelectForWrite();

		int SendOutboundData (const char*, int);
		virtual int GetOutboundDataSize() {return OutboundDataSize;}

		virtual bool GetSubprocessPid (pid_t*);

	protected:
		struct OutboundPage {
			OutboundPage (const char *b, int l, int o=0): Buffer(b), Length(l), Offset(o) {}
			void Free() {if (Buffer) free ((char*)Buffer); }
			const char *Buffer;
			int Length;
			int Offset;
		};

	protected:
		bool bReadAttemptedAfterClose;

		deque<OutboundPage> OutboundPages;
		int OutboundDataSize;

		pid_t SubprocessPid;

	private:
		void _DispatchInboundData (const char *buffer, int size);
};
#endif // OS_UNIX


/************************
class KeyboardDescriptor
************************/

class KeyboardDescriptor: public EventableDescriptor
{
	public:
		KeyboardDescriptor (EventMachine_t*);
		virtual ~KeyboardDescriptor();

		virtual void Read();
		virtual void Write();
		virtual void Heartbeat();

		virtual bool SelectForRead() {return true;}
		virtual bool SelectForWrite() {return false;}

	protected:
		bool bReadAttemptedAfterClose;

	private:
		void _DispatchInboundData (const char *buffer, int size);
};


/***********************
class InotifyDescriptor
************************/

class InotifyDescriptor: public EventableDescriptor
{
	public:
		InotifyDescriptor (EventMachine_t*);
		virtual ~InotifyDescriptor();

		void Read();
		void Write();

		virtual void Heartbeat() {}
		virtual bool SelectForRead() {return true;}
		virtual bool SelectForWrite() {return false;}
};

#endif // __EventableDescriptor__H_


