#include "ruby.h"

#ifndef RUBY_19
#include "rubysig.h"
#endif

#include "netifaces.h"

#if !defined(WIN32)
#if  !HAVE_GETNAMEINFO
#undef getnameinfo
#undef NI_NUMERICHOST

#define getnameinfo our_getnameinfo
#define NI_NUMERICHOST 1

/* A very simple getnameinfo() for platforms without */
static int
getnameinfo (const struct sockaddr *addr, int addr_len,
             char *buffer, int buflen,
             char *buf2, int buf2len,
             int flags)
{
	switch (addr->sa_family) 
	{
	case AF_INET:
	{
		const struct sockaddr_in *sin = (struct sockaddr_in *)addr;
		const unsigned char *bytes = (unsigned char *)&sin->sin_addr.s_addr;
		char tmpbuf[20];

		sprintf (tmpbuf, "%d.%d.%d.%d",
		       bytes[0], bytes[1], bytes[2], bytes[3]);

		strncpy (buffer, tmpbuf, buflen);
	}
	break;
#ifdef AF_INET6
	case AF_INET6:
	{
		const struct sockaddr_in6 *sin = (const struct sockaddr_in6 *)addr;
		const unsigned char *bytes = sin->sin6_addr.s6_addr;
		int n;
		char tmpbuf[80], *ptr = tmpbuf;
		int done_double_colon = FALSE;
		int colon_mode = FALSE;

		for (n = 0; n < 8; ++n) 
		{
			unsigned char b1 = bytes[2 * n];
			unsigned char b2 = bytes[2 * n + 1];

			if (b1) 
			{
		  		if (colon_mode) 
				{
					colon_mode = FALSE;
					*ptr++ = ':';
		  		}
		  	sprintf (ptr, "%x%02x", b1, b2);
		  	ptr += strlen (ptr);
		  	*ptr++ = ':';
			} 
			else if (b2) 
			{
			  	if (colon_mode) 
				{
				    colon_mode = FALSE;
				    *ptr++ = ':';
				}
				sprintf (ptr, "%x", b2);
				ptr += strlen (ptr);
				*ptr++ = ':';
			} 
			else {
		  		if (!colon_mode) 
				{
		    			if (done_double_colon) 
					{
						*ptr++ = '0';
						*ptr++ = ':';
		    			} 
					else 
					{
		      				if (n == 0)
						*ptr++ = ':';
		      				colon_mode = TRUE;
		      				done_double_colon = TRUE;
		    			}
		  		}
			}
		}
		if (colon_mode) 
		{
			colon_mode = FALSE;
			*ptr++ = ':';
			*ptr++ = '\0';
		} 
		else 
		{
			*--ptr = '\0';
		}

		strncpy (buffer, tmpbuf, buflen);
	}
	break;
#endif /* AF_INET6 */
  	default:
    		return -1;
  }

	return 0;
}
#endif

static int
string_from_sockaddr (struct sockaddr *addr,
                      char *buffer,
                      int buflen)
{
	if (!addr || addr->sa_family == AF_UNSPEC)
    		return -1;

  	if (getnameinfo (addr, SA_LEN(addr),
                   buffer, buflen,
                   NULL, 0,
                   NI_NUMERICHOST) != 0) 
	{
    		int n, len;
		char *ptr;
		const char *data;

		len = SA_LEN(addr);

#if HAVE_AF_LINK
	/* BSD-like systems have AF_LINK */
		if (addr->sa_family == AF_LINK) 
		{
			struct sockaddr_dl *dladdr = (struct sockaddr_dl *)addr;
			len = dladdr->sdl_alen;
			if(len >=0)
				data = LLADDR(dladdr);
		} 
		else 
		{
#endif
#if defined(AF_PACKET)
      /* Linux has AF_PACKET instead */
		if (addr->sa_family == AF_PACKET) 
		{
			struct sockaddr_ll *lladdr = (struct sockaddr_ll *)addr;
			len = lladdr->sll_halen;
			//amaloteaux: openbsd and maybe other systems have a len of 0 for enc0,pflog0 .. interfaces
			if(len >=0)
				data = (const char *)lladdr->sll_addr;
		} 	
		else 
		{
#endif
			/* We don't know anything about this sockaddr, so just display
			   the entire data area in binary. */
			len -= (sizeof (struct sockaddr) - sizeof (addr->sa_data));
			data = addr->sa_data;
#if defined(AF_PACKET)
		}
#endif
#if HAVE_AF_LINK
		}
#endif

		if ((buflen < 3 * len) || len <= 0)
			return -1;

		ptr = buffer;
		buffer[0] = '\0';

		for (n = 0; n < len; ++n) 
		{
			sprintf (ptr, "%02x:", data[n] & 0xff);
			ptr += 3;
		}
		*--ptr = '\0';
	}

  	return 0;
}
#endif /* !defined(WIN32) */

static VALUE add_to_family(VALUE result, VALUE family, VALUE value)
{
	Check_Type(result, T_HASH);
	Check_Type(family, T_FIXNUM);
	Check_Type(value, T_HASH);
	VALUE list;

	list = rb_hash_aref(result, family);

	if (list == Qnil)
		list = rb_ary_new();
	else
		Check_Type(list, T_ARRAY);

	rb_ary_push(list, value);
	rb_hash_aset(result, family, list);
	return result;
}

VALUE
rbnetifaces_s_addresses (VALUE class, VALUE dev)
{
	Check_Type(dev, T_STRING);

	VALUE result;
	int found = FALSE;
	result = rb_hash_new();
	
#if defined(WIN32)
	PIP_ADAPTER_INFO pAdapterInfo = NULL;
	PIP_ADAPTER_INFO pInfo = NULL;
	ULONG ulBufferLength = 0;
	DWORD dwRet;
	PIP_ADDR_STRING str;

	//First, retrieve the adapter information.  We do this in a loop, in
  //case someone adds or removes adapters in the meantime. 
	do 
	{
		dwRet = GetAdaptersInfo(pAdapterInfo, &ulBufferLength);

		if (dwRet == ERROR_BUFFER_OVERFLOW) 
		{
			if (pAdapterInfo)
				free (pAdapterInfo);
			pAdapterInfo = (PIP_ADAPTER_INFO)malloc (ulBufferLength);

			if (!pAdapterInfo) 
			{
				rb_raise(rb_eRuntimeError, "Unknow error at OS level");
				return Qnil;
		}
    }
  } while (dwRet == ERROR_BUFFER_OVERFLOW);

	// If we failed, then fail in Ruby too 
	if (dwRet != ERROR_SUCCESS && dwRet != ERROR_NO_DATA) 
	{
		if (pAdapterInfo)
			free (pAdapterInfo);
		rb_raise(rb_eRuntimeError, "Unable to obtain adapter information.");
		return Qnil;
	}

	for (pInfo = pAdapterInfo; pInfo; pInfo = pInfo->Next) 
	{
		char buffer[256];
		//dev is the iface GUID on windows with "\\Device\\NPF_" prefix
		int cmpAdapterNamelen = (MAX_ADAPTER_NAME_LENGTH + 4) + 12;
		char cmpAdapterName[cmpAdapterNamelen];
		memset(cmpAdapterName, 0x00, cmpAdapterNamelen);
		strncpy(cmpAdapterName, "\\Device\\NPF_", 12);
		int AdapterName_len = strlen(pInfo->AdapterName);
		strncpy(cmpAdapterName + 12, pInfo->AdapterName, AdapterName_len);
		if (strcmp (cmpAdapterName, StringValuePtr(dev)) != 0)
			continue;

		VALUE rbhardw = Qnil;
		VALUE rbaddr = Qnil;	
		VALUE rbnetmask = Qnil;
		VALUE rbbraddr = Qnil;
	
		found = TRUE;

		// Do the physical address 
		if (256 >= 3 * pInfo->AddressLength) 
		{
			VALUE hash_hardw;
			hash_hardw = rb_hash_new();

			char *ptr = buffer;
			unsigned n;
		  
			*ptr = '\0';
			for (n = 0; n < pInfo->AddressLength; ++n) 
			{
				sprintf (ptr, "%02x:", pInfo->Address[n] & 0xff);
				ptr += 3;
			}
			*--ptr = '\0';

			rbhardw = rb_str_new2(buffer);
			rb_hash_aset(hash_hardw, rb_str_new2("addr"), rbhardw);
			result = add_to_family(result, INT2FIX(AF_LINK), hash_hardw);
		}

		for (str = &pInfo->IpAddressList; str; str = str->Next) 
		{
			
			VALUE result2;
			result2 = rb_hash_new();
				
			if(str->IpAddress.String)
				rbaddr = rb_str_new2(str->IpAddress.String);
			if(str->IpMask.String)
				rbnetmask = rb_str_new2(str->IpMask.String);
			
			//If this isn't the loopback interface, work out the broadcast
			//address, for better compatibility with other platforms. 
			if (pInfo->Type != MIB_IF_TYPE_LOOPBACK) 
			{
				unsigned long inaddr = inet_addr (str->IpAddress.String);
				unsigned long inmask = inet_addr (str->IpMask.String);
				struct in_addr in;
				char *brstr;

				in.S_un.S_addr = (inaddr | ~inmask) & 0xfffffffful;

				brstr = inet_ntoa (in);

				if (brstr)
					rbbraddr = rb_str_new2(brstr);
			}

			if (rbaddr)
				rb_hash_aset(result2, rb_str_new2("addr"), rbaddr);
			if (rbnetmask)
				rb_hash_aset(result2, rb_str_new2("netmask"), rbnetmask);
			if (rbbraddr)
				rb_hash_aset(result2, rb_str_new2("broadcast"), rbbraddr);
		
			result = add_to_family(result, INT2FIX(AF_INET), result2);
				
		}
	} // for

	free (pAdapterInfo);

#elif HAVE_GETIFADDRS
	struct ifaddrs *addrs = NULL;
	struct ifaddrs *addr = NULL;

	if (getifaddrs (&addrs) < 0) 
	{
		rb_raise(rb_eRuntimeError, "Unknow error at OS level");
  	}

  	for (addr = addrs; addr; addr = addr->ifa_next) 
	{
		char buffer[256];
		VALUE rbaddr = Qnil;
		VALUE rbnetmask = Qnil;
		VALUE rbbraddr = Qnil;

		if (strcmp (addr->ifa_name, StringValuePtr(dev)) != 0)
			continue;
	 
		/* Sometimes there are records without addresses (e.g. in the case of a
		dial-up connection via ppp, which on Linux can have a link address
		record with no actual address).  We skip these as they aren't useful.
		Thanks to Christian Kauhaus for reporting this issue. */
		if (!addr->ifa_addr)
			continue;  

		found = TRUE;

		if (string_from_sockaddr (addr->ifa_addr, buffer, sizeof (buffer)) == 0)
			rbaddr = rb_str_new2(buffer);

		if (string_from_sockaddr (addr->ifa_netmask, buffer, sizeof (buffer)) == 0)
			rbnetmask = rb_str_new2(buffer);

		if (string_from_sockaddr (addr->ifa_broadaddr, buffer, sizeof (buffer)) == 0)
			rbbraddr = rb_str_new2(buffer);

		VALUE result2;
		result2 = rb_hash_new();

		if (rbaddr)
			rb_hash_aset(result2, rb_str_new2("addr"), rbaddr);
		if (rbnetmask)
			rb_hash_aset(result2, rb_str_new2("netmask"), rbnetmask);
		if (rbbraddr) 
		{
			if (addr->ifa_flags & (IFF_POINTOPOINT | IFF_LOOPBACK))
				rb_hash_aset(result2, rb_str_new2("peer"), rbbraddr);
			else
				rb_hash_aset(result2, rb_str_new2("broadcast"), rbbraddr);
		}
		if (rbaddr || rbnetmask || rbbraddr)
			result = add_to_family(result, INT2FIX(addr->ifa_addr->sa_family), result2);
	}
  	freeifaddrs (addrs);
#elif HAVE_SOCKET_IOCTLS

	int sock = socket(AF_INET, SOCK_DGRAM, 0);

	if (sock < 0) 
	{
	    	rb_raise(rb_eRuntimeError, "Unknow error at OS level");
		return Qnil;
	}

	struct CNAME(ifreq) ifr;
	
	char buffer[256];
	int is_p2p = FALSE;
	VALUE rbaddr = Qnil;
	VALUE rbnetmask = Qnil;
	VALUE rbbraddr = Qnil;
	VALUE rbdstaddr = Qnil;

	strncpy (ifr.CNAME(ifr_name), StringValuePtr(dev), IFNAMSIZ);

#if HAVE_SIOCGIFHWADDR
	if (ioctl (sock, SIOCGIFHWADDR, &ifr) == 0) 
	{
		if (string_from_sockaddr (&(ifr.CNAME(ifr_addr)), buffer, sizeof (buffer)) == 0) 
		{
			found = TRUE;

			VALUE rbhardw = Qnil;
			VALUE hash_hardw;
			hash_hardw = rb_hash_new();
			rbhardw = rb_str_new2(buffer);
			rb_hash_aset(hash_hardw, rb_str_new2("addr"), rbhardw);
			result = add_to_family(result, INT2FIX(AF_LINK), hash_hardw);
		}
	}
#endif


#if HAVE_SIOCGIFADDR
#if HAVE_SIOCGLIFNUM
	if (ioctl (sock, SIOCGLIFADDR, &ifr) == 0) 
	{
#else
	if (ioctl (sock, SIOCGIFADDR, &ifr) == 0) 
	{
#endif
		if (string_from_sockaddr ((struct sockaddr *)&ifr.CNAME(ifr_addr), buffer, sizeof (buffer)) == 0)
		{
			found = TRUE;
	      		rbaddr = rb_str_new2(buffer);
		}
  	}
#endif

#if HAVE_SIOCGIFNETMASK
#if HAVE_SIOCGLIFNUM
	if (ioctl (sock, SIOCGLIFNETMASK, &ifr) == 0) 
	{
#else
  	if (ioctl (sock, SIOCGIFNETMASK, &ifr) == 0) 
	{
#endif
		if (string_from_sockaddr ((struct sockaddr *)&ifr.CNAME(ifr_addr), buffer, sizeof (buffer)) == 0)
		{
			found = TRUE;
			rbnetmask = rb_str_new2(buffer);
		}
	}
#endif

#if HAVE_SIOCGIFFLAGS
#if HAVE_SIOCGLIFNUM
	if (ioctl (sock, SIOCGLIFFLAGS, &ifr) == 0) 
	{
#else
	if (ioctl (sock, SIOCGIFFLAGS, &ifr) == 0) 
	{
#endif

		if (ifr.CNAME(ifr_flags) & IFF_POINTOPOINT)
		{
			is_p2p = TRUE;
		}
  	}
#endif

#if HAVE_SIOCGIFBRDADDR
#if HAVE_SIOCGLIFNUM
	if (!is_p2p && ioctl (sock, SIOCGLIFBRDADDR, &ifr) == 0) 
	{
#else
	if (!is_p2p && ioctl (sock, SIOCGIFBRDADDR, &ifr) == 0) 
	{
#endif


		if (string_from_sockaddr ((struct sockaddr *)&ifr.CNAME(ifr_addr), buffer, sizeof (buffer)) == 0)
		{
	    		found = TRUE;
			rbbraddr = rb_str_new2(buffer);
		}
  	}
#endif

#if HAVE_SIOCGIFDSTADDR
#if HAVE_SIOCGLIFNUM
	if (is_p2p && ioctl (sock, SIOCGLIFBRDADDR, &ifr) == 0) 
	{
#else
	if (is_p2p && ioctl (sock, SIOCGIFBRDADDR, &ifr) == 0) 
	{
#endif
		if (string_from_sockaddr ((struct sockaddr *)&ifr.CNAME(ifr_addr), buffer, sizeof (buffer)) == 0)
		{
			found = TRUE;
      			rbdstaddr = rb_str_new2(buffer);
		}
	}

#endif
	VALUE result2;
	result2 = rb_hash_new();

	if (rbaddr)
		rb_hash_aset(result2, rb_str_new2("addr"), rbaddr);
	if (rbnetmask)
		rb_hash_aset(result2, rb_str_new2("netmask"), rbnetmask);
	if (rbbraddr) 
		rb_hash_aset(result2, rb_str_new2("broadcast"), rbbraddr);
  	if (rbdstaddr)
		rb_hash_aset(result2, rb_str_new2("peer"), rbbraddr);

	if (rbaddr || rbnetmask || rbbraddr || rbdstaddr)
		result = add_to_family(result, INT2FIX(AF_INET), result2);

	close (sock);
#endif /* HAVE_SOCKET_IOCTLS */

	if (found)
		return result;
	else
		return Qnil;

}

VALUE
rbnetifaces_s_interfaces (VALUE self)
{
  	VALUE result;
	result = rb_ary_new();

#if defined(WIN32)
	PIP_ADAPTER_INFO pAdapterInfo = NULL;
	PIP_ADAPTER_INFO pInfo = NULL;
	ULONG ulBufferLength = 0;
	DWORD dwRet;

	// First, retrieve the adapter information 
	do {
		dwRet = GetAdaptersInfo(pAdapterInfo, &ulBufferLength);

		if (dwRet == ERROR_BUFFER_OVERFLOW) 
		{
			if (pAdapterInfo)
			free (pAdapterInfo);
			pAdapterInfo = (PIP_ADAPTER_INFO)malloc (ulBufferLength);

			if (!pAdapterInfo) 
			{
				rb_raise(rb_eRuntimeError, "Unknow error at OS level");
			}
    	}
  	} while (dwRet == ERROR_BUFFER_OVERFLOW);

	// If we failed, then fail in Ruby too 
	if (dwRet != ERROR_SUCCESS && dwRet != ERROR_NO_DATA) 
	{
		if (pAdapterInfo)
			free (pAdapterInfo);

    	rb_raise(rb_eRuntimeError, "Unknow error at OS level");
   	 	return Qnil;
	}
	if (dwRet == ERROR_NO_DATA) 
	{
		free (pAdapterInfo);
		return result;
	}

	for (pInfo = pAdapterInfo; pInfo; pInfo = pInfo->Next) 
	{
		int outputnamelen = (MAX_ADAPTER_NAME_LENGTH + 4) + 12;
		char outputname[outputnamelen];
		memset(outputname, 0x00, outputnamelen);
		strncpy(outputname, "\\Device\\NPF_", 12);
		int AdapterName_len = strlen(pInfo->AdapterName);
		strncpy(outputname + 12, pInfo->AdapterName, AdapterName_len);
		VALUE ifname =  rb_str_new2(outputname) ;

		if(!rb_ary_includes(result, ifname))
			rb_ary_push(result, ifname);
	}

	free (pAdapterInfo);

#elif HAVE_GETIFADDRS
	const char *prev_name = NULL;
	struct ifaddrs *addrs = NULL;
	struct ifaddrs *addr = NULL;

	if (getifaddrs (&addrs) < 0) 
	{
		rb_raise(rb_eRuntimeError, "Unknow error at OS level");
	}

	for (addr = addrs; addr; addr = addr->ifa_next) 
	{
		if (!prev_name || strncmp (addr->ifa_name, prev_name, IFNAMSIZ) != 0) 
		{
			VALUE ifname =  rb_str_new2(addr->ifa_name);

		if(!rb_ary_includes(result, ifname))
			rb_ary_push(result, ifname);

		prev_name = addr->ifa_name;
		}
	}

	freeifaddrs (addrs);
#elif HAVE_SIOCGIFCONF

	const char *prev_name = NULL;
	int fd = socket (AF_INET, SOCK_DGRAM, 0);
	struct CNAME(ifconf) ifc;
	int len = -1, n;
	if (fd < 0) {
		rb_raise(rb_eRuntimeError, "Unknow error at OS level");
		return Qnil;
	}

  // Try to find out how much space we need
#if HAVE_SIOCGSIZIFCONF
	if (ioctl (fd, SIOCGSIZIFCONF, &len) < 0)
		len = -1;
#elif HAVE_SIOCGLIFNUM
#error This code need to be checked first
/*
	{ struct lifnum lifn;
	lifn.lifn_family = AF_UNSPEC;
	lifn.lifn_flags = LIFC_NOXMIT | LIFC_TEMPORARY | LIFC_ALLZONES;
	ifc.lifc_family = AF_UNSPEC;
	ifc.lifc_flags = LIFC_NOXMIT | LIFC_TEMPORARY | LIFC_ALLZONES;
	if (ioctl (fd, SIOCGLIFNUM, (char *)&lifn) < 0)
		len = -1;
	else
		len = lifn.lifn_count;
	}
*/
#endif

	// As a last resort, guess
	if (len < 0)
	len = 64;

	ifc.CNAME(ifc_len) = len * sizeof (struct CNAME(ifreq));
	ifc.CNAME(ifc_buf) = malloc (ifc.CNAME(ifc_len));

	if (!ifc.CNAME(ifc_buf)) {
		close (fd);
		rb_raise(rb_eRuntimeError, "Not enough memory");
		return Qnil;
	  }

#if HAVE_SIOCGLIFNUM
	if (ioctl (fd, SIOCGLIFCONF, &ifc) < 0) {
#else
	if (ioctl (fd, SIOCGIFCONF, &ifc) < 0) {

#endif
		free (ifc.CNAME(ifc_req));
		close (fd);
		rb_raise(rb_eRuntimeError, "Unknow error at OS level");
		return Qnil;
	}

	struct CNAME(ifreq) *pfreq = ifc.CNAME(ifc_req);

	for (n = 0; n < ifc.CNAME(ifc_len)/sizeof(struct CNAME(ifreq));n++,pfreq++) 
	{
		if (!prev_name || strncmp (prev_name, pfreq->CNAME(ifr_name), IFNAMSIZ) != 0) 
		{
			VALUE ifname =  rb_str_new2(pfreq->CNAME(ifr_name));
			if(!rb_ary_includes(result, ifname))
				rb_ary_push(result, ifname);

			prev_name = pfreq->CNAME(ifr_name);
		}
	}

	free (ifc.CNAME(ifc_buf));
	close (fd);

#endif //

	return result;
}

//This function is usefull only under windows to retrieve some additionnal interfaces informations
VALUE
rbnetifaces_s_interface_info (VALUE self, VALUE dev)
{
	VALUE result = Qnil;
	
#if defined(WIN32)

	PIP_ADAPTER_INFO pAdapterInfo = NULL;
	PIP_ADAPTER_INFO pInfo = NULL;
	ULONG ulBufferLength = 0;
	DWORD dwRet;

	// First, retrieve the adapter information 
	do {
		dwRet = GetAdaptersInfo(pAdapterInfo, &ulBufferLength);

		if (dwRet == ERROR_BUFFER_OVERFLOW) 
		{
			if (pAdapterInfo)
			free (pAdapterInfo);
			pAdapterInfo = (PIP_ADAPTER_INFO)malloc (ulBufferLength);

			if (!pAdapterInfo) 
			{
				rb_raise(rb_eRuntimeError, "Unknow error at OS level");
			}
    	}
  	} while (dwRet == ERROR_BUFFER_OVERFLOW);

	// If we failed, then fail in Ruby too 
	if (dwRet != ERROR_SUCCESS && dwRet != ERROR_NO_DATA) 
	{
		if (pAdapterInfo)
			free (pAdapterInfo);

    	rb_raise(rb_eRuntimeError, "Unknow error at OS level");
   	 	return Qnil;
	}
	if (dwRet == ERROR_NO_DATA) 
	{
		free (pAdapterInfo);
		return result;
	}

	for (pInfo = pAdapterInfo; pInfo; pInfo = pInfo->Next) 
	{
		
		//dev is the iface GUID on windows with "\\Device\\NPF_" prefix
		int cmpAdapterNamelen = (MAX_ADAPTER_NAME_LENGTH + 4) + 12;
		char cmpAdapterName[cmpAdapterNamelen];
		memset(cmpAdapterName, 0x00, cmpAdapterNamelen);
		strncpy(cmpAdapterName, "\\Device\\NPF_", 12);
		int AdapterName_len = strlen(pInfo->AdapterName);
		strncpy(cmpAdapterName + 12, pInfo->AdapterName, AdapterName_len);
		if (strcmp (cmpAdapterName, StringValuePtr(dev)) != 0)
			continue;

		result = rb_hash_new();
		rb_hash_aset(result, rb_str_new2("description"), rb_str_new2(pInfo->Description));
		rb_hash_aset(result, rb_str_new2("guid"), rb_str_new2(pInfo->AdapterName));
		
		// Get the name from the registry
		const char* prefix = "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\";
		const char* sufix  = "\\Connection";
		int prefix_len = strlen(prefix);
		int sufix_len  = strlen(sufix);
		int adaptername_len = strlen(pInfo->AdapterName);
		char* keypath = NULL;
		keypath = malloc(prefix_len +  sufix_len + adaptername_len + 1);
		memset(keypath, 0x00, prefix_len +  sufix_len + adaptername_len + 1);
		strncpy(keypath, prefix, prefix_len);
		strncpy(keypath + prefix_len, pInfo->AdapterName, adaptername_len);
		strncpy(keypath + prefix_len + adaptername_len, sufix, sufix_len);
		
		HKEY hKey;   
		LONG lRet = 0;
		LPBYTE buffer = NULL;
		DWORD dwSize = 0;               
		if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, keypath, 0, KEY_READ, &hKey) == ERROR_SUCCESS)
		{
			// obtain current value size
			lRet = RegQueryValueEx(hKey, "Name", NULL, NULL, NULL, &dwSize);
			if (dwSize > 0 && ERROR_SUCCESS == lRet)
			{
				buffer = malloc((dwSize * sizeof(BYTE)) + 4);
				memset(buffer, 0x00, (dwSize * sizeof(BYTE)) + 4);
				lRet = RegQueryValueEx(hKey, "Name", NULL, NULL, buffer, &dwSize);
				if (ERROR_SUCCESS == lRet)
				{
					rb_hash_aset(result, rb_str_new2("name"), rb_str_new2(buffer));
				}
				else
				{
					rb_hash_aset(result, rb_str_new2("name"), rb_str_new2(""));
				}
				free(buffer);
			}
			else
			{
				rb_hash_aset(result, rb_str_new2("name"), rb_str_new2(""));
			}
			RegCloseKey(hKey);	
		}
		else
		{
			rb_hash_aset(result, rb_str_new2("name"), rb_str_new2(""));
		}
		free(keypath);
	} 
	free (pAdapterInfo);
#endif	
	
	return result;
}


