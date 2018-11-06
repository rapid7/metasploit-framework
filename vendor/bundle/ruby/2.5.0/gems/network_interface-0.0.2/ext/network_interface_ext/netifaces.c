#include "ruby.h"
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
      len -= (int)(sizeof (struct sockaddr) - sizeof (addr->sa_data));
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
  VALUE list;
  Check_Type(result, T_HASH);
  Check_Type(family, T_FIXNUM);
  Check_Type(value, T_HASH);

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
  VALUE result;
  int found = FALSE;
#if defined(WIN32)
  PIP_ADAPTER_INFO pAdapterInfo = NULL;
  PIP_ADAPTER_INFO pInfo = NULL;
  ULONG ulBufferLength = 0;
  DWORD dwRet;
  PIP_ADDR_STRING str;
#elif HAVE_GETIFADDRS
  struct ifaddrs *addrs = NULL;
  struct ifaddrs *addr = NULL;
  VALUE result2;
#elif HAVE_SOCKET_IOCTLS
  int sock;
  struct CNAME(ifreq) ifr;
  char buffer[256];
  int is_p2p = FALSE;
  VALUE rbaddr = Qnil;
  VALUE rbnetmask = Qnil;
  VALUE rbbraddr = Qnil;
  VALUE rbdstaddr = Qnil;
  VALUE result2;
#endif

  Check_Type(dev, T_STRING);
  result = rb_hash_new();

#if defined(WIN32)
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
    int AdapterName_len = strlen(pInfo->AdapterName);

    VALUE rbhardw = Qnil;
    VALUE rbaddr = Qnil;
    VALUE rbnetmask = Qnil;
    VALUE rbbraddr = Qnil;

    memset(cmpAdapterName, 0x00, cmpAdapterNamelen);
    strncpy(cmpAdapterName, "\\Device\\NPF_", 12);
    strncpy(cmpAdapterName + 12, pInfo->AdapterName, AdapterName_len);
    if (strcmp (cmpAdapterName, StringValuePtr(dev)) != 0)
      continue;

    found = TRUE;

    // Do the physical address
    if (256 >= 3 * pInfo->AddressLength)
    {
      char *ptr = buffer;
      unsigned n;
      VALUE hash_hardw;
      hash_hardw = rb_hash_new();

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

  sock = socket(AF_INET, SOCK_DGRAM, 0);

  if (sock < 0)
  {
        rb_raise(rb_eRuntimeError, "Unknow error at OS level");
    return Qnil;
  }

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
#if defined(WIN32)
  PIP_ADAPTER_INFO pAdapterInfo = NULL;
  PIP_ADAPTER_INFO pInfo = NULL;
  ULONG ulBufferLength = 0;
  DWORD dwRet;
#elif HAVE_GETIFADDRS
  const char *prev_name = NULL;
  struct ifaddrs *addrs = NULL;
  struct ifaddrs *addr = NULL;
#elif HAVE_SIOCGIFCONF
  const char *prev_name = NULL;
  int fd, len, n;
  struct CNAME(ifconf) ifc;
  struct CNAME(ifreq) *pfreq;
#endif

  result = rb_ary_new();

#if defined(WIN32)
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
    int AdapterName_len = strlen(pInfo->AdapterName);
    VALUE ifname;
    memset(outputname, 0x00, outputnamelen);
    strncpy(outputname, "\\Device\\NPF_", 12);
    strncpy(outputname + 12, pInfo->AdapterName, AdapterName_len);
    ifname =  rb_str_new2(outputname) ;

    if(!rb_ary_includes(result, ifname))
      rb_ary_push(result, ifname);
  }

  free (pAdapterInfo);

#elif HAVE_GETIFADDRS
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

  fd = socket (AF_INET, SOCK_DGRAM, 0);
  len = -1;
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

  pfreq = ifc.CNAME(ifc_req);

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
    // registry name location
    const char* prefix = "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\";
    const char* sufix  = "\\Connection";
    int prefix_len, sufix_len, adaptername_len;
    char* keypath = NULL;
    HKEY hKey;
    LONG lRet = 0;
    LPBYTE buffer = NULL;
    DWORD dwSize = 0;

    //dev is the iface GUID on windows with "\\Device\\NPF_" prefix
    int cmpAdapterNamelen = (MAX_ADAPTER_NAME_LENGTH + 4) + 12;
    char cmpAdapterName[cmpAdapterNamelen];
    int AdapterName_len = strlen(pInfo->AdapterName);
    memset(cmpAdapterName, 0x00, cmpAdapterNamelen);
    strncpy(cmpAdapterName, "\\Device\\NPF_", 12);
    strncpy(cmpAdapterName + 12, pInfo->AdapterName, AdapterName_len);
    if (strcmp (cmpAdapterName, StringValuePtr(dev)) != 0)
      continue;

    result = rb_hash_new();
    rb_hash_aset(result, rb_str_new2("description"), rb_str_new2(pInfo->Description));
    rb_hash_aset(result, rb_str_new2("guid"), rb_str_new2(pInfo->AdapterName));

    // Get the name from the registry
    prefix_len = strlen(prefix);
    sufix_len  = strlen(sufix);
    adaptername_len = strlen(pInfo->AdapterName);
    keypath = malloc(prefix_len +  sufix_len + adaptername_len + 1);
    memset(keypath, 0x00, prefix_len +  sufix_len + adaptername_len + 1);
    strncpy(keypath, prefix, prefix_len);
    strncpy(keypath + prefix_len, pInfo->AdapterName, adaptername_len);
    strncpy(keypath + prefix_len + adaptername_len, sufix, sufix_len);

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

VALUE rb_cNetworkInterface;
void
Init_network_interface_ext()
{
	rb_cNetworkInterface = rb_define_module("NetworkInterface");
	rb_define_module_function(rb_cNetworkInterface, "interfaces", rbnetifaces_s_interfaces, 0);
	rb_define_module_function(rb_cNetworkInterface, "addresses", rbnetifaces_s_addresses, 1);
	rb_define_module_function(rb_cNetworkInterface, "interface_info", rbnetifaces_s_interface_info, 1);
	
	//constants
	// Address families (auto-detect using #ifdef)

	#ifdef AF_INET
		rb_define_const(rb_cNetworkInterface, "AF_INET", INT2NUM(AF_INET));
	#endif
	#ifdef AF_INET6
		rb_define_const(rb_cNetworkInterface, "AF_INET6", INT2NUM(AF_INET6));
	#endif
	#ifdef AF_UNSPEC
		rb_define_const(rb_cNetworkInterface, "AF_UNSPEC", INT2NUM(AF_UNSPEC));
	#endif
	#ifdef AF_UNIX
		rb_define_const(rb_cNetworkInterface, "AF_UNIX", INT2NUM(AF_UNIX));
	#endif
	#ifdef AF_FILE
		rb_define_const(rb_cNetworkInterface, "AF_FILE", INT2NUM(AF_FILE));
	#endif
	#ifdef AF_AX25
		rb_define_const(rb_cNetworkInterface, "AF_AX25", INT2NUM(AF_AX25));
	#endif
	#ifdef AF_IMPLINK
		rb_define_const(rb_cNetworkInterface, "AF_IMPLINK", INT2NUM(AF_IMPLINK));
	#endif
	#ifdef AF_PUP
		rb_define_const(rb_cNetworkInterface, "AF_PUP", INT2NUM(AF_PUP));
	#endif
	#ifdef AF_CHAOS
		rb_define_const(rb_cNetworkInterface, "AF_CHAOS", INT2NUM(AF_CHAOS));
	#endif
	#ifdef AF_NS
		rb_define_const(rb_cNetworkInterface, "AF_NS", INT2NUM(AF_NS));
	#endif
	#ifdef AF_ISO
		rb_define_const(rb_cNetworkInterface, "AF_ISO", INT2NUM(AF_ISO));
	#endif
	#ifdef AF_ECMA
		rb_define_const(rb_cNetworkInterface, "AF_ECMA", INT2NUM(AF_ECMA));
	#endif
	#ifdef AF_DATAKIT
		rb_define_const(rb_cNetworkInterface, "AF_DATAKIT", INT2NUM(AF_DATAKIT));
	#endif
	#ifdef AF_CCITT
		rb_define_const(rb_cNetworkInterface, "AF_CCITT", INT2NUM(AF_CCITT));
	#endif
	#ifdef AF_SNA
		rb_define_const(rb_cNetworkInterface, "AF_SNA", INT2NUM(AF_SNA));
	#endif
	#ifdef AF_DECnet
		rb_define_const(rb_cNetworkInterface, "AF_DECnet", INT2NUM(AF_DECnet));
	#endif
	#ifdef AF_DLI
		rb_define_const(rb_cNetworkInterface, "AF_DLI", INT2NUM(AF_DLI));
	#endif
	#ifdef AF_LAT
		rb_define_const(rb_cNetworkInterface, "AF_LAT", INT2NUM(AF_LAT));
	#endif
	#ifdef AF_HYLINK
		rb_define_const(rb_cNetworkInterface, "AF_HYLINK", INT2NUM(AF_HYLINK));
	#endif
	#ifdef AF_APPLETALK
		rb_define_const(rb_cNetworkInterface, "AF_APPLETALK", INT2NUM(AF_APPLETALK));
	#endif
	#ifdef AF_ROUTE
		rb_define_const(rb_cNetworkInterface, "AF_ROUTE", INT2NUM(AF_ROUTE));
	#endif
	#ifdef AF_LINK
		rb_define_const(rb_cNetworkInterface, "AF_LINK", INT2NUM(AF_LINK));
	#endif
	#ifdef AF_PACKET
		rb_define_const(rb_cNetworkInterface, "AF_PACKET", INT2NUM(AF_PACKET));
	#endif
	#ifdef AF_COIP
		rb_define_const(rb_cNetworkInterface, "AF_COIP", INT2NUM(AF_COIP));
	#endif
	#ifdef AF_CNT
		rb_define_const(rb_cNetworkInterface, "AF_CNT", INT2NUM(AF_CNT));
	#endif
	#ifdef AF_IPX
		rb_define_const(rb_cNetworkInterface, "AF_IPX", INT2NUM(AF_IPX));
	#endif
	#ifdef AF_SIP
		rb_define_const(rb_cNetworkInterface, "AF_SIP", INT2NUM(AF_SIP));
	#endif
	#ifdef AF_NDRV
		rb_define_const(rb_cNetworkInterface, "AF_NDRV", INT2NUM(AF_NDRV));
	#endif
	#ifdef AF_ISDN
		rb_define_const(rb_cNetworkInterface, "AF_ISDN", INT2NUM(AF_ISDN));
	#endif
	#ifdef AF_NATM
		rb_define_const(rb_cNetworkInterface, "AF_NATM", INT2NUM(AF_NATM));
	#endif
	#ifdef AF_SYSTEM
		rb_define_const(rb_cNetworkInterface, "AF_SYSTEM", INT2NUM(AF_SYSTEM));
	#endif
	#ifdef AF_NETBIOS
		rb_define_const(rb_cNetworkInterface, "AF_NETBIOS", INT2NUM(AF_NETBIOS));
	#endif
	#ifdef AF_NETBEUI
		rb_define_const(rb_cNetworkInterface, "AF_NETBEUI", INT2NUM(AF_NETBEUI));
	#endif
	#ifdef AF_PPP
		rb_define_const(rb_cNetworkInterface, "AF_PPP", INT2NUM(AF_PPP));
	#endif
	#ifdef AF_ATM
		rb_define_const(rb_cNetworkInterface, "AF_ATM", INT2NUM(AF_ATM));
	#endif
	#ifdef AF_ATMPVC
		rb_define_const(rb_cNetworkInterface, "AF_ATMPVC", INT2NUM(AF_ATMPVC));
	#endif
	#ifdef AF_ATMSVC
		rb_define_const(rb_cNetworkInterface, "AF_ATMSVC", INT2NUM(AF_ATMSVC));
	#endif
	#ifdef AF_NETGRAPH
		rb_define_const(rb_cNetworkInterface, "AF_NETGRAPH", INT2NUM(AF_NETGRAPH));
	#endif
	#ifdef AF_VOICEVIEW
		rb_define_const(rb_cNetworkInterface, "AF_VOICEVIEW", INT2NUM(AF_VOICEVIEW));
	#endif
	#ifdef AF_FIREFOX
		rb_define_const(rb_cNetworkInterface, "AF_FIREFOX", INT2NUM(AF_FIREFOX));
	#endif
	#ifdef AF_UNKNOWN1
		rb_define_const(rb_cNetworkInterface, "AF_UNKNOWN1", INT2NUM(AF_UNKNOWN1));
	#endif
	#ifdef AF_BAN
		rb_define_const(rb_cNetworkInterface, "AF_BAN", INT2NUM(AF_BAN));
	#endif
	#ifdef AF_CLUSTER
		rb_define_const(rb_cNetworkInterface, "AF_CLUSTER", INT2NUM(AF_CLUSTER));
	#endif
	#ifdef AF_12844
		rb_define_const(rb_cNetworkInterface, "AF_12844", INT2NUM(AF_12844));
	#endif
	#ifdef AF_IRDA
		rb_define_const(rb_cNetworkInterface, "AF_IRDA", INT2NUM(AF_IRDA));
	#endif
	#ifdef AF_NETDES
		rb_define_const(rb_cNetworkInterface, "AF_NETDES", INT2NUM(AF_NETDES));
	#endif
	#ifdef AF_NETROM
		rb_define_const(rb_cNetworkInterface, "AF_NETROM", INT2NUM(AF_NETROM));
	#endif
	#ifdef AF_BRIDGE
		rb_define_const(rb_cNetworkInterface, "AF_BRIDGE", INT2NUM(AF_BRIDGE));
	#endif
	#ifdef AF_X25
		rb_define_const(rb_cNetworkInterface, "AF_X25", INT2NUM(AF_X25));
	#endif
	#ifdef AF_ROSE
		rb_define_const(rb_cNetworkInterface, "AF_ROSE", INT2NUM(AF_ROSE));
	#endif
	#ifdef AF_SECURITY
		rb_define_const(rb_cNetworkInterface, "AF_SECURITY", INT2NUM(AF_SECURITY));
	#endif
	#ifdef AF_KEY
		rb_define_const(rb_cNetworkInterface, "AF_KEY", INT2NUM(AF_KEY));
	#endif
	#ifdef AF_NETLINK
		rb_define_const(rb_cNetworkInterface, "AF_NETLINK", INT2NUM(AF_NETLINK));
	#endif
	#ifdef AF_ASH
		rb_define_const(rb_cNetworkInterface, "AF_ASH", INT2NUM(AF_ASH));
	#endif
	#ifdef AF_ECONET
		rb_define_const(rb_cNetworkInterface, "AF_ECONET", INT2NUM(AF_ECONET));
	#endif
	#ifdef AF_PPPOX
		rb_define_const(rb_cNetworkInterface, "AF_PPPOX", INT2NUM(AF_PPPOX));
	#endif
	#ifdef AF_WANPIPE
		rb_define_const(rb_cNetworkInterface, "AF_WANPIPE", INT2NUM(AF_WANPIPE));
	#endif
	#ifdef AF_BLUETOOTH
		rb_define_const(rb_cNetworkInterface, "AF_BLUETOOTH", INT2NUM(AF_BLUETOOTH));
	#endif
	
}

