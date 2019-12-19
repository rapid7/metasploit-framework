Meterpreter has always had the need to be configured on the fly so that it knows how to talk to Metasploit. For many years, this configuration management was achieved by hot-patching a copy of the `metsrv` DLL/binary using a simple "string replace" approach. This worked well enough to support a number of situations, but restricted the flexibility of Meterpreter and its support for handling multiple transports.

It wasn't just transports that were locked down, but the ability to provide payloads that contained way more than the core Meterpreter (metsrv) itself. It was also not easy to pass other forms of information on the fly to the Meterpreter instance because the stagers were only able to pass in a copy of the active socket handle.

Recent modifications to Meterpreter have done away with this old method and have replaced with with a dynamic configuration block that can be used to alleviate these problems and provide the flexibility for other more interesting things down the track.

This document contains information on the structure and layout of the new configuration block, along with how it is used by Meterpreter.

## How the configuration is found

In the past Meterpreter has required that the stager (or stage0 as some like to call it) pass in a handle to the active socket so that it can take over communications without creating a new socket (at least in the case of `TCP` connections). While this feature is still required, it doesn't happen in the way that it used to. Instead, Meterpreter now requires that the stager pass in a pointer to the start of the configuration block. The configuration block can be anywhere in memory, so long as the memory region is marked as `RWX`.

### Loading configuration in Windows Meterpreter

Stage 1 of loading Windows Meterpreter now utilises a new loader, called `meterpreter_loader` ([Win x86](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/payload/windows/meterpreter_loader.rb), [Win x64](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/payload/windows/x64/meterpreter_loader.rb)), which does the following:

* Loads the `metsrv` DLL from disk.
* Patches the DOS header of the DLL so that it contains executable shellcode that correctly initialises `metsrv` and calculates the location that points to the end of `metsrv` in memory. It also takes any existing socket value (found in `edi` or `rdi` depending on the architecture) and writes that directly to the configuration (more on this later).
* Generates a configuration block and appends this to the `metsrv` binary.

The result is that the payload has the following structure once it has been prepared:

```
  +--------------+
  | Patched DOS  |
  |    header    |
  +--------------+
  |              |
  .              .
  .  metsrv dll  .
  .              .
  |              |
  +--------------+
  | config block |
  +--------------+
```

### Loading configuration in POSIX Meterpreter (Mettle)

All of the configuration for the POSIX Meterpreter is able to be passed via command line arguments to the payload. When generating a payload with a specific configuration, a simulated command line is patched into a static variable in the main startup code. Generate a payload and see `./mettle -h` for a full description of available arguments.

## Windows Meterpreter Configuration Block Structure

In order to pass information to Meterpreter and not have it break, a known format of configuration is required. This format needs to be consistent on each invocation much like you would expect with any configuration. In the case of binary Meterpreter (POSIX and Windows), this configuration block contains the following:

* One Session configuration block.
* One or more Transport Configuration blocks, followed by a terminator.
* One or more Extension configuration blocks, followed by a terminator.

Each of these blocks are described in detail in the sections below.

### Session configuration block

The notion of a session configuration block is used to wrap up the following values:

* Socket handle - When Meterpreter is invoked with TCP communications, an active socket is already in use. This socket handle is intended to be reused by Meterpreter when `metsrv` executes. This socket handle is written to the configuration block on the fly by the loader. It is stored in the Session configuration block so that it has a known location. This value is always a 32-bit DWORD, even on 64-bit platforms.
* Exit func - This value is a 32-bit DWORD value that identifies the method that should be used when terminating the Meterpreter session. This value is the equivalent of the [Block API Hash](https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/text.rb#L1685) that represents the function to be invoked. Meterpreter used to delegate the responsibility of handling this to the stager that had invoked it. Meterpreter no longer does this, instead it handles the closing of the Meterpreter session by itself, and hence the chosen method for termination must be made known in the configuration.
* Session expiry value - This is a 32-bit DWORD that contains the number of seconds that the Meterpreter session should last for. While Meterpreter is running, this value is continually checked, and if the session expiry time is reached, then Meterpreter shuts itself down. For more information, please read the **Timeout documentation** (link coming soon).
* UUID - This is a 16-byte value that represents a payload UUID. A UUID is a new concept that has come to Metasploit with a goal of tracking payload type and origin, and validing that sessions received by Metasploit are intended for use by the current installation. For more information, please read the **UUID documentation** (link coming soon).

The layout of this block in memory looks like this:

```
  +--------------+
  |Socket Handle |
  +--------------+
  |  Exit func   |
  +--------------+
  |Session Expiry|
  +--------------+
  |              |
  |     UUID     |
  |              |
  |              |
  +--------------+

  | <- 4 bytes ->|
```

With this structure in place, Meterpreter knows that the session configuration block is exactly `28` bytes in size.

The Session configuration block description can be found in the [Meterpreter source](https://github.com/rapid7/meterpreter/blob/master/source/common/config.h#L25).

### Transport configuration block

The Transport configuration block is a term used to refer to the group of transport configurations that are present in the payload. Meterpreter now supports multiple transports, and so the configuration should support multiple transports too.

There are two main issues when dealing with transport configurations:

1. The configuration should allow for many transport configurations to be specified.
1. The configuration should allow for each transport to be of a different type and size.

Meterpreter's current transport implementations provide two main "classes" of transport, those being `HTTP(S)` and `TCP`. Each of these transport classes require different configuration values, as well as common values, in order to function.

#### Common configuration values

The values that are common to both `HTTP(S)` and `TCP` transports are:

* URL - This value is a meta-description of the transport and is used not only as a configuration element for the transport itself but also as a way of determining exactly what type of transport this block represents. The field is a total of `512` _characters_ (Windows Meterpreter uses `wchar_t`, while POSIX Meterpreter uses `char`). Transport types are specified by the scheme element in the URL, and the body of the URL specifies key information such as host and port information. Meterpreter inspects this to determine what type of transport block is in use, and hence from there is able to determine the size of the block. Valid values look like the following:
    * `tcp://<host>:<port>` - indicates that this payload is a _reverse_ **IPv4** `TCP` connection.
    * `tcp6://<host>:<port>?<scope>` - indicates that this payload is a _reverse_ **IPv6** `TCP` connection.
    * `tcp://:<port>` - indicates that this payload is a _bind_ payload listening on the specified port (note that no host is specifed).
    * `http://<host>:<port>/<uri>` - indicates that this payload is an HTTP connection (can only be _reverse_).
    * `https://<host>:<port>/<uri>` - indicates that this payload is an HTTPS connection (can only be _reverse_).
* Communications expiry - This value is another 32-bit DWORD value that represents the number of seconds to wait between successful packet/receive calls. For more information, please read the **Timeout documentation** (link coming soon).
* Retry total - This value is 32-bit DWORD value that represents the number of seconds that Meterpreter should continue to attempt to reconnect on this transport before giving up. For more information, please read the **Timeout documentation** (link coming soon).
* Retry wait - This value is 32-bit DWORD value that represents the number of seconds between each attempt that Meterpreter makes to reconnect on this transport. For more information, please read the **Timeout documentation** (link coming soon).

The layout of this block in memory looks like the following:

```
  +--------------+
  |              |
  |      URL     |
  .              .
  .              .  512 characters worth
  .              .  (POSIX -> ASCII -> char)
  .              .  (Windows -> wide char -> wchar_t)
  .              .
  |              |
  +--------------+
  |  Comms T/O   |
  +--------------+
  |  Retry Total |
  +--------------+
  |  Retry Wait  |
  +--------------+

  | <- 4 bytes ->|
```

The common transport configuration block description can be found in the [Meterpreter source](https://github.com/rapid7/meterpreter/blob/master/source/common/config.h#L33).

#### TCP configuration values

At this time, there are no `TCP`-specific configuration values, as the common configuration block caters for all of the needs of `TCP` transports. This may change down the track.

#### HTTP/S configuration values

`HTTP` and `HTTPS` connections have a number of extra configuration values that are required in order to make it function correctly in various environments. Those values are:

* Proxy host - In environments where proxies are required to be set manually, this field contains the detail of the proxy to use. The field is `128` characters in size (`wchar_t` only, given that we don't yet have `HTTP/S` transport in POSIX), and can be in one of the following formats:
    * `http://<proxy ip>:<proxy port>` in the case of `HTTP` proxies.
    * `socks=<socks ip>:<sock port>` in the case of `socks` proxies.
* Proxy user name - Some proxies require authentication. In such cases, this value contains the username that should be used to authenticate with the given proxy. This field is `64` characters in size (`wchar_t`).
* Proxy password - This value will accompany the user name field in the case where proxy authentication is required. It contains the password used to authenticate with the proxy, and is also `64` characters in size (`wchar_t`).
* User agent string - Customisable user agent string. This changes the user agent that is used when `HTTP/S` requests are made to Metasploit. This field is `256` characters in size (`wchar_t`).
* Expected SSL certificate hash - Meterpreter has the capability of validating the SSL certificate that Metasploit presents when using `HTTPS`. This value contains the `20`-byte SHA1 hash of the expected certificate. For more information, please read the **SSL certificate validation documentation** (link coming soon).

All values that are shown above need to be specified in the configuration, including SSL certificate validation for plain `HTTP` connections. Values that are not used should be zeroed out.

The structure of the `HTTP/S` configuration is as follows.

```
  +--------------+
  |              |
  |  Proxy host  |
  .              .  128 characters worth (wchar_t)
  |              |
  +--------------+
  |              |
  |  Proxy user  |
  .              .  64 characters worth (wchar_t)
  |              |
  +--------------+
  |              |
  |  Proxy pass  |
  .              .  64 characters worth (wchar_t)
  |              |
  +--------------+
  |              |
  |  User agent  |
  .              .  256 characters worth (wchar_t)
  |              |
  +--------------+
  |              |
  |   SSL cert   |
  |   SHA1 hash  |
  |              |
  |              |
  +--------------+

  | <- 4 bytes ->|
```

The `HTTP/S` transport configuration block description can be found in the [Meterpreter source](https://github.com/rapid7/meterpreter/blob/master/source/common/config.h#L48).

#### Transport configuration list

As already mentioned, more than one of these transport configuration blocks can be specified. In order to facilitate this, Meterpreter needs to know when the "list" of transports has ended. Using the `URL`, Meterpreter can determine the size of the block, and can move to the next block depending on the type that is discovered. As soon as Meterpreter detects a transport configuration `URL` value that has a string length of zero (ie. a single `NULL` ASCII char in POSIX and a single `NULL` multi-byte char in Windows) it assumes that the transport list has been terminated. The byte immediately following this is deemed to be the start of the Extension configuration, which is documented in the next section.

### Extension configuration block

The extension configuration block is designed to allow Meterpreter payloads to contain any extra extensions that the user wants to bundle in. The goal is to provide the ability to have **Stageless payloads** (link coming soon), and to provide the means for sharing of extensions during migration (though this hasn't been implemented yet). Each of the extensions must have been compiled with [Reflective DLL Injection](https://github.com/rapid7/ReflectiveDLLInjection/) support, as this is the mechanism that is used to load the extensions when Meterpreter starts. For more information on this facility, please see the **Stageless payloads** (link coming soon) documentation.

The extension configuration block also functions as a "list" to allow for an arbitrary number of extensions to be included. Each extension entry needs to contain the following:

* Size - This is the exact size, in bytes, of the extension DLL itself. The value is a 32-bit DWORD.
* Extension binary - This is the full binary directly copied from the DLL. This value needs to be exactly the same length as what is specified in the Size field.

When loading the extensions from the configuration, Meterpreter will continue to parse entries until it finds a `size` value of `0`. At this point Meterpreter assumes it has reached the end of the extension list and will stop parsing.

The structure is simply laid out like the following:

```
  +--------------+
  |  Ext. Size   |
  +--------------+
  | Ext. content |
  +--------------+
  |  NULL term.  |
  |   (4 bytes)  |
  +--------------+
```

## Configuration Block Overview

To summarise, the following shows the layout of a full configuration:


```
  +--------------+
  |Socket Handle |
  +--------------+
  |  Exit func   |
  +--------------+
  |Session Expiry|
  +--------------+
  |              |
  |     UUID     |
  |              |
  |              |
  +--------------+
  |  Transport 1 |
  |  tcp://...   |
  .              .
  |              |
  +--------------+
  |  Comms T/O   |
  +--------------+
  |  Retry Total |
  +--------------+
  |  Retry Wait  |
  +--------------+
  |  Transport 2 |
  |  http://...  |
  .              .
  |              |
  +--------------+
  |  Comms T/O   |
  +--------------+
  |  Retry Total |
  +--------------+
  |  Retry Wait  |
  +--------------+
  |              |
  |  Proxy host  |
  |              |
  +--------------+
  |              |
  |  Proxy user  |
  |              |
  +--------------+
  |              |
  |  Proxy pass  |
  |              |
  +--------------+
  |              |
  |  User agent  |
  |              |
  +--------------+
  |              |
  |   SSL cert   |
  |   SHA1 hash  |
  |              |
  +--------------+
  |  NULL term.  |
  |(1 or 2 bytes)|
  +--------------+
  | Ext 1. Size  |
  +--------------+
  |Ext 1. content|
  +--------------+
  | Ext 2. Size  |
  +--------------+
  |Ext 2. content|
  +--------------+
  |  NULL term.  |
  +--------------+
```