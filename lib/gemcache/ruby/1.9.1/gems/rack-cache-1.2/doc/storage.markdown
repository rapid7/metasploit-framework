Storage
=======

__Rack::Cache__ runs within each of your backend application processes and does not
rely on a single intermediary process like most types of proxy cache
implementations. Because of this, the storage subsystem has implications on not
only where cache data is stored but whether the cache is properly distributed
between multiple backend processes. It is highly recommended that you read and
understand the following before choosing a storage implementation.

Storage Areas
-------------

__Rack::Cache__ stores cache entries in two separate configurable storage
areas: a _MetaStore_ and an _EntityStore_.

The _MetaStore_ keeps high level information about each cache entry, including
the request/response headers and other status information. When a request is
received, the core caching logic uses this meta information to determine whether
a fresh cache entry exists that can satisfy the request.

The _EntityStore_ is where the actual response body content is stored. When a
response is entered into the cache, a SHA1 digest of the response body content
is calculated and used as a key. The entries stored in the MetaStore reference
their response bodies using this SHA1 key.

Separating request/response meta-data from response content has a few important
advantages:

  * Different storage types can be used for meta and entity storage. For
    example, it may be desirable to use memcached to store meta information
    while using the filesystem for entity storage.

  * Cache entry meta-data may be retrieved quickly without also retrieving
    response bodies. This avoids significant overhead when the cache misses
    or only requires validation.

  * Multiple different responses may include the same exact response body. In
    these cases, the actual body content is stored once and referenced from
    each of the meta store entries.

You should consider how the meta and entity stores differ when choosing a storage
implementation. The MetaStore does not require nearly as much memory as the
EntityStore and is accessed much more frequently. The EntityStore can grow quite
large and raw performance is less of a concern. Using a memory based storage
implementation (`heap` or `memcached`) for the MetaStore is strongly advised,
while a disk based storage implementation (`file`) is often satisfactory for
the EntityStore and uses much less memory.

Storage Configuration
---------------------

The MetaStore and EntityStore used for a particular request is determined by
inspecting the `rack-cache.metastore` and `rack-cache.entitystore` Rack env
variables. The value of these variables is a URI that identifies the storage
type and location (URI formats are documented in the following section).

The `heap:/` storage is assumed if either storage type is not explicitly
provided. This storage type has significant drawbacks for most types of
deployments so explicit configuration is advised.

The default metastore and entitystore values can be specified when the
__Rack::Cache__ object is added to the Rack middleware pipeline as follows:

    use Rack::Cache,
      :metastore => 'file:/var/cache/rack/meta',
      :entitystore => 'file:/var/cache/rack/body'

Alternatively, the `rack-cache.metastore` and `rack-cache.entitystore`
variables may be set in the Rack environment by an upstream component.

Storage Implementations
-----------------------

__Rack::Cache__ includes meta and entity storage implementations backed by local
process memory ("heap storage"), the file system ("disk storage"), and
memcached. This section includes information on configuring __Rack::Cache__ to
use a specific storage implementation as well as pros and cons of each.

### Heap Storage

Uses local process memory to store cached entries.

    use Rack::Cache,
      :metastore   => 'heap:/',
      :entitystore => 'heap:/'

The heap storage backend is simple, fast, and mostly useless. All cache
information is stored in each backend application's local process memory (using
a normal Hash, in fact), which means that data cached under one backend is
invisible to all other backends. This leads to low cache hit rates and excessive
memory use, the magnitude of which is a function of the number of backends in
use. Further, the heap storage provides no mechanism for purging unused entries
so memory use is guaranteed to exceed that available, given enough time and
utilization.

Use of heap storage is recommended only for testing purposes or for very
simple/single-backend deployment scenarios where the number of resources served
is small and well understood.

### Disk Storage

Stores cached entries on the filesystem.

    use Rack::Cache,
      :metastore   => 'file:/var/cache/rack/meta',
      :entitystore => 'file:/var/cache/rack/body'

The URI may specify an absolute, relative, or home-rooted path:

  * `file:/storage/path` - absolute path to storage directory.
  * `file:storage/path` - relative path to storage directory, rooted at the
    process's current working directory (`Dir.pwd`).
  * `file:~user/storage/path` - path to storage directory, rooted at the
    specified user's home directory.
  * `file:~/storage/path` - path to storage directory, rooted at the current
    user's home directory.

File system storage is simple, requires no special daemons or libraries, has a
tiny memory footprint, and allows multiple backends to share a single cache; it
is one of the slower storage implementations, however. Its use is recommended in
cases where memory is limited or in environments where more complex storage
backends (i.e., memcached) are not available. In many cases, it may be
acceptable (and even optimal) to use file system storage for the entitystore and
a more performant storage implementation (i.e. memcached) for the metastore.

__NOTE:__ When both the metastore and entitystore are configured to use file
system storage, they should be set to different paths to prevent any chance of
collision.

### Memcached Storage

Stores cached entries in a remote [memcached](http://www.danga.com/memcached/)
instance.

    use Rack::Cache,
      :metastore   => 'memcached://localhost:11211/meta',
      :entitystore => 'memcached://localhost:11211/body'

The URI must specify the host and port of a remote memcached daemon. The path
portion is an optional (but recommended) namespace that is prepended to each
cache key.

The memcached storage backend requires either the `dalli` or `memcached`
libraries. By default, the `dalli` library is used; require the `memcached`
library explicitly to use it instead.

    gem install dalli

Memcached storage is reasonably fast and allows multiple backends to share a
single cache. It is also the only storage implementation that allows the cache
to reside somewhere other than the local machine. The memcached daemon stores
all data in local process memory so using it for the entitystore can result in
heavy memory usage. It is by far the best option for the metastore in
deployments with multiple backend application processes since it allows the
cache to be properly distributed and provides fast access to the
meta-information required to perform cache logic. Memcached is considerably more
complex than the other storage implementations, requiring a separate daemon
process and extra libraries. Still, its use is recommended in all cases where
you can get away with it.

[e]: http://blog.evanweaver.com/files/doc/fauna/memcached/files/README.html
[f]: http://blog.evanweaver.com/articles/2008/01/21/b-the-fastest-u-can-b-memcached/
[l]: http://tangent.org/552/libmemcached.html
