## Description

Redis is an in-memory data structure project implementing a distributed, in-memory key-value database with optional durability.
Redis supports different kinds of abstract data structures, such as strings, lists, maps, sets, sorted sets, HyperLogLogs, bitmaps, streams, and spatial indexes.

This module locates Redis endpoints by attempting to run a specified Redis command.

## Vulnerable Application

This module is tested on two different Redis server instances.
Virtual testing environments (inside docker container): 

 - Redis 5.0.6
 - Redis 4.0.14
 - Redis 8.2.0

## Verification Steps

  1. Do: `use auxiliary/scanner/redis/redis_server`
  2. Do: `set rhosts [ips]`
  3. Do: `run`

## Options

### COMMAND

Requires a valid redis command to be executed on rhosts. Defaults to `INFO`. 
Redis commands list can be found [here](https://redis.io/commands).

## Scenarios

### Redis: 8.2.0 inside a docker container
  ```
msf auxiliary(scanner/redis/redis_server) > use auxiliary/scanner/redis/redis_server
msf auxiliary(scanner/redis/redis_server) > set RHOSTS 172.17.0.3
RHOSTS => 172.17.0.3
msf auxiliary(scanner/redis/redis_server) > run

[+] 172.17.0.3:6379       - Found redis with INFO command
Server
======

  Key                 Value
  ---                 -----
  arch_bits           64
  atomicvar_api       c11-builtin
  config_file
  configured_hz       10
  executable          /data/redis-server
  gcc_version         12.2.0
  hz                  10
  io_threads_active   0
  listener0           name=tcp,bind=0.0.0.0,port=6379
  lru_clock           2271980
  monotonic_clock     POSIX clock_gettime
  multiplexing_api    epoll
  os                  Linux 6.8.0-124-generic x86_64
  process_id          1
  process_supervised  no
  redis_build_id      35c067db3b86fa2f
  redis_git_dirty     1
  redis_git_sha1      00000000
  redis_mode          standalone
  redis_version       8.2.0
  run_id              31e7b7a9abe8c26368ea20ecec99c0f3a0a9414b
  server_time_usec    1780656876052541
  tcp_port            6379
  uptime_in_days      0
  uptime_in_seconds   76626

Clients
=======

  Key                              Value
  ---                              -----
  blocked_clients                  0
  client_recent_max_input_buffer   0
  client_recent_max_output_buffer  0
  clients_in_timeout_table         0
  cluster_connections              0
  connected_clients                1
  maxclients                       10000
  pubsub_clients                   0
  total_blocking_keys              0
  total_blocking_keys_on_nokey     0
  total_watched_keys               0
  tracking_clients                 0
  watching_clients                 0

Memory
======

  Key                                  Value
  ---                                  -----
  active_defrag_running                0
  allocator_active                     2023424
  allocator_allocated                  1662248
  allocator_frag_bytes                 285144
  allocator_frag_ratio                 1.24
  allocator_muzzy                      0
  allocator_resident                   4870144
  allocator_rss_bytes                  2846720
  allocator_rss_ratio                  2.41
  lazyfree_pending_objects             0
  lazyfreed_objects                    0
  maxmemory                            0
  maxmemory_human                      0B
  maxmemory_policy                     noeviction
  mem_allocator                        jemalloc-5.3.0
  mem_aof_buffer                       0
  mem_clients_normal                   0
  mem_clients_slaves                   0
  mem_cluster_links                    0
  mem_fragmentation_bytes              22738256
  mem_fragmentation_ratio              24.07
  mem_not_counted_for_evict            0
  mem_overhead_db_hashtable_rehashing  0
  mem_replica_full_sync_buffer         0
  mem_replication_backlog              0
  mem_total_replication_buffers        0
  number_of_cached_scripts             0
  number_of_functions                  0
  number_of_libraries                  0
  rss_overhead_bytes                   18853888
  rss_overhead_ratio                   4.87
  total_system_memory                  4105568256
  total_system_memory_human            3.82G
  used_memory                          1005320
  used_memory_dataset                  18446744073709527704
  used_memory_dataset_perc             45221474436382720.00%
  used_memory_functions                192
  used_memory_human                    981.76K
  used_memory_lua                      31744
  used_memory_lua_human                31.00K
  used_memory_overhead                 1029232
  used_memory_peak                     1008672
  used_memory_peak_human               985.03K
  used_memory_peak_perc                99.67%
  used_memory_peak_time                1780589416
  used_memory_rss                      23724032
  used_memory_rss_human                22.62M
  used_memory_scripts                  192
  used_memory_scripts_eval             0
  used_memory_scripts_human            192B
  used_memory_startup                  964528
  used_memory_vm_eval                  31744
  used_memory_vm_functions             32768
  used_memory_vm_total                 64512
  used_memory_vm_total_human           63.00K

Persistence
===========

  Key                                Value
  ---                                -----
  aof_current_rewrite_time_sec       -1
  aof_enabled                        0
  aof_last_bgrewrite_status          ok
  aof_last_cow_size                  0
  aof_last_rewrite_time_sec          -1
  aof_last_write_status              ok
  aof_rewrite_in_progress            0
  aof_rewrite_scheduled              0
  aof_rewrites                       0
  aof_rewrites_consecutive_failures  0
  async_loading                      0
  current_cow_peak                   0
  current_cow_size                   0
  current_cow_size_age               0
  current_fork_perc                  0.00
  current_save_keys_processed        0
  current_save_keys_total            0
  loading                            0
  module_fork_in_progress            0
  module_fork_last_cow_size          0
  rdb_bgsave_in_progress             0
  rdb_changes_since_last_save        0
  rdb_current_bgsave_time_sec        -1
  rdb_last_bgsave_status             ok
  rdb_last_bgsave_time_sec           -1
  rdb_last_cow_size                  0
  rdb_last_load_keys_expired         0
  rdb_last_load_keys_loaded          0
  rdb_last_save_time                 1780580250
  rdb_saves                          0

Threads
=======

  Key          Value
  ---          -----
  io_thread_0  clients=1,reads=123,writes=13

Stats
=====

  Key                                        Value
  ---                                        -----
  acl_access_denied_auth                     0
  acl_access_denied_channel                  0
  acl_access_denied_cmd                      0
  acl_access_denied_key                      0
  active_defrag_hits                         0
  active_defrag_key_hits                     0
  active_defrag_key_misses                   0
  active_defrag_misses                       0
  client_output_buffer_limit_disconnections  0
  client_query_buffer_limit_disconnections   0
  current_active_defrag_time                 0
  current_eviction_exceeded_time             0
  dump_payload_sanitizations                 0
  eventloop_cycles                           762070
  eventloop_duration_cmd_sum                 2125
  eventloop_duration_sum                     296128177
  evicted_clients                            0
  evicted_keys                               0
  evicted_scripts                            0
  expire_cycle_cpu_milliseconds              1576
  expired_keys                               0
  expired_stale_perc                         0.00
  expired_subkeys                            0
  expired_time_cap_reached_count             0
  instantaneous_eventloop_cycles_per_sec     9
  instantaneous_eventloop_duration_usec      385
  instantaneous_input_kbps                   0.00
  instantaneous_input_repl_kbps              0.00
  instantaneous_ops_per_sec                  0
  instantaneous_output_kbps                  0.00
  instantaneous_output_repl_kbps             0.00
  io_threaded_reads_processed                0
  io_threaded_total_prefetch_batches         0
  io_threaded_total_prefetch_entries         0
  io_threaded_writes_processed               0
  keyspace_hits                              0
  keyspace_misses                            0
  latest_fork_usec                           0
  migrate_cached_sockets                     0
  pubsub_channels                            0
  pubsub_patterns                            0
  pubsubshard_channels                       0
  rejected_connections                       0
  reply_buffer_expands                       0
  reply_buffer_shrinks                       51
  slave_expires_tracked_keys                 0
  sync_full                                  0
  sync_partial_err                           0
  sync_partial_ok                            0
  total_active_defrag_time                   0
  total_commands_processed                   18
  total_connections_received                 65
  total_error_replies                        9
  total_eviction_exceeded_time               0
  total_forks                                0
  total_net_input_bytes                      20995
  total_net_output_bytes                     62815
  total_net_repl_input_bytes                 0
  total_net_repl_output_bytes                0
  total_reads_processed                      123
  total_writes_processed                     13
  tracking_total_items                       0
  tracking_total_keys                        0
  tracking_total_prefixes                    0
  unexpected_error_replies                   0

Replication
===========

  Key                             Value
  ---                             -----
  connected_slaves                0
  master_failover_state           no-failover
  master_repl_offset              0
  master_replid                   8330f92dc9a16c55179ddd70c90aec3ffac30f87
  master_replid2                  0000000000000000000000000000000000000000
  repl_backlog_active             0
  repl_backlog_first_byte_offset  0
  repl_backlog_histlen            0
  repl_backlog_size               1048576
  role                            master
  second_repl_offset              -1

CPU
===

  Key                        Value
  ---                        -----
  used_cpu_sys               81.891011
  used_cpu_sys_children      0.033990
  used_cpu_sys_main_thread   81.887197
  used_cpu_user              251.248880
  used_cpu_user_children     0.010110
  used_cpu_user_main_thread  251.244287

Modules
=======

  Key     Value
  ---     -----
  module  name=bf,ver=80200,api=1,filters=0,usedby=[],using=[],options=[]
  module  name=search,ver=80200,api=1,filters=0,usedby=[],using=[ReJSON],options=[handle-io-errors]
  module  name=vectorset,ver=1,api=1,filters=0,usedby=[],using=[],options=[handle-io-errors|handle-repl-async-load]
  module  name=timeseries,ver=80200,api=1,filters=0,usedby=[],using=[],options=[handle-io-errors]
  module  name=ReJSON,ver=80200,api=1,filters=0,usedby=[search],using=[],options=[handle-io-errors]

Errorstats
==========

  Key            Value
  ---            -----
  errorstat_ERR  count=9

Cluster
=======

  Key              Value
  ---              -----
  cluster_enabled  0


[*] 172.17.0.3:6379       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
  ```
