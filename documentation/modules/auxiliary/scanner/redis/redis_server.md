## Description

Redis is an in-memory data structure project implementing a distributed, in-memory key-value database with optional durability.
Redis supports different kinds of abstract data structures, such as strings, lists, maps, sets, sorted sets, HyperLogLogs, bitmaps, streams, and spatial indexes.

This module locates Redis endpoints by attempting to run a specified Redis command.

## Vulnerable Application

This module is tested on two different Redis server instances.
Virtual testing environments (inside docker container): 

 - Redis 5.0.6
 - Redis 4.0.14

## Verification Steps

  1. Do: `use auxiliary/scanner/redis/redis_server`
  2. Do: `set rhosts [ips]`
  3. Do: `run`

## Options

**COMMAND**

Requires a valid redis command to be executed on rhosts. Defaults to `INFO`. 
Redis commands list can be found [here](https://redis.io/commands).

## Scenarios

### Redis:4.0.14 inside a docker container
  ```
msf5 auxiliary(scanner/redis/redis_server) > use auxiliary/scanner/redis/redis_server
msf5 auxiliary(scanner/redis/redis_server) > set RHOSTS 172.17.0.3
RHOSTS => 172.17.0.3
msf5 auxiliary(scanner/redis/redis_server) > run

[+] 172.17.0.3:6379       - Found redis with INFO command: $2701\x0d\x0a# Server\x0d\x0aredis_version:4.0.14\x0d\x0aredis_git_sha1:00000000\x0d\x0aredis_git_dirty:0\x0d\x0aredis_build_id:30850c2ae048947f\x0d\x0aredis_mode:standalone\x0d\x0aos:Linux 4.19.69-1-MANJARO x86_64\x0d\x0aarch_bits:64\x0d\x0amultiplexing_api:epoll\x0d\x0aatomicvar_api:atomic-builtin\x0d\x0agcc_version:8.3.0\x0d\x0aprocess_id:1\x0d\x0arun_id:de1d3d4547ce93ecad76de2efdbcf7ae2d456613\x0d\x0atcp_port:6379\x0d\x0auptime_in_seconds:564\x0d\x0auptime_in_days:0\x0d\x0ahz:10\x0d\x0alru_clock:10154159\x0d\x0aexecutable:/data/redis-server\x0d\x0aconfig_file:\x0d\x0a\x0d\x0a# Clients\x0d\x0aconnected_clients:1\x0d\x0aclient_longest_output_list:0\x0d\x0aclient_biggest_input_buf:0\x0d\x0ablocked_clients:0\x0d\x0a\x0d\x0a# Memory\x0d\x0aused_memory:849224\x0d\x0aused_memory_human:829.32K\x0d\x0aused_memory_rss:4464640\x0d\x0aused_memory_rss_human:4.26M\x0d\x0aused_memory_peak:849224\x0d\x0aused_memory_peak_human:829.32K\x0d\x0aused_memory_peak_perc:100.00%\x0d\x0aused_memory_overhead:836126\x0d\x0aused_memory_startup:786488\x0d\x0aused_memory_dataset:13098\x0d\x0aused_memory_dataset_perc:20.88%\x0d\x0atotal_system_memory:12010311680\x0d\x0atotal_system_memory_human:11.19G\x0d\x0aused_memory_lua:37888\x0d\x0aused_memory_lua_human:37.00K\x0d\x0amaxmemory:0\x0d\x0amaxmemory_human:0B\x0d\x0amaxmemory_policy:noeviction\x0d\x0amem_fragmentation_ratio:5.26\x0d\x0amem_allocator:jemalloc-4.0.3\x0d\x0aactive_defrag_running:0\x0d\x0alazyfree_pending_objects:0\x0d\x0a\x0d\x0a# Persistence\x0d\x0aloading:0\x0d\x0ardb_changes_since_last_save:0\x0d\x0ardb_bgsave_in_progress:0\x0d\x0ardb_last_save_time:1570434683\x0d\x0ardb_last_bgsave_status:ok\x0d\x0ardb_last_bgsave_time_sec:-1\x0d\x0ardb_current_bgsave_time_sec:-1\x0d\x0ardb_last_cow_size:0\x0d\x0aaof_enabled:0\x0d\x0aaof_rewrite_in_progress:0\x0d\x0aaof_rewrite_scheduled:0\x0d\x0aaof_last_rewrite_time_sec:-1\x0d\x0aaof_current_rewrite_time_sec:-1\x0d\x0aaof_last_bgrewrite_status:ok\x0d\x0aaof_last_write_status:ok\x0d\x0aaof_last_cow_size:0\x0d\x0a\x0d\x0a# Stats\x0d\x0atotal_connections_received:5\x0d\x0atotal_commands_processed:3\x0d\x0ainstantaneous_ops_per_sec:0\x0d\x0atotal_net_input_bytes:79\x0d\x0atotal_net_output_bytes:8191\x0d\x0ainstantaneous_input_kbps:0.00\x0d\x0ainstantaneous_output_kbps:0.00\x0d\x0arejected_connections:0\x0d\x0async_full:0\x0d\x0async_partial_ok:0\x0d\x0async_partial_err:0\x0d\x0aexpired_keys:0\x0d\x0aexpired_stale_perc:0.00\x0d\x0aexpired_time_cap_reached_count:0\x0d\x0aevicted_keys:0\x0d\x0akeyspace_hits:0\x0d\x0akeyspace_misses:0\x0d\x0apubsub_channels:0\x0d\x0apubsub_patterns:0\x0d\x0alatest_fork_usec:0\x0d\x0amigrate_cached_sockets:0\x0d\x0aslave_expires_tracked_keys:0\x0d\x0aactive_defrag_hits:0\x0d\x0aactive_defrag_misses:0\x0d\x0aactive_defrag_key_hits:0\x0d\x0aactive_defrag_key_misses:0\x0d\x0a\x0d\x0a# Replication\x0d\x0arole:master\x0d\x0aconnected_slaves:0\x0d\x0amaster_replid:0d4b69672220406a209cf68d63e22215f5bc8741\x0d\x0amaster_replid2:0000000000000000000000000000000000000000\x0d\x0amaster_repl_offset:0\x0d\x0asecond_repl_offset:-1\x0d\x0arepl_backlog_active:0\x0d\x0arepl_backlog_size:1048576\x0d\x0arepl_backlog_first_byte_offset:0\x0d\x0arepl_backlog_histlen:0\x0d\x0a\x0d\x0a# CPU\x0d\x0aused_cpu_sys:0.66\x0d\x0aused_cpu_user:0.45\x0d\x0aused_cpu_sys_children:0.00\x0d\x0aused_cpu_user_children:0.00\x0d\x0a\x0d\x0a# Cluster\x0d\x0acluster_enabled:0\x0d\x0a\x0d\x0a# Keyspace
[*] 172.17.0.3:6379       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
  ```
