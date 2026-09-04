@load policy/tuning/json-logs
@load policy/protocols/conn/known-hosts
@load policy/protocols/conn/known-services
@load policy/protocols/ssl/log-hostcerts-only

redef Log::default_rotation_interval = 1hr;
redef Site::local_nets += { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 };
