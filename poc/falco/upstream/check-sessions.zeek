event new_connection(c: connection)
    {
    if ( c$id$orig_h != 192.0.2.250 ) return;
    local ssh: conn_id = [$orig_h=192.0.2.10,$orig_p=45000/tcp,$resp_h=198.51.100.15,$resp_p=22/tcp];
    local http: conn_id = [$orig_h=192.0.2.10,$orig_p=45001/tcp,$resp_h=198.51.100.15,$resp_p=80/tcp];
    print fmt("%d %d %d",port_to_count(c$id$orig_p),connection_exists(ssh) ? 1 : 0,connection_exists(http) ? 1 : 0);
    }
