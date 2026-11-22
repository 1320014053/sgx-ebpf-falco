module Notice;

event new_connection(c: connection)
    {
    if ( c$id$orig_h == 192.0.2.251 )
        print fmt("%d %d", port_to_count(c$id$orig_p) - 50000, |suppressing|);
    }
