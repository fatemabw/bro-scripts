## Courtsey Seth Hall :)
##! Add the name of the current node to conn.log

@load base/protocols/conn

export {
        redef record Conn::Info += {
                ## The name of the node where this connection was analyzed.
                node: string &log &optional;
        };
}

event connection_state_remove(c: connection) &priority=2
        {
        c$conn$node = peer_description;
        }
