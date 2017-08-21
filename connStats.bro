# Script to calculate the stats for every unique IP addr: inbytes, outbytes total established Incomming/outgoing Connections to/from the IP.

@load base/frameworks/sumstats

module ConnStats;

export {
        redef enum Log::ID += { LOG };

        type Info: record {
                ts: time &log;
                netIP: addr &log;
                inbytes: double &log;
                outbytes: double &log;
                EstinboundConns: count &log;
                EstoutboundConns: count &log;
        };

        global log_ConnStats: event( rec: Info );
}

event bro_init() {

        local r1 = SumStats::Reducer($stream="inbytes", $apply=set(SumStats::SUM));
        local r2 = SumStats::Reducer($stream="outbytes", $apply=set(SumStats::SUM));
        local r3 = SumStats::Reducer($stream="EstinboundConns", $apply=set(SumStats::SUM));
        local r4 = SumStats::Reducer($stream="EstoutboundConns", $apply=set(SumStats::SUM));

        SumStats::create([$name="ConnStats-measurement",
                          $epoch=60mins,
                          $reducers=set(r1, r2, r3, r4),
                          $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                             {
                                local out: ConnStats::Info;
                                out$ts = ts;
                                out$netIP = key$host;
                                out$inbytes = result["inbytes"]$sum;
                                out$outbytes = result["outbytes"]$sum;
                                out$EstinboundConns = result["EstinboundConns"]$sum;
                                out$EstoutboundConns = result["EstoutboundConns"]$sum;

                                Log::write(ConnStats::LOG, out);
                             }]);

        Log::create_stream(ConnStats::LOG, [$columns=Info, $ev=log_ConnStats]);
        Log::set_buf(ConnStats::LOG, F);
}

event connection_state_remove(c: connection) {
        if ( c$conn$proto == tcp && c$conn$conn_state == "SF" ) {
                if ( Site::is_local_addr(c$id$resp_h) ) {
                        SumStats::observe("outbytes", SumStats::Key($host=c$id$resp_h), SumStats::Observation($num=c$conn$resp_bytes));
                        SumStats::observe("inbytes", SumStats::Key($host=c$id$resp_h), SumStats::Observation($num=c$conn$orig_bytes));
                        SumStats::observe("EstinboundConns", SumStats::Key($host=c$id$resp_h),SumStats::Observation($num=1));
                } else if ( Site::is_local_addr(c$id$orig_h) ) {
                        SumStats::observe("outbytes", SumStats::Key($host=c$id$orig_h), SumStats::Observation($num=c$conn$orig_bytes));
                        SumStats::observe("inbytes", SumStats::Key($host=c$id$orig_h), SumStats::Observation($num=c$conn$resp_bytes));
                        SumStats::observe("EstoutboundConns", SumStats::Key($host=c$id$orig_h),SumStats::Observation($num=1));
                }
        }
}
