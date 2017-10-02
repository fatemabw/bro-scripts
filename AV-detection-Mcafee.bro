
# Mcafee GTI File Reputation accesses an online master database to determine whether a file is suspicious. 
# GTI File Reputation queries can be recognized because they are on sub domains of avqs.mcafee.com or avts.mcafee.com.
# By determining the src_ip making the queries to GTI DB for suspicious file, one can find out if they are running Mcafee VS.
# Following script determines the Mcafee AV by looking at the DNS queries for those sub-domains.

@load base/frameworks/software
@load base/protocols/dns

module AV;

    export {
        redef enum Software::Type += {
        ## Identifier for Mcafee software
            MCAFEE,
        };

        type Software::name_and_version: record {
                name   : string;
                version: Software::Version;
        };

      }

event DNS::log_dns (rec: DNS::Info) &priority=5
    {
        #local result: Software::name_and_version;
        local result: Software::name_and_version;
        
        if ( /avts.mcafee.com/ in rec$query )
        
        {   
            result$name = "Mcafee GTI";
            result$version$addl = "Probably VSCore 14.4.0.354.17 or later";
            Software::found(rec$id, [$version=result$version, $name=result$name, $host=rec$id$orig_h, $software_type=MCAFEE,$unparsed_version=rec$query]);   
            
        }
        
        if ( /avqs.mcafee.com/ in rec$query )
        
        {   
            result$name = "Mcafee GTI";
            result$version$addl = "Probably GTI Proxy or Othe Mcafee Entp. product";
            Software::found(rec$id, [$version=result$version, $name=result$name, $host=rec$id$orig_h, $software_type=MCAFEE,$unparsed_version=rec$query]);   
            
        }
        
        
    }
