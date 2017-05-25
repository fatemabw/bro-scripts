##############################################################
# A script to extract UNIQUE files across cluster from HTTP connections.
#
# Ignoring the file downloads by SEcure/DMZ subnets...
# fatemabw 29th Sep 1016.
#
# MAKE SURE YOU HAVE HASH DIRS IN PLACE BEFORE RUNNING THIS SCRIPT
##############################################################

module Extract;

redef FileExtract::prefix = "/mnt/brolog/logs/fileExtract/";

global SECONDS_IN_DAY = 60*60*24;
global tempDir = "/mnt/brolog/logs/fileExtract/temp/";

export {
    # Append the value LOG to the Log::ID enumerable.
    redef enum Log::ID += { LOG };

    # Define a new type called Extract::Info.
    type Info: record {
        fuid: string &log;
        conn_uids: set[string] &log;
        tx_hosts: set[addr] &log;
        rx_hosts: set[addr] &log;
        note: string &log;
        dept_info: string &log;
        };
    }

# List of the mime-types.
global ext_map: table[string] of string = {

   # ["text/plain"] = "txt",
   # ["image/jpeg"] = "jpg",
   # ["image/png"] = "png",
   # ["text/html"] = "html",
    ["application/x-dosexec"] = "exe",
   # ["application/pdf"] = "pdf",
   # ["application/vnd.ms-excel"] = "xls",
   # ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"] = "xlsx",
   # ["application/zip"] = "zip",
   # ["application/x-compressed-zip"] = "xzip",
   # ["application/x-rar-compressed"] = "rar",
   # ["application/msword"] = "doc",
   # ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"] = "docx",
   # ["application/rtf"] = "rtf",

} &default ="";

# White list of subbnets to exclude file extraction for.
global subnet_map: table[subnet] of string = {
      [y.y.y.0/25] = "Secure subnet1",
      [w.w.w.128/26] = "Secure subnet2",
      [z.z.z.0/24] = "Secure subnet3",
      [x.x.x.0/24] = "Secure subnet4",
} &default ="";

# Whitelisting the domains to ignore file transfer from.
global WL_hosts = set( "au.download.windowsupdate.com",
                       "download.windowsupdate.com",
                       "upgrade.scdn.co",
                       "wsus.ds.download.windowsupdate.com",
                       "download.gfe.nvidia.com",
                       "download-cdn.gfe.nvidia.com",
                       "fcas-udpilot.us-east-1.elasticbeanstalk.com",
                       "definitionupdates.microsoft.com");

event bro_init()
    {
    # Create the logging stream.
    Log::create_stream(LOG, [$columns=Info, $path="files-extract-WL"]);

    }

event file_sniff(f: fa_file, meta: fa_metadata)
    {

    # check for right source to extract.
    if( f$source != "HTTP")
        return;

    # check the right mime-type to extract.
    if ( ! meta?$mime_type || meta$mime_type !in ext_map )
        return;

    # check for the Whitelisted domains.
    if( f$http?$host && f$http$host in WL_hosts)
        return;

    # get the recieving hosts from the record.
    local rx_addr: set[addr];
    rx_addr = f$info$rx_hosts;

    # check if the rx host is in Secure subnet
    for (i in rx_addr)
    {
     if ( i in subnet_map )
      {
       local note = "The IP is in WL subnets.";
       local rec: Extract::Info = [$conn_uids=f$info$conn_uids, $fuid=f$info$fuid, $tx_hosts=f$info$tx_hosts, $rx_hosts=f$info$rx_hosts, $note=note, $dept_info=subnet_map[i]];
       Log::write( Extract::LOG, rec);
       return;
      }
    }

    if ( meta?$mime_type )
     {
         local fname = fmt("%s%s-%s.%s", tempDir, f$source, f$id, ext_map[meta$mime_type]);
         Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
     }
    }

event file_state_remove(f: fa_file)
    {

        if ( !f$info?$extracted )
             return;

        if ( !f$info?$md5 )
         {
           local orig1 = fmt("%s", f$info$extracted);
           local cmd1 = fmt("rm %s", orig1);
           when ( local result1 = Exec::run([$cmd=cmd1]) )
                {
                }
           return;
         }

        local orig = fmt("%s", f$info$extracted);

        local split_orig = split_string(f$info$extracted, /\./);
        local extension = split_orig[|split_orig|-1];

        local dirInitial = str_split(f$info$md5, vector(1));

        #Renaming the file with the hash and moving it to the corresponding folder.
        local dest = fmt("%s%s/%s-%s.%s", FileExtract::prefix, dirInitial[1], f$source, f$info$md5, extension);

        local cmd = fmt("mv %s %s", orig, dest);
        when ( local result = Exec::run([$cmd=cmd]) )
                {
                        f$info$extracted = dest;
                }
        #f$info$extracted = dest;

    }
