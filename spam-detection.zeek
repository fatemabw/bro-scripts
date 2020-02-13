module SpamDetection;

export {

        redef enum Notice::Type += {
                ## Raised when the condition in proto-port sig is true.
                SMTP_SPAM,
        };
  }

event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string,
                 msg: string, cont_resp: bool)&priority=-5
        {
        # This continually overwrites, but we want the last reply,
        # so this actually works fine.
        if(/spamhaus/ in msg)
                NOTICE([$note=SpamDetection::SMTP_SPAM,
                        $msg=fmt("%d %s", code, msg),
                        $sub=cmd,
                        $conn=c,
                        $identifier=fmt("%s%s", c$id$orig_h,
                                        c$id$resp_h)]);

        }
