import socket


def init(id, cfg): return True


def deinit(id): return True


def inform_super(id, qstate, superqstate, qdata): return True


rewrite_ip_list = [
    "192.168.55.35", "192.168.55.36", "192.168.55.37", "192.168.55.38",
]
rewrite_ip6_list = [
    "2001:db8::35", "2001:db8::36", "2001:db8::37", "2001:db8::38",
]

rewrite_cname_list = [
    # "rewrite.com.",
    "rewrite.ru.",
]

replace_list = {
    "A": ["1.3.3.7", "3.1.33.7"],
    "AAAA": ["1:3:3::7", "3:1:33::7"]
}

replace_ttl = 60


def unpackIP(strIP):
    return socket.inet_ntoa(strIP[2:])


def unpackIP6(strIP):
    return socket.inet_ntop(socket.AF_INET6, strIP[2:])


def unpackNAME(strNAME):
    lbl_remain = ord(strNAME[2])
    name = ""
    for c in strNAME[3:]:
        if lbl_remain == 0:
            name += "."
            lbl_remain = ord(c)
            continue
        lbl_remain -= 1
        name += c
    return name


def operate(id, event, qstate, qdata):
    if (event == MODULE_EVENT_NEW) or (event == MODULE_EVENT_PASS):
        # pass the query to validator
        qstate.ext_state[id] = MODULE_WAIT_MODULE
        return True

    if event == MODULE_EVENT_MODDONE:
        # log_info("pythonmod: iterator module done")

        if not qstate.return_msg:
            qstate.ext_state[id] = MODULE_FINISHED
            return True

        # modify the response

        qdn = qstate.qinfo.qname_str

        if qstate.qinfo.qtype in [RR_TYPE_A, RR_TYPE_CNAME, RR_TYPE_AAAA]:

            is_need_replace = False
            # log_info("qstate.qinfo.qtype: {}".format(qstate.qinfo.qtype_str))
            rep = qstate.return_msg.rep
            for i in xrange(rep.an_numrrsets):
                # replace it with RR_TYPE_A
                if rep.rrsets[i].rk.type_str == "A":
                    # log_info("check for A")
                    data = rep.rrsets[i].entry.data
                    for j in xrange(data.count):
                        ip = unpackIP(data.rr_data[j])
                        if ip in rewrite_ip_list:
                            is_need_replace = True
                            log_info("find A {}, need to rewrite".format(ip))

                # replace it with RR_TYPE_AAAA
                elif rep.rrsets[i].rk.type_str == "AAAA":
                    # log_info("check for AAAA")
                    data = rep.rrsets[i].entry.data
                    for j in xrange(data.count):
                        ip = unpackIP6(data.rr_data[j])
                        if ip in rewrite_ip6_list:
                            is_need_replace = True
                            log_info("find AAAA {}, need to rewrite".format(ip))

                # replace it with RR_TYPE_CNAME
                elif rep.rrsets[i].rk.type_str == "CNAME":
                    # log_info("check for CNAME")
                    data = rep.rrsets[i].entry.data
                    for j in xrange(data.count):
                        cname_value = unpackNAME(data.rr_data[j])
                        for rewrite_cname in rewrite_cname_list:
                            if cname_value.endswith(rewrite_cname):
                                is_need_replace = True
                                log_info("find CNAME {}, need to rewrite".format(cname_value))

            # log_info("end inspect answer")

            if is_need_replace:
                msg = DNSMessage(qstate.qinfo.qname_str, qstate.qinfo.qtype, RR_CLASS_IN, PKT_QR | PKT_RA | PKT_RD)

                invalidateQueryInCache(qstate, qstate.return_msg.qinfo)

                msg_qtype_str = qstate.qinfo.qtype_str
                if qstate.qinfo.qtype_str == "CNAME":
                    msg_qtype_str = "A"

                for new_record in replace_list.get(msg_qtype_str, []):
                    msg.answer.append('%s %d IN %s %s' % (qdn, replace_ttl, msg_qtype_str, new_record))

                if not msg.set_return_msg(qstate):
                    qstate.ext_state[id] = MODULE_ERROR
                    return True
                    # raise Exception("Can't create response")
                qstate.return_rcode = RCODE_NOERROR
                qstate.return_msg.rep.security = 2
                #              storeQueryInCache(qstate, qstate.qinfo, qstate.return_msg.rep, 0)
                try:
                    invalidateQueryInCache(qstate, qstate.return_msg.qinfo)
                    storeQueryInCache(qstate, qstate.qinfo, qstate.return_msg.rep, 0)
                except Exception as e:
                    log_info("exception on storeQueryInCache: {}".format(e))
                qstate.no_cache_store = 1
                qstate.no_cache_lookup = 1
                # qstate.no_cache_store = 1

        qstate.ext_state[id] = MODULE_FINISHED
        return True

    log_err("pythonmod: bad event")
    qstate.ext_state[id] = MODULE_ERROR
    return True
