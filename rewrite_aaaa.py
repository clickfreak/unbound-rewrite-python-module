
# to satisfy Pycharm
# Warning! empty answer will not stored in cache
# from unbound import *
# from unboundmodule import *


def init(id, cfg): return True


def deinit(id): return True


def inform_super(id, qstate, superqstate, qdata): return True


record_types_reject = ['AAAA']


def operate(id, event, qstate, qdata):

    if (event == MODULE_EVENT_NEW) or (event == MODULE_EVENT_PASS):
        # log_info("pythonmod: module_event_new or module_event_pass")
        # pass the query to validator
        if (qstate.qinfo.qtype == RR_TYPE_AAAA):
            msg = DNSMessage(qstate.qinfo.qname_str, qstate.qinfo.qtype, RR_CLASS_IN, PKT_QR | PKT_RA | PKT_RD)

            if not msg.set_return_msg(qstate):
                qstate.ext_state[id] = MODULE_ERROR
                return True

            # TODO: First, we need to get SOA for requested zone,
            #  beacuse answer without records doesn't stored in cache
            # setTTL(qstate, 3600)
            # if not storeQueryInCache(qstate, qstate.return_msg.qinfo, qstate.return_msg.rep, 0):
            #    qstate.ext_state[id] = MODULE_ERROR
            #    return False

            # we don't need validation, result is valid
            qstate.return_msg.rep.security = 2

            qstate.return_rcode = RCODE_NOERROR
            qstate.ext_state[id] = MODULE_FINISHED
            return True

            # invalidateQueryInCache(qstate, qstate.return_msg.qinfo)
        else:
            qstate.ext_state[id] = MODULE_WAIT_MODULE
            return True

    if event == MODULE_EVENT_MODDONE:
        log_info("pythonmod: iterator module done")
        qstate.ext_state[id] = MODULE_FINISHED
        return True

    log_err("pythonmod: bad event")
    qstate.ext_state[id] = MODULE_ERROR
    return True
