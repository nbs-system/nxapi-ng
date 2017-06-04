from datetime import datetime
import logging
import re
import socket
import copy
import itertools
import dateutil.parser

try:
    from urlparse import parse_qs
except ImportError:  # python3
    from urllib.parse import parse_qs

from . import rules

date_regex = re.compile("""(((Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)""" \
                        """\s+([0-3]?[0-9])|([0-2]0[0-3][0-9](/|-)(0?[0-9]|1[0-2])""" \
                        """(/|-)([0-3][0-9])))\s+[0-1][0-9|2[0-3]):[0-5][0-9]:[0-5][0-9]""" \
                        """(\+0[0-9]|1[0-2])?""")


def parse_date(nxlog):
    """
    :param str nxlog: A naxsi log ( https://github.com/nbs-system/naxsi/wiki/naxsilogs )
    :return string: date string or empty string if we fail to find a date
    """

    end=nxlog.find("[error]")
    ret=""
    if end > 0:
        match=re.search(date_regex, nxlog[:end])
        if match:
            ret = match.group(0)
    return ret

def parse_nxlog(nxlog):
    """

    :param str nxlog: A naxsi log ( https://github.com/nbs-system/naxsi/wiki/naxsilogs )  
  :return list, dict: A list of errors, and the dictionary representation of the `nxlog`
    """
    errors = list()
    ret = list()
    raw_dict = dict()

    date = parse_date(nxlog)
    start = nxlog.find("ip=")
    if start < 0:
        errors.append('%s is an invalid extlog or nxlog, string "ip=" not found.' % nxlog)
        return errors, ret

    if '[error]' in nxlog:
        end = nxlog.find(", ")
        if end < 0:
            errors.append('%s is an invalid nxlog, string "," not found.' % nxlog)
            return errors, ret
    elif '[debug]' in nxlog:
        end = len(nxlog)
    else:
        errors.append('%s is an invalid line: no [debug] or [error] found.' % nxlog)
        return errors, ret

    # Flatten the dict, since parse_qs is a bit annoying
    raw_dict = parse_qs(nxlog[start:end])
    for key, value in raw_dict.items():
        raw_dict[key] = value[0]

    # We may have a multi-line event
    min_dict = dict()
    for key in raw_dict:
        if not key.startswith('id') and not key.startswith('zone') and not key.startswith('var_name'):
            min_dict[key]=raw_dict[key]

    min_dict['date'] = unify_date(date)
    min_dict['coords'] = coords(min_dict['ip'])
    
    for i in itertools.count():
        _id = "id%d" % i
        _var_name = "var_name%d" % i
        _zone = "zone%d" % i
        if {_id, _var_name, _zone}.issubset(raw_dict):
            ret.append(copy.copy(min_dict))
            ret[-1]['id'] = raw_dict[_id]
            ret[-1]['var_name'] = raw_dict[_var_name]
            ret[-1]['zone'] = raw_dict[_zone]
        else:
            break

    return list(), ret


def explain_nxlog(nxlog):
    """

    :param dict nxlog: A dictionary representation of an `nxlog`. For string, use the `parse_nxlog` function first .
    :return str: A textual explaination of the `nxlog`
    """

    explain = "Peer <strong>{}</strong> performed a request to <strong>{}</strong> on URI <strong>{}</strong> ".format(
        nxlog['ip'], nxlog['server'], nxlog['uri'])

    scores = list()
    cpt = 0
    while "cscore{}".format(cpt) in nxlog:
        cscore = "cscore{}".format(cpt)
        score = "score{}".format(cpt)
        scores.append("that reached a <strong>{}</strong> score of <strong>{}</strong> ".format(
            nxlog[cscore], nxlog[score]))
        cpt += 1
    explain += ' and '.join(scores)

    cpt = 0
    named = list()
    while "id{}".format(cpt) in nxlog:
        _id = "id{}".format(cpt)
        _var_name = "var_name{}".format(cpt)
        _zone = "zone{}".format(cpt)
        if "var_name{}".format(cpt) in nxlog:
            named.append("<strong>{}</strong> in var named <strong>{}</strong> of zone <strong>{}</strong>".format(
                rules.get_description_core(nxlog[_id]), nxlog[_var_name], nxlog[_zone]))
        else:
            named.append("id <strong>{}</strong> in zone <strong>{}</strong>".format(nxlog[_id], nxlog[_zone]))
        cpt += 1
    explain += ' and '.join(named)

    return explain

def unify_date(date):
    """ tries to parse a text date,
    returns date object or None on error """
    out_date_format = "%Y%m%dT%H:%M:%S"
    idx = 0
    # Seems coherent to store UTC time
    # The RFC 3339 specifies CCYY-MM-DDThh:mm:ss[Z|(+|-)hh:mm] as a format
    while date[idx] == " " or date[idx] == "\t":
        idx += 1
    date=date[idx:]

    date_obj=dateutil.parser.parse(date)
    return date_obj.strftime(out_date_format)

def coords(ip, db='/usr/share/GeoIP/GeoIPCity.dat'):
    ret=None
    try:
        import GeoIP
    except:
        logging.warning("GeoIP python module not installed")
        return ret
    try:
        socket.inet_aton(ip)
        ip_type=4
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            ip_type=6
        except socket.error:
            logging.warning("Ip %s is not parseable" % ip)
            return None
    r=None
    if ip_type==4:
        gi = GeoIP.open(db, GeoIP.GEOIP_STANDARD |GeoIP.GEOIP_MEMORY_CACHE | GeoIP.GEOIP_CHECK_CACHE)
        r = gi.record_by_addr(ip)
    elif ip_type==6:
        pass
    # For the moment there's no useable open ipv6 city database
    if r is not None:
        ret= "[%f, %f]" % (round(float(r['latitude']),4), round(float(r['longitude']),4))
    return ret
