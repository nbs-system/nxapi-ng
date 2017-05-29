from datetime import datetime
import logging
import re
import socket

try:
    from urlparse import parse_qs
except ImportError:  # python3
    from urllib.parse import parse_qs

from . import rules

def parse_date(nxlog):
    """
    :param str nxlog: A naxsi log ( https://github.com/nbs-system/naxsi/wiki/naxsilogs )
    :return string: date string or empty string if we fail to find a date
    """
    date_regex = re.compile("""(((Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)""" \
                                """\s+([0-3]?[0-9])|([0-2]0[0-3][0-9](/|-)(0?[0-9]|1[0-2])""" \
                                """(/|-)([0-3][0-9])))\s+[0-1][0-9|2[0-3]):[0-5][0-9]:[0-5][0-9]""" \
                                """(\+0[0-9]|1[0-2])?""")

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
    ret = dict()
    #re.match(r'\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} \[error\]')

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
    ret = parse_qs(nxlog[start:end])
    for key, value in ret.items():
        ret[key] = value[0]

    ret['date'] = unify_date(date)
    ret['coords'] = coords(ret['ip'])
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
    res = ""
    utc_shift=0
    success = 0
    supported_formats = [
        "%b  %d %H:%M:%S",
        "%b %d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S"
    #            "%Y-%m-%dT%H:%M:%S+%:z"
        ]
    # Seems coherent to store UTC time
    # The RFC 3339 specifies CCYY-MM-DDThh:mm:ss[Z|(+|-)hh:mm] as a format
    # This is not RFC 3339 compliant...
    while date[idx] == " " or date[idx] == "\t":
        idx += 1
        success = 0
    for date_format in supported_formats:
        # strptime does not support numeric time zone, hack.
        idx = date.find("+")
        if idx != -1:
            utc_shift = date[idx:]
            date = date[:idx]
        try:
            x = datetime.strptime(date, date_format)
            x = x.replace(hour=x.hour+int(utc_shift))
            # ugly hack when we don't have year
            if x.year==1900:
                x=x.replace(year=datetime.now().year)
            z = x.strftime(out_date_format)
            success = 1
            break
        except:
            #print "'"+clean_date+"' not in format '"+date_format+"'"
            pass
    if success == 0:
        logging.critical("Unable to parse date format :'"+date+"'")
        return ""
    return z

def coords(ip, db='nxapi/data/GeoIPCity_stripped_down.dat'):
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
        gi = GeoIP.open(db, GeoIP.GEOIP_STANDARD)
        r = gi.record_by_addr(ip)
    elif ip_type==6:
        pass
    # For the moment there's no useable open ipv6 city database
    if r is not None:
        ret= "[%f, %f]" % (round(float(r['latitude']),4), round(float(r['longitude']),4))
    return ret
