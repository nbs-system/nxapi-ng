try:
    from urlparse import parse_qs
except ImportError:  # python3
    from urllib.parse import parse_qs


def parse_nxlog(nxlog):
    """

    :param str nxlog: A naxsi log ( https://github.com/nbs-system/naxsi/wiki/naxsilogs )
    :return list, dict: A list of errors, and the dictionary representation of the `nxlog`
    """
    errors = list()
    ret = dict()

    start = nxlog.find("ip=")
    if start < 0:
        errors.append('%s is an invalid extlog, string "ip=" not found.' % nxlog)
        return errors, ret

    end = nxlog.find(", ")
    if end < 0:
        errors.append('%s is an invalid extlog, string "," not found.' %nxlog)
        return errors, ret

    # Flatten the dict, since parse_qs is a bit annoying
    ret = parse_qs(nxlog[start:end])
    for key, value in ret.items():
        ret[key] = value[0]

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
            named.append("id <strong>{}</strong> in var named <strong>{}</strong> of zone <strong>{}</strong>".format(
                nxlog[_id], nxlog[_var_name], nxlog[_zone]))
        else:
            named.append("id <strong>{}</strong> in zone <strong>{}</strong>".format(nxlog[_id], nxlog[_zone]))
        cpt += 1
    explain += ' and '.join(named)

    return explain

