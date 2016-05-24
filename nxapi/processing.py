import itertools

def check_whitelist(rule, nxlog):
    """

    :param  dict rule:
    :param dict nxlog:
    :return bool: Did the `rule` whitelisted the `nxlog`?
    """
    negative_id = any(i < 0 for i in rule['wl'])
    for mz in rule['mz'].split('|'):
        for nb in itertools.count():
            zone = nxlog.get('zone%d' % nb, '')
            if not zone:
                break
            elif zone not in mz:
                return False

            if negative_id:
                if int(nxlog['id%d' % nb]) in rule['wl']:
                    return False
            elif int(nxlog['id%d' % nb]) not in rule['wl']:
                return False
    return True