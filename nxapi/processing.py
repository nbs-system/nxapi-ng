import itertools
import pcre


def check_whitelist(rule, nxlog):
    """

    :param  dict rule:
    :param dict nxlog:
    :return bool: Did the `rule` whitelisted the `nxlog`?
    """
    negative_id = any(i < 0 for i in rule['wl'])
    for mz in rule['mz']:
        for nb in itertools.count():
            matched = False
            nxlog_zone = nxlog.get('zone%d' % nb, '')
            if not nxlog_zone:
                break
            if mz.startswith('$'):  # named argument
                mz_zone, mz_var = mz.split(':', 1)
                if mz_zone.endswith('_X'):  # regexp named argument
                    if pcre.match(mz_var, nxlog['var_name%d' % nb], pcre.I) and nxlog_zone == mz_zone[1:-6]:
                        matched = True
                elif nxlog['var_name%d' % nb] == mz_var and nxlog_zone == mz_zone[1:-4]:
                        matched = True
            elif nxlog_zone in mz:  # zone without argument
                matched = True

            if not matched:  # We didn't manage to match the nxlog zone `nxlog_zone` with anything in our `rule`
                return False

            if negative_id:
                if int(nxlog['id%d' % nb]) in rule['wl']:
                    return False
            elif int(nxlog['id%d' % nb]) not in rule['wl']:
                return False
    return True
