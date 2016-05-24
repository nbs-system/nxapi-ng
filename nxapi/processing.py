import re
import itertools

def process(rule, nxlog):
    """

    :param dict rule:
    :param dict nxlog:
    :return bool: Did the rule blocked the nxlog?
    """
    return True


def check_whitelist(rule, nxlog):
    """

    :param  dict rule:
    :param dict nxlog:
    :return bool: Did the `rule` whitelisted the `nxlog`?
    """
    for mz in rule['mz'].split('|'):
        for nb in itertools.count():
            zone = nxlog.get('zone%d' % nb, '')
            if not zone:
                break
            elif zone not in mz:
                return False
    return True