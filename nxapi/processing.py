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
    for i in itertools.count():
        if 'zone%d' % i not in nxlog:
            break
        elif nxlog['zone%d' % i] == rule['mz']:
            return True
    return False

