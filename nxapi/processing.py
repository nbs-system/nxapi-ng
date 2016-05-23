import re

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

    for key, value in nxlog.items():
        if key.startswith('zone'):
            number = key[len('zone'):]
            _id = nxlog['id' + number]
            for zone in rule['mz']:
                if value in zone:  # great, the zone in the nxlog is present in the rule
                    if zone.startswith('$'):  # a specific variable in the rule's current zone
                        if zone.split(':')[1] == nxlog['var_name' + number]:  # the variable is matching!
                            continue
                else:
                    return False


            # One of the zones in the nxlog isn't in the rule.
            if not any(value.startswith(zone) for zone in rule['mz']):
                return False
    return True
