import re
import shlex


def parse(str_wl):
    """

    :param str str_wl:
    :return list, list dict: A list of errors, a list of warnings, and a dict representation of the `str_wl`
    """
    warnings = list()
    errors = list()
    ret = dict()

    lexer = shlex.shlex(str_wl, posix=True)
    lexer.whitespace_split = True
    try:
        split = list(lexer)
    except ValueError:
        errors.append('No closing quotation in your whitelist')
        return errors, warnings, ret

    for piece in split:
        if piece.endswith(";"):  # remove semi-colons
            piece = piece[:-1]

        if piece == 'BasicRule':
            continue
        elif piece.startswith('wl:'):
            __validate_wl(warnings, errors, piece[3:].split(','))
            if errors:
                return errors, warnings, ret
            ret['wl'] = [int(i) for i in piece[3:].split(',')]
        elif piece.startswith('mz:'):
            ret['mz'] = piece[3:]
        elif piece == 'negative':
            ret['negative ']= True
        else:
            errors.append('Unknown fragment: {}'.format(piece))
            return errors, warnings, ret

        #if not piece.islower():
        #    warnings.append('Your whitelist is not completely in lowercase.')

    if 'BasicRule' not in split:
        errors.append("No 'BasicRule' keyword in {}.".format(str_wl))
        return errors, warnings, ret

    return errors, warnings, ret


def validate(wl):
    warnings = list()
    errors = list()
    __validate_wl(warnings, errors, wl['wl'])
    return errors, warnings


def __validate_wl(warnings, errors, wl):
    """
    :param list of str warnings:
    :param list of str errors:
    :param str wl:
    :return list, list: warnings, errors
    """
    for wid in wl:
        if not re.match(r'(\-?\d+,)*\-?\d+', wid):
            errors.append('Illegal character in the wl.')
    return errors, warnings


def explain(wlist):
    def __linkify_rule(_rid):
        return _rid
        #if NaxsiRules.query.filter(NaxsiRules.sid == self.wid).first() is None:
        #    return _rid
        #return '<a href="{}">{}</a>'.format(url_for('rules.view', sid=_rid), self.wid)
    ret = 'Whitelist '
    for wil in wlist['wl']:
        if 0 == wil:
            ret += 'all rules'
        else:
            zones = list()
            if wil < 0:
                    zones.append('except the rule {}'.format(__linkify_rule(abs(wil))))
            else:
                zones.append('the rule {}'.format(__linkify_rule(wil)))
            ret += ', '.join(zones)

    if 'mz' in wlist:
        return ret + ' if matching in {}.'.format(wlist['mz'])
    return ret + '.'
