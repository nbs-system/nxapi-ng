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
            __validate_wl(warnings, errors, piece[3:])
            if errors:
                return errors, warnings, ret
            ret['wl'] = piece[3:]
        elif piece.startswith('mz:'):
            ret['mz'] = piece[3:]
        elif piece == 'negative':
            ret['negative ']= True
        else:
            errors.append('Unknown fragment: {}'.format(piece))
            return errors, warnings, ret

        if not piece.islower():
            warnings.append('Your whitelist is not completely in lowercase.')

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
    if not re.match(r'(\-?\d+,)*\-?\d+', wl):
        errors.append('Illegal character in the wl.')
    return errors, warnings


def explain(wlist):
    def __linkify_rule(_rid):
        return _rid
        #if NaxsiRules.query.filter(NaxsiRules.sid == self.wid).first() is None:
        #    return _rid
        #return '<a href="{}">{}</a>'.format(url_for('rules.view', sid=_rid), self.wid)

    if wlist['wl'] == '0':
        ret = 'Whitelist all rules'
    elif wlist['wl'].isdigit():
        ret = 'Whitelist the rule {}'.format(__linkify_rule(wlist['wl']))
    else:
        zones = list()
        for rid in wlist['wl'].split(','):
            if rid.startswith('-'):
                zones.append('except the rule {}'.format(__linkify_rule(rid[1:])))
            else:
                zones.append('the rule {}'.format(__linkify_rule(rid)))
        ret = 'Whitelist ' + ', '.join(zones)

    if not wlist['mz']:
        return ret + '.'

    return ret + ' if matching in {}.'.format(wlist['mz'])