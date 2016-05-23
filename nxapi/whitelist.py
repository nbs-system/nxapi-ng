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
            __validate_mz(warnings, errors, piece[3:])
            ret['mz'] = piece[3:]
        elif piece == 'negative':
            ret['negative '] = True
        else:
            errors.append('Unknown fragment: {}'.format(piece))
            return errors, warnings, ret

    if 'BasicRule' not in split:
        errors.append("No 'BasicRule' keyword in {}.".format(str_wl))
        return errors, warnings, ret

    return errors, warnings, ret


def validate(wl):
    warnings = list()
    errors = list()
    __validate_wl(warnings, errors, wl['wl'])
    __validate_mz(warnings, errors, wl['mz'])
    return errors, warnings


def __validate_mz(warnings, errors, mz):
    valid_zones = ['ARGS', 'HEADERS', 'BODY', 'URL']
    valid_named_zones = ['$%s_VAR' % i for i in valid_zones]
    valid_regexp_zones = [i + '_X' for i in valid_named_zones]

    _mz = mz.split('|')
    for m in _mz:
        try:
            s = m.split(':', 1)
            if not s[1].islower():
                warnings.append('The expression %s is not in lowercase.' % s[1])
        except IndexError:
            continue

    if len(_mz) > 3:
        errors.append('The matchzone has more than 2 pipes.')
        return errors, warnings
    elif len(_mz) == 3:
        if _mz[2] != 'NAME':
            errors.append('The last argument of your matchzone with two pipes is not "NAME"')
            return errors, warnings
        elif _mz[0].endswith('_X') ^ _mz[1].endswith('_X') and _mz[1] != 'NAME':
            errors.append('You can not use regexp matchzone with non-regexp one' % _mz)
            return errors, warnings
    elif len(_mz) == 2:
        if _mz[0].endswith('_X') ^ _mz[1].endswith('_X') and _mz[1] != 'NAME':
            errors.append('You can not use regexp matchzone with non-regexp one' % _mz)
            return errors, warnings
    elif len(_mz) == 1:
        if not any(mz.startswith(i + ':') for i in valid_zones + valid_named_zones + valid_regexp_zones):
            errors.append('The matchzone %s is not valid.' % mz)
            return errors, warnings
    return errors, warnings


def __validate_wl(warnings, errors, wl):
    """
    :param list of str warnings:
    :param list of str errors:
    :param str wl:
    :return list, list: warnings, errors
    """
    for wid in wl:
        try:
            int(wid)
        except ValueError:
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
