from shlex import shlex
import collections

mr_kw = ["MainRule", "BasicRule", "main_rule", "basic_rule"]
static_mz = {"$ARGS_VAR", "$BODY_VAR", "$URL", "$HEADERS_VAR"}
full_zones = {"ARGS", "BODY", "URL", "HEADERS", "FILE_EXT", "RAW_BODY"}
rx_mz = {"$ARGS_VAR_X", "$BODY_VAR_X", "$URL_X", "$HEADERS_VAR_X"}
sub_mz = list(static_mz) + list(full_zones) + list(rx_mz)

"""
    A rule is a dict with (at least) the following fields:
        - negative
        - detection
        - msg
        - mz
        - score
        - sid
"""


def short_str(rule):
    """
    :param dict rule:
    :return str: A _short_ textual representation of the `rule`
    """
    return 'MainRule {} "{}" "msg:{}" "mz:{}" "s:{}" id:{} ;'.format(
        'negative' if rule.get('negative', '') else '', rule['detection'], rule['msg'], rule['mz'], rule['score'],
        rule['sid'])


def explain(rule):
    """ Return a string explaining the `rule`.

    :param dict rule:
    :return str: A textual explanation of the rule
    """
    translation = {'ARGS': 'argument', 'BODY': 'body', 'URL': 'url', 'HEADER': 'header',
                   'HEADER:Cookie': 'cookies'}
    explanation = 'The rule number <strong>{0}</strong> is '.format(rule['sid'])
    if rule['negative']:
        explanation += '<strong>not</strong> '
    explanation += 'setting the '

    scores = []
    for score in rule['score'].split(','):
        scores.append('<strong>{0}</strong> score to <strong>{1}</strong> '.format(*score.split(':', 1)))
    explanation += ', '.join(scores) + 'when it '
    if rule['detection'].startswith('str:'):
        explanation += 'finds the string <strong>{}</strong> '.format(rule['detection'][4:])
    else:
        explanation += 'matches the regexp <strong>{}</strong> in '.format(rule['detection'][3:])

    zones = []
    for mz in rule['mz'].split('|'):
        if mz.startswith('$'):
            current_zone, arg = mz.split(":", 1)
            zone_name = "?"

            for translated_name in translation:  # translate zone names
                if translated_name in current_zone:
                    zone_name = translation[translated_name]

            if "$URL" in current_zone:
                regexp = "matching regex" if current_zone == "$URL_X" else ""
                zones.append("on the URL {} '{}' ".format(regexp, arg))
            else:
                regexp = "matching regex" if current_zone.endswith("_X") else ""
                if zone_name == 'header' and arg.lower() == 'cookie':
                    zones.append('in the <strong>cookies</strong>')
                else:
                    zones.append("in the var with name {} '{}' of {} ".format(regexp, arg, zone_name))
        else:
            zones.append('the <strong>{0}</strong>'.format(translation[mz]))
    return explanation + ' ' + ', '.join(zones) + '.'


def test_rule(rule, request):
    if rule['detection'].startswith('rx:'):
        try:
            import pcre
        except ImportError:
            raise ImportError


def parse_rule(full_str):
    """
    Parse and validate a full naxsi rule
    :param str full_str: Textual representation of a rule.
    :return list, list, dict:
    """
    warnings = list()
    errors = list()
    ret = collections.defaultdict(str)

    func_map = {"id:": __validate_id, "str:": lambda e, w, p_str: True,
                "rx:": __validate_detection_rx, "msg:": lambda e, w, p_str: True,
                "mz:": __validate_matchzone, "negative": lambda e, w, p_str: p_str == 'checked',
                "s:": __validate_score}

    lexer = shlex(full_str, posix=True)
    lexer.whitespace_split = True
    try:
        split = list(lexer)
    except ValueError:
        errors.append('No closing quotation in your rule')
        return errors, warnings, ret

    duplicate = [k for k,v in collections.Counter(split).items() if v > 1]
    if duplicate:
        errors.append("Duplicates elements: %s" % ', '.join(duplicate))
        return errors, warnings, ret

    if 'BasicRule' in split and 'MainRule' in split:
        errors.append("Both BasicRule and MainRule are present.")
        return errors, warnings, ret

    intersection = set(split).intersection(set(mr_kw))
    if not intersection:
        errors.append("No mainrule/basicrule keyword.")
        return errors, warnings, ret

    split.remove(intersection.pop())  # remove the mainrule/basicrule keyword

    if ";" in split:
        split.remove(";")

    for keyword in split:
        keyword = keyword.strip()

        if keyword.endswith(";"):  # remove semi-colons
            keyword = keyword[:-1]

        parsed = False
        for frag_kw in func_map:
            if keyword.startswith(frag_kw):  # use the right parser
                if frag_kw in ('rx:', 'str:'):  # don't remove the leading "str:" or "rx:"
                    payload = keyword
                else:
                    payload = keyword[len(frag_kw):]

                function = func_map[frag_kw]  # we're using an array of functions, C style!
                function(warnings, errors, payload)
                if not errors:
                    parsed = True
                    if frag_kw == 'mz:':  # we want matchzones in a list
                        payload = payload.split('|')
                    ret[keyword[:len(frag_kw)]] = payload
                    break
                errors.append("parsing of element '{0}' failed.".format(keyword))
                return errors, warnings, ret

        if parsed is False:  # we have an item that wasn't successfully parsed
            errors.append("'{}' is an invalid element and thus can not be parsed.".format(keyword))
            break
    return errors, warnings, ret


def validate(rule):
    """

    :param dict rule: Validate a `rule`
    :return list, list: An array of errors, and another of warnings
    """
    warnings = list()
    errors = list()

    if 'msg' not in rule:
        warnings.append("Rule has no 'msg:'.")
    if 'score' not in rule:
        errors.append("Rule has no score.")
    if 'mz' not in rule:
        errors.append("Rule has no match zone.")
    if 'sid' not in rule:
        errors.append("Rule has no sid.")

    __validate_matchzone(warnings, errors, rule['mz'])
    __validate_id(warnings, errors, rule['sid'])
    __validate_score(warnings, errors, rule['score'])

    if rule['detection'].startswith('rx:'):
        __validate_detection_rx(warnings, errors, rule['detection'])
    elif rule['detection'].startswith('str:'):
        pass  # There is nothing to validate in a string.
    else:
        errors.append("Your 'detection' string must either start with 'str:' or 'rx:'.")

    return errors, warnings


# Bellow are parsers for specific parts of a rule

def __validate_detection_rx(warnings, errors, p_str):
    if not p_str.islower():
        warnings.append("detection {} is not lower-case. naxsi is case-insensitive".format(p_str))

    try:  # try to validate the regex with PCRE's python bindings
        import pcre
        try:  # if we can't compile the regex, it's likely invalid
            pcre.compile(p_str[3:])
        except pcre.PCREError:
            errors.append("{} is not a valid regex:".format(p_str))
    except ImportError:  # python-pcre is an optional dependency
        pass
    return errors, warnings


def __validate_score(warnings, errors, p_str):
    for score in p_str.split(','):
        if ':' not in score:
            errors.append("You score '{}' has no value or name.".format(score))
        name, value = score.split(':')
        if not value.isdigit():
            errors.append("Your value '{}' for your score '{}' is not numeric.".format(value, score))
        elif not name.startswith('$'):
            errors.append("Your name '{}' for your score '{}' does not start with a '$'.".format(name, score))
    return errors, warnings


def __validate_matchzone(warnings, errors, p_str):
    has_zone = False
    mz_state = set()
    for loc in p_str.split('|'):
        keyword, arg = loc, None
        if loc.startswith("$"):
            if loc.find(":") == -1:
                errors.append("Missing 2nd part after ':' in {0}".format(loc))
            keyword, arg = loc.split(":")

        if keyword not in sub_mz:  # check if `keyword` is a valid keyword
            errors.append("'{0}' is not a known sub-part of mz : {1}".format(keyword, sub_mz))

        mz_state.add(keyword)

        # verify that the rule doesn't attempt to target REGEX and STATIC _VAR/URL at the same time
        if len(rx_mz & mz_state) and len(static_mz & mz_state):
            errors.append("You can't mix static $* with regex $*_X ({})".format(', '.join(mz_state)))

        if arg and not arg.islower():  # just a gentle reminder
            warnings.append("{0} in {1} is not lowercase. naxsi is case-insensitive".format(arg, loc))

        # the rule targets an actual zone
        if keyword not in ["$URL", "$URL_X"] and keyword in (rx_mz | full_zones | static_mz):
            has_zone = True

    if has_zone is False:
        errors.append("The rule/whitelist doesn't target any zone.")
    return errors, warnings


def __validate_id(warnings, errors, p_str):
    try:
        num = int(p_str)
        if num < 10000:
            warnings.append("rule IDs below 10k are reserved ({0})".format(num))
    except ValueError:
        errors.append("id:{0} is not numeric".format(p_str))
    return errors, warnings
