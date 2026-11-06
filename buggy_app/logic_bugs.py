"""Reliability bugs: code that runs but behaves incorrectly."""
import logging

logger = logging.getLogger(__name__)


def append_item(item, items=[]):
    # BUG L1: mutable default argument shared between calls
    items.append(item)
    return items


def average(numbers):
    # BUG L2: ZeroDivisionError on empty list
    return sum(numbers) / len(numbers)


def is_none(value):
    # BUG L3: identity comparison should be "is None"
    return value == None  # noqa: E711


def compare_strings(a, b):
    # BUG L4: "is" used to compare strings / literals
    return a is "hello" or a is b  # noqa: F632


def safe_divide(a, b):
    try:
        return a / b
    except:  # BUG L5: bare except swallows everything incl. KeyboardInterrupt
        pass


def parse_int(text):
    try:
        return int(text)
    except Exception:
        # BUG L6: exception silently swallowed
        pass
    return 0


def last_element(values):
    # BUG L7: off-by-one -> IndexError
    return values[len(values)]


def find_index(values, target):
    for i in range(len(values)):
        if values[i] == target:
            return i
    # BUG L8: inconsistent return (implicit None vs int)


def compute_discount(price, is_member):
    if is_member:
        discount = 0.1
    # BUG L9: 'discount' possibly unbound
    return price * (1 - discount)  # noqa: F821


def remove_negatives(values):
    # BUG L10: modifying a list while iterating over it
    for v in values:
        if v < 0:
            values.remove(v)
    return values


def check_status(status):
    # BUG L11: identical branches / duplicated condition
    if status == "ok":
        return True
    elif status == "ok":
        return True
    else:
        return True


def always_true(x):
    # BUG L12: condition is always true
    if x or True:
        return 1
    return 0


def self_assign(value):
    # BUG L13: self-assignment does nothing
    value = value
    return value


def unreachable(x):
    return x * 2
    # BUG L14: dead code after return
    print("never printed")


def compare_float(a, b):
    # BUG L15: float equality comparison
    return a + b == 0.3


def shadow_builtins(list, dict, id):  # noqa: A002
    # BUG L16: shadowing builtins
    return list, dict, id


def string_format_mismatch(name):
    # BUG L17: wrong number of format args -> TypeError at runtime
    return "Hello %s, you are %d years old" % (name)


def wrong_logging(user):
    # BUG L18: string formatting in logging call, wrong arg count
    logger.info("User %s logged in from %s", user)


def infinite_loop(n):
    # BUG L19: loop variable never changes -> infinite loop when n > 0
    i = 0
    while i < n:
        n = n
    return i


def raise_wrong():
    # BUG L20: raising a non-exception / NotImplemented
    raise NotImplemented


def unused_variables(a, b):
    result = a + b  # BUG L21: unused local variable
    tmp = a * b  # noqa: F841
    return a


def resource_leak(path):
    # BUG L22: file never closed
    fh = open(path)
    return fh.read()


def keys_check(d):
    # BUG L23: dict.has_key style / redundant .keys()
    if "a" in d.keys():
        return d["a"]


def recursion_without_base(n):
    # BUG L24: missing base case -> RecursionError
    return recursion_without_base(n - 1) + 1


def type_confusion(value):
    # BUG L25: concatenating str and int -> TypeError
    return "Value: " + value + 1
