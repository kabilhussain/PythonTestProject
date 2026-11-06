"""Maintainability problems: complexity, duplication, style, dead code."""
import os, sys, json  # BUG C1: multiple imports on one line, unused imports
from math import *  # BUG C2: wildcard import


GLOBAL_COUNTER = 0


class userManager:  # BUG C3: class name not CamelCase
    def __init__(self, Name, Age, Email, Phone, Address, City, Country, Zip):
        # BUG C4: too many parameters, bad arg naming
        self.Name = Name
        self.Age = Age
        self.Email = Email
        self.Phone = Phone
        self.Address = Address
        self.City = City
        self.Country = Country
        self.Zip = Zip

    def ProcessUser(self):  # BUG C5: method naming
        global GLOBAL_COUNTER  # BUG C6: global statement
        GLOBAL_COUNTER += 1
        return self.Name

    def get_info(self):
        # BUG C7: method could be a function / doesn't use self
        return "info"

    def __eq__(self, other):
        # BUG C8: __eq__ without __hash__
        return self.Name == other.Name


def complex_function(a, b, c, d, e):
    # BUG C9: very high cognitive / cyclomatic complexity, deep nesting
    result = 0
    if a > 0:
        if b > 0:
            if c > 0:
                if d > 0:
                    if e > 0:
                        for i in range(a):
                            if i % 2 == 0:
                                for j in range(b):
                                    if j % 3 == 0:
                                        while c > 0:
                                            if d > e:
                                                result += 1
                                            elif d < e:
                                                result -= 1
                                            else:
                                                result *= 2
                                            c -= 1
                    else:
                        result = -1
                else:
                    result = -2
            else:
                result = -3
        else:
            result = -4
    else:
        result = -5
    return result


# BUG C10: duplicated code blocks (copy/paste)
def calculate_tax_a(amount):
    if amount < 0:
        raise ValueError("negative")
    tax = 0
    if amount > 10000:
        tax = amount * 0.3
    elif amount > 5000:
        tax = amount * 0.2
    elif amount > 1000:
        tax = amount * 0.1
    else:
        tax = 0
    total = amount + tax
    print("Total: " + str(total))
    return total


def calculate_tax_b(amount):
    if amount < 0:
        raise ValueError("negative")
    tax = 0
    if amount > 10000:
        tax = amount * 0.3
    elif amount > 5000:
        tax = amount * 0.2
    elif amount > 1000:
        tax = amount * 0.1
    else:
        tax = 0
    total = amount + tax
    print("Total: " + str(total))
    return total


def calculate_tax_c(amount):
    if amount < 0:
        raise ValueError("negative")
    tax = 0
    if amount > 10000:
        tax = amount * 0.3
    elif amount > 5000:
        tax = amount * 0.2
    elif amount > 1000:
        tax = amount * 0.1
    else:
        tax = 0
    total = amount + tax
    print("Total: " + str(total))
    return total


def magic_numbers(x):
    # BUG C11: magic numbers
    return x * 86400 + 3600 * 24 - 42 / 3.14159


def empty_function():
    # BUG C12: empty function body with TODO
    # TODO: implement this
    # FIXME: this is broken
    pass


def commented_out_code():
    # BUG C13: commented-out code
    # x = compute_everything()
    # if x > 10:
    #     return x
    return None


def long_line():
    # BUG C14: line too long
    return "This is a really long line that goes well beyond the recommended seventy nine or even one hundred and twenty characters limit used by most linters"


def bad_spacing( a,b ):
    x=a+b  # BUG C15: whitespace/style violations
    if(x>10):return x
    return  x


def too_many_returns(x):
    # BUG C16: too many return statements
    if x == 1:
        return "one"
    if x == 2:
        return "two"
    if x == 3:
        return "three"
    if x == 4:
        return "four"
    if x == 5:
        return "five"
    if x == 6:
        return "six"
    if x == 7:
        return "seven"
    return "many"


def lambda_assignment():
    f = lambda x: x * 2  # BUG C17: lambda assigned to a name  # noqa: E731
    return f(2)


def print_debug(data):
    print("DEBUG:", data)  # BUG C18: leftover debug print
    return data


class EmptyClass:
    pass


def unused_argument(a, b, c):  # BUG C19: unused arguments
    return a
