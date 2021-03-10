# Python Module extended_euclidean

import logging


class Error(Exception):
    """Base class for exceptions in this module."""

    pass


class InversionError(Error):
    """Exception raised for errors in the input.

    Attributes:
        expression -- input expression in which the error occurred
        message -- explanation of the error
    """

    def __init__(self, expression, message):
        self.expression = expression
        self.message = message


def get_inverse(base, value_to_inverse):
    """Searches the Inverse of an given value_to_inverse.

    Args:
        base: Mod base, for the inverse to check.
        value_to_inverse: Value to check for inverse

    Returns:
        Returns the inverse to value_to_inverse
    """
    return __extended_euclid(base, value_to_inverse)


## ungültige werte checken ! -1, 3,5 !
## input auf gültigkeit prüfen/ plausibilty (zahlen dürfen nur aus N sein!)
def __extended_euclid(base, value_to_inverse):

    # init to get first step in Euclid from the vlaues
    q = int(base / value_to_inverse)
    if q < 0:
        q = 0
    a = value_to_inverse
    rest = base - (q * a)
    result = base

    if rest == 0:
        logging.error(
            f"ERROR - UNDEFINED INVERSE Base: {base}, Value: {value_to_inverse}"
        )
        raise InversionError(
            "r = base-(q*a)",
            f"ERROR - UNDEFINED INVERSE Base: {base}, Value: {value_to_inverse}",
        )

    # standard init for reverse euclid
    x0 = 0
    x1 = 1

    # Eclid and reverse Euclid iterations
    while rest != 0:
        # Reverse Euclid
        invers = (x0 - x1 * q) % base

        # Euclid
        result = a
        a = rest

        q = int(result / a)
        if q < 0:
            q = 0

        rest = result - (q * a)

        # New Values for Reverse Euclid
        x0 = x1
        x1 = invers

    if rest == invers:
        logging.error(
            f"ERROR - UNDEFINED INVERSE Base: {base}, Value: {value_to_inverse}"
        )
        raise InversionError(
            "r = base-(q*a)",
            f"ERROR - UNDEFINED INVERSE Base: {base}, Value: {value_to_inverse}",
        )

    return invers
