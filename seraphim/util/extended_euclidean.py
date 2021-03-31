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


def get_inverse(base, value_to_inverse, current_value):
    """Searches the Inverse of an given value_to_inverse.
    Args:
        base: Mod base, for the inverse to check.
        value_to_inverse: Value to check for inverse
    Returns:
        Returns the inverse to value_to_inverse
    """
    return __extended_euclid(base, value_to_inverse, current_value)

def __extended_euclid(base, value_to_inverse, current_value):
    """
    Calculate Inverse Element to value_to_inverse or Raises Error, if not Possible
    Iterate the extended Euclidean Algyrthm to find an Inverse element of the given Value
    Args:
        base: Mod base, for the inverse to check.
        value_to_inverse: Value to check for inverse
        current_value: Current Value given in teh division, only used to Improve errors
    Returns:
        Returns the inverse to value_to_inverse
    """

    value_to_inverse = value_to_inverse % base
    # init to get first step in Euclid from the vlaues
    q = int(base / value_to_inverse)
    a = value_to_inverse
    rest = base - (q * a)
    result = base
    # standard init for reverse euclid
    x0 = 0
    x1 = 1

    if rest == 0:
        logging.error(
            "ERROR - CANNOT DO %s/%s mod %s | UNDEFINED INVERSE FOR mod: %s, Value: %s",
            current_value,
            value_to_inverse,
            base,
            base,
            value_to_inverse,
        )
        raise InversionError(
            "r = base-(q*a)",
            (
                "ERROR - UNDEFINED INVERSE Base: %s, Value: %s",
                base,
                value_to_inverse,
            ),
        )

    # Eclid and reverse Euclid iterations
    while rest != 0:
        # Reverse Euclid Calculation
        invers = (x0 - x1 * q) % base

        # Calculate new Values to use in Reverse Euclid
        result = a
        a = rest
        q = int(result / a)
        rest = result - (q * a)

        # New Values for Reverse Euclid
        x0 = x1
        x1 = invers

    if rest == invers:
        logging.error(
            "ERROR - CANNOT DO %s/%s mod %s | UNDEFINED INVERSE 234124 FOR mod: %s, Value: %s",
            current_value,
            value_to_inverse,
            base,
            base,
            value_to_inverse,
        )
        raise InversionError(
            "r = base-(q*a)",
            "ERROR - UNDEFINED INVERSE Base: {base}, Value: {value_to_inverse}",
        )

    return invers