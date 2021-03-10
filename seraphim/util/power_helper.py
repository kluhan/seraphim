def repeated_square(value_to_pow):
    res = 2
    running = True
    while running:
        if res * 2 < value_to_pow:
            res = res * 2
        else:
            running = False
            return res

    return res


def squre_power_calc(value_to_pow):
    return 1


def little_fermat(base, value_to_pow):
    """Subtracts the base-1 from the power, because a number to the power of the base-1 is always 1 if base is prime

    Args:
        base: Mod base, for the inverse to check.
        value_to_pow: Power to use for Fermat

    Returns:
        Returns the rest power after Fermat
    """
    while value_to_pow > base:
        value_to_pow = value_to_pow - (base - 1)
    return value_to_pow
