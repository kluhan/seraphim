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
        

def get_inverse(base,value_to_inverse):
    return __extended_euclid(base,value_to_inverse)

def __extended_euclid(base,value_to_inverse):

    q = int(base / value_to_inverse)
    if(q < 0):
        q = 0
    a = value_to_inverse
    r = base-(q*a)
    res = base

    if r == 0:
        logging.error(f"ERROR - UNDEFINED INVERSE Base: {base}, Value: {value_to_inverse}")
        raise InversionError("r = base-(q*a)",f"ERROR - UNDEFINED INVERSE Base: {base}, Value: {value_to_inverse}")

    x0 = 0
    x1 = 1

    while(r != 0):
        invers = (x0 - x1 * q ) % base

        res = a
        a = r

        q = int(res/ a)
        if(q < 0):
            q = 0
        
        r = res-(q*a)

        x0 = x1
        x1 = invers

    if r == invers:
            logging.error(f"ERROR - UNDEFINED INVERSE Base: {base}, Value: {value_to_inverse}")
            raise InversionError("r = base-(q*a)",f"ERROR - UNDEFINED INVERSE Base: {base}, Value: {value_to_inverse}")

    return invers



   







    
