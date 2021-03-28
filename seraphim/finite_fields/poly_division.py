from seraphim.finite_fields.polynomial import Polynomial as polyn

# Koeffizienten vom Typ ModuloKlasse benutzen
def poly_ext_synth_division(poly, divisor):
    dividend = poly.coefficients
    dividend.reverse()
    rev_div = divisor.coefficients
    rev_div.reverse()

    out = list(dividend)
    normalizer = rev_div[0]

    for i in range(len(dividend) - (len(rev_div) - 1)):
        out[i] /= normalizer
        coef = out[i]

        if coef != 0:
            for j in range(1, len(rev_div)):
                out[i + j] += -rev_div[j] * coef

    separator = -(len(rev_div) - 1)

    coef_quotient = out[:separator]
    coef_remainder = out[separator:]

    coef_quotient.reverse()
    coef_remainder.reverse()
    return polyn.Polynomial(coef_quotient), polyn.Polynomial(coef_remainder)
