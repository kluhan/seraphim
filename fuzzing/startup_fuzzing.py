from tests.finite_fields.fuzzing.uwu_test_finite_field_fuzz import (
    FiniteFieldElementFuzzing,
)
from tests.mod_arithmetic.fuzzing.uwu_test_modularearithmetic_eff_fuzz import (
    ModArithmeticFuzzing,
)
from tests.primge_generator.fuzzing.uwu_test_prime_generater_fuzz import (
    PrimeGeneratorFuzzing,
)


# ModArithmeticFuzzing().test_bigNumbers_fuzzing()
# ModArithmeticFuzzing().test_modularearythmetic_eff_fuzzing()
PrimeGeneratorFuzzing().test_prime_generator_fuzzing()
# FiniteFieldElementFuzzing().test_finite_field_fuzzing()
# FiniteFieldElementFuzzing().test_polynomarithmetic_fuzzing()
