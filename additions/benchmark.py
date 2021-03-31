import time
import secrets
from progress.bar import Bar
from seraphim.prime_generator.primeGenerator import prime_generator
from seraphim.elliptic_curves.elliptic_curve import EllipticCurve




class PrimeBenchmark:
    loop_count = 100
    sizes = [128, 256, 512]
    reference_algorithm = 2
    accuracy = 10
    algorithms = [(0, "Fermat@      "), (1, "Miller-Rabin@"), (2, "Referenze@   ")]

    def run(self):
        for size in self.sizes:
            times = []
            for algorithm in self.algorithms:
                bar = Bar(
                    algorithm[1].replace("@", "@" + str(size)),
                    suffix="%(percent).1f%% - ETA: %(eta)ds - AVG: %(avg).5fs - ELA: %(elapsed)ds",
                    max=self.loop_count,
                )
                t = time.process_time()

                for _ in range(self.loop_count):
                    _ = next(prime_generator(size, self.accuracy, algorithm[0]))
                    bar.next()

                elapsed_time = time.process_time() - t
                times.append((algorithm[1].replace("@", ""), elapsed_time))
                bar.finish()
            print(f"\n--Summary@{ size }: ")
            for algo_time in times:
                factor = "{:.2f}".format(
                    times[self.reference_algorithm][1] / algo_time[1]
                )
                print(f"    { algo_time[0] }: { factor }")
            print(
                "\n------------------------------------------------------------------------------------------------"
            )

class CurveBenchmark:
    loop_count = 100
    sizes = [128, 256, 512]
    reference_algorithm = 0
    algorithms = [(0, "Projective@      ", EllipticCurve([ 0, 1, 486662, 1 ], (2 ** 255) - 19, 9, projective=True)), (1, "Affine@         ", EllipticCurve([ 0, 1, 486662, 1 ], (2 ** 255) - 19, 9, projective=False))]

    def run(self):
            for size in self.sizes:
                times = []
                for algorithm in self.algorithms:
                    bar = Bar(
                        algorithm[1].replace("@", "@" + str(size)),
                        suffix="%(percent).1f%% - ETA: %(eta)ds - AVG: %(avg).5fs - ELA: %(elapsed)ds",
                        max=self.loop_count,
                    )
                    t = time.process_time()

                    for _ in range(self.loop_count):

                        secret_alice = secrets.randbits(size)
                        secret_bob = secrets.randbits(size)

                        alice_point = algorithm[2].getGenerator()
                        bob_point = algorithm[2].getGenerator()

                        alice_point = alice_point * secret_alice
                        bob_point = bob_point * secret_bob

                        bob_recived = alice_point
                        alice_recived = bob_point

                        alice_key = alice_recived * secret_alice
                        bob_key = bob_recived * secret_bob

                        assert bob_key == alice_key

                        assert bob_key.serialize() == alice_key.serialize()




                        bar.next()

                    elapsed_time = time.process_time() - t
                    times.append((algorithm[1].replace("@", ""), elapsed_time))
                    bar.finish()

                print(f"\n--Summary@{ size }: ")
                for algo_time in times:
                    factor = "{:.2f}".format(
                        times[self.reference_algorithm][1] / algo_time[1]
                    )
                    print(f"    { algo_time[0] }: { factor }")
                print(
                    "\n------------------------------------------------------------------------------------------------"
                )








CurveBenchmark().run()
PrimeBenchmark().run()