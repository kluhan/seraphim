import time
from progress.bar import Bar
from primeGenerator import prime_generator


class Benchmark:
    loop_count = 100
    sizes = [128, 256, 512, 1024, 2048, 4096]
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
