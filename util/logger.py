import os
import json

"""
Lightweight file logger for experiment runs.

- Creates a new run directory under time_experiments (run_0, run_1, ...).
- Optionally writes a CSV header on initialization.
- Provides helpers to persist configuration (JSON) and append results rows.
"""

class Logger:
    """Utility to persist configuration and timing results for demo runs.
    """
    def __init__(self, header=None):
        self.path = os.path.join("time_experiments")

        if not os.path.isdir(self.path):
            os.makedirs(self.path)

        self.index = 0
        self.save_folder = "run_" + str(self.index)

        while os.path.isdir(os.path.join(self.path, self.save_folder)):
            self.index += 1
            self.save_folder = "run_" + str(self.index)

        self.savepath = os.path.join(self.path, self.save_folder)
        os.makedirs(self.savepath)

        print("Experiments will be saved to: ", self.savepath, flush=True)

        if header is not None:
            info = header
            with open(os.path.join(self.savepath, "results.csv"), "a") as results_file:
                results_file.write(",".join(info) + "\n")

    def log_configuration(self, config):
        with open(
            os.path.join(self.savepath, "configuration.json"), "w"
        ) as config_file:
            json.dump(config, config_file, sort_keys=True, indent=4)

    def log_results(self, info, file_name: str = "results.csv") -> None:
        info = ",".join(info) + "\n"
        with open(os.path.join(self.savepath, file_name), "a") as results_file:
            results_file.write(info)
