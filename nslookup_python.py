import subprocess
from logger import b_logger
from logger import get_default_logger
main_logger = get_default_logger()


class nslookup_python():
    def __init__(self, types, url):
        self.types = types
        self.url = url
        self.all_information = []

    @b_logger(my_logger=main_logger)
    def run(self):
        for type in self.types:
            command = "nslookup -type=" + type + " " + self.url
            process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
            output, error = process.communicate()
            if error:
                continue
            self.all_information.append(output.decode())
        return self.all_information