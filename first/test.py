import socket
import subprocess
import os
import threading

GREEN = '\033[92m'
RED = '\033[91m'
BLACK = '\033[0m'


class Tester:
    def __init__(self, port: int, host: str='', requires_server: bool=False):
        self.port = port
        self.host = host
        assert os.system("make clean") == 0, "Make clean failed"
        assert os.system("make") == 0, "Make failed"
        if not requires_server:
            self.run()
        else:
            pass
            #self.run_server()

    
    def test_success(self, test_name: str):
        print(GREEN + "Test {} passed".format(test_name) + BLACK)

    def test_fail(self, test_name: str):
        print(RED + "Test {} failed".format(test_name) + BLACK)

class ArgumentTester(Tester):
    def __init__(self, port: int, host: str=''):
        super().__init__(port, host)

    def assert_eq(self, a, b, msg):
        self.test_success(msg) if a == b else self.test_fail(msg)

    def assert_empty(self, a, msg):
        self.test_success(msg) if a == '' else self.test_fail(msg)

    def assert_not_empty(self, a, msg):
        self.test_success(msg) if a != '' else self.test_fail(msg)


    # these tests should fail
    def run(self):
        tests = ["./ipkcpc", 
                 "./ipkcpc -h", 
                 "./ipkcpc -p", 
                 "./ipkcpc -m",
                 "./ipkcpc -h merlin.fit.vutbr.cz",
                 "./ipkcpc -h 12345 -m",
                 "./ipkcpc -h merlin.fit.vutbr.cz -p merlin.fit.vutbr.cz -m tcp",
                 "./ipkcpc -h merlin.fit.vutbr.cz -p merlin.fit.vutbr.cz -m udp",
                 "./ipkcpc -h merlin.fit.vutbr.cz -p 10000 -m icmp",
                 "./ipkcpc -h merlin.fit.vutbr.cz -p 10000 -m sctp",
                 "./ipkcpc -p 10000 -h merlin.fit.vutbr.cz -m tcp",
                 "./ipkcpc -p 10000 -h merlin.fit.vutbr.cz -m udp",
                 "./ipkcpc -m tcp -h merlin.fit.vutbr.cz -p 10000"]

        for test in tests:
            process = subprocess.Popen(test, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout = process.communicate()[0].decode('utf-8')
            stderr = process.communicate()[1].decode('utf-8')
            exit_code = int(process.returncode)

            self.assert_eq(exit_code, 1, "Expected exit code 1, got {}".format(exit_code))
            self.assert_empty(stdout, "{} should not print anything to stdout".format(test))
            self.assert_not_empty(stderr, "{} should print something to stderr".format(test))


HOST = ''
PORT = 12345

arg_tester = ArgumentTester(PORT, HOST)

exit(0)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen(1)
conn, addr = s.accept()


