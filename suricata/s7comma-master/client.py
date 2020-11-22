import snap7
import time

class Client:
    def __init__(self, IP):
        self.cli = snap7.client.Client()
        self.cli.create()
        self.ip = IP
    
    @staticmethod
    def _log(mess):
        print('[+] {}'.format(mess))

    def connect(self):
        self._log('Connection...')
        self._log('Connected: ' + str(self.cli.get_connected()))
        self.cli.connect(self.ip, 0,0) # <- ya hz chto eto za dva argumenta
        self._log('Connected: ' + str(self.cli.get_connected()) + '\n')

    def disconnect(self):
        self._log('Disconnection...')
        self._log('Connected: ' + str(self.cli.get_connected()))
        self.cli.disconnect() # <- ya hz chto eto za dva argumenta
        self._log('Connected: ' + str(self.cli.get_connected()) + '\n')


if __name__ == '__main__':
    cli = Client('127.0.0.1')
    cli.connect()
    cli.cli.ab_write(0, b'Hello World')
    time.sleep(20)
    cli.disconnect()
