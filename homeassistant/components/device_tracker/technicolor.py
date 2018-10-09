import paramiko
import logging
import re
import voluptuous as vol

import homeassistant.helpers.config_validation as cv
from homeassistant.components.device_tracker import (
    DOMAIN, PLATFORM_SCHEMA, DeviceScanner)
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME

_LOGGER = logging.getLogger(__name__)

_DEVICES_REGEX = re.compile(
    r'(?P<number>([0-9]*))\s+'    
    r'(?P<mac>(([0-9a-f]{2}[:-]){5}([0-9a-f]{2})))\s+'
    r'(?P<ip>([0-9]{1,3}[\.]){3}[0-9]{1,3})\s+'
    r'(?P<host>([^\s]+))')

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Required(CONF_HOST): cv.string,
    vol.Required(CONF_PASSWORD): cv.string,
    vol.Required(CONF_USERNAME): cv.string
})

def get_scanner(hass, config):
    """Validate the configuration and return a THOMSON scanner."""
    scanner = TechnicolorDeviceScanner(config[DOMAIN])

    return scanner if scanner.success_init else None

class TechnicolorDeviceScanner(DeviceScanner):
    """This class queries a router running TECHNICOLOR firmware."""

    def __init__(self,config):
        """Initializes the scanner"""
        self.host = config[CONF_HOST]
        self.username = config[CONF_USERNAME]
        self.password = config[CONF_PASSWORD]
        self.last_results = {}

        #Test if the router is accessible
        data = self.get_technicolor_data()
        self.success_init = data is not None

    def scan_devices(self):
        """Scan for new devices and return a list with found device IDs."""
        self._update_info()
        return [client['mac'] for client in self.last_results]

    def get_device_name(self, device):
        """Return the name of the given device or None if we don't know."""
        if not self.last_results:
            return None
        for client in self.last_results:
            if client['mac'] == device:
                return client['host']
        return None
    
    def _update_info(self):
        """Ensure the information from the THOMSON router is up to date.

        Return boolean if scanning successful.
        """
        if not self.success_init:
            return False

        _LOGGER.info("Checking ARP")
        data = self.get_technicolor_data()
        if not data:
            return False

        self.last_results = [client for client in data.values() if
                            client['status'].find('C') != -1]
        return True

    def get_technicolor_data(self):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_stdout = ssh_stderr = None
            ssh.connect(self.host,username=self.username,password=self.password)
            _, ssh_stdout, ssh_stderr = ssh.exec_command("for ip in $(cat /proc/net/arp | grep -v IP | awk '{print $1}'); do grep $ip /tmp/dhcp.leases; done")
        except Exception as e:
            _LOGGER.exception("SSH connection error with Technicolor: {0}".format(e))
            return
        if ssh_stdout:
            devices_result = ssh_stdout.readlines().split('\r\n')
            devices = {}
            for device in devices_result:
                match = _DEVICES_REGEX.search(device.decode('utf-8'))
                if match:
                    devices[match.group('ip')] = {
                        'ip': match.group('ip'),
                        'mac': match.group('mac').upper(),
                        'host': match.group('host'),
                        'status': 'C'
                        }
        else:
            _LOGGER.exception("Couldn't retrieve ssh stdin from technicolor")

        ssh.close()   
        return devices
