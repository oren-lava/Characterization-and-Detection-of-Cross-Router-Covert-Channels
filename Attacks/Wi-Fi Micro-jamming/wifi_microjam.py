import pyvisa as visa
from decimal import Decimal
from time import sleep
import subprocess
from threading import Thread
from datetime import datetime, timedelta, date
import os, binascii
from dns import resolver

# configure the waveform generator
def config_waveform_generator(instrument):
    freq = 200
    duty_cycle = 80

    instrument.write('mmem:load:stat "10BPS.sta"')
    sleep(30)

    instrument.write('FUNCtion SQUare')
    instrument.write('FREQ ' + str(freq))
    instrument.write('FUNC:SQU:DCYC +' + str(duty_cycle))
    instrument.write('VOLT:HIGH +0.1')
    instrument.write('VOLT:LOW -1.9')
    instrument.write('SUM:SOURce INT')
    instrument.write('SUM:AMPLitude +100.0')
    instrument.write('SUM:STATe ON')

    print_config(instrument)

    return

def print_config(instrument):
    ql = ["sour1:func?", "sour1:func:prbs:brat?", "sour1:func:prbs:data?", "sour1:func:squ:dcyc?", "sour1:func:squ:per?", "sour1:freq?", "sour1:volt?", "sour1:volt:offs?", "sum:sour?", "sum:int:func?"]
    for q in ql:
        print(q)
        print(instrument.query(q))

def turn_on(instrument):
    instrument.write('OUTPut1 ON')
    return

def turn_off(instrument):
    instrument.write('OUTPut1 OFF')
    return

def isConnected(name):
    res = subprocess.check_output(['netsh', 'wlan', 'show', 'interfaces'])
    if name in str(res):
        return True
    return False

def create_output_filename():
    file_path = RECORD_DIR_PATH
    curr_time = datetime.now().strftime("%Y-%m-%d_%H_%M_%S")
    if INVOLVE_ATTACK == True:
        capture_file_name = file_path + "mal_" + curr_time + ".pcap"
    else:
        capture_file_name = file_path + "beg_" + curr_time + ".pcap"

    return capture_file_name

def record():
    interface_name = "Wi-Fi"
    capture_file_name = create_output_filename()
    print("Recording to file: " + capture_file_name)
    f = open(capture_file_name, "w")
    p = subprocess.Popen([TSHARK_PATH, "-i", interface_name, "-w", capture_file_name], stdout=subprocess.PIPE)
    return f, p

def send_one_DNS():
    try:
        _ = resolver.query('https://' + randomEightHexDigits() + FAKE_DOMAIN_SUFFIX, 'NS')
    except resolver.NoAnswer:
        return 1
    except resolver.NXDOMAIN:
        return 2
    except resolver.Timeout:
        print("timeout exception")
        return 3
    return 0

def send_DNS():
    while(True):
        sleep(1/30)
        send_one_DNS()

def randomEightHexDigits():
    return str(binascii.b2a_hex(os.urandom(8)))[2:-1]

# CONSTS
WAVEFORM_DEVICE_NAME = "33622A"
WIFI_NAME = "Wednesday Guest"
TSHARK_PATH = 'C:/Program Files/Wireshark/tshark.exe'
RECORD_DIR_PATH = 'C:/Users/enbaiot/Desktop/recordings/'
FAKE_DOMAIN_SUFFIX = '.rom.orenlab.local'
CONFIGURE_WAVEFORM = False       # if you wish to configure the waveform generator, put True
INVOLVE_ATTACK = False           # if you wish to disrupt the DNS packets (attack), put True

# Make sure the router and waveform generator are connected
rm = visa.ResourceManager()
my_instrument = rm.open_resource('waveform_generator')
device_iden_str = my_instrument.query('*IDN?')
if WAVEFORM_DEVICE_NAME not in device_iden_str:
    print("Waveform generator is not connected!")
    exit(1)

if isConnected(WIFI_NAME) == False:
    print("Wi-Fi is not connected!")
    exit(2)

# Optional: configure the waveform generator (optional because it should already be configured)
if CONFIGURE_WAVEFORM == True:
    config_waveform_generator(my_instrument)

# Start tshark session
f, p = record()

# Send DNS requests (rate = 120pps)
dns_thread = Thread(target=send_DNS, daemon=True)
dns_thread.start()
sleep(3)

# Start the Atmel (attack)
if INVOLVE_ATTACK == True:
    turn_on(my_instrument)
    sleep(7)
    turn_off(my_instrument)
else:
    sleep(7)

# Stop tshark session
sleep(3)
f.close()
p.terminate()
print("Stopped recording.")

# Close the device session and resource manager
my_instrument.close()
rm.close()