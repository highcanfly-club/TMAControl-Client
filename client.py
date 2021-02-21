#!/usr/bin/python3
import urllib.request
import ssl
import socket
import json
import binascii

from OpenSSL import crypto
from time import sleep
import pygame

#get the certificate
def getCertificate(host, port=443, timeout=10):
    context = ssl.create_default_context()
    conn = socket.create_connection((host, port))
    sock = context.wrap_socket(conn, server_hostname=host)
    sock.settimeout(timeout)
    try:
        der_cert = sock.getpeercert(True)
    finally:
        sock.close()
    return ssl.DER_cert_to_PEM_cert(der_cert)

def verifySignature(certificate, data, signature):
    server_cert = crypto.load_certificate(crypto.FILETYPE_PEM, certificate)
    pubkey = server_cert.get_pubkey()
    crypto.verify(server_cert, signature, data, 'sha256')

def playsoundWithUUIDMessage(uuid):
    if uuid == 'a4d651bb-bc98-4e57-ae95-dfa94a415b19':  #TMA Active
        return 'TMAActive.mp3'
    elif uuid == '42917626-92c7-4f16-a5e0-6fab087f42b5': #TMA inactive
        return 'TMAInactive.mp3'
    elif uuid == '1bebbccc-e29e-4a8c-8834-3cfeae21432d': #Système en maintenance
        return 'TMAServiceEnMaintenance.mp3'
    else:   #Erreur
        return 'SystemeErreur.mp3'


#retrieve the certificate
cert = getCertificate('tmalille31.highcanfly.club') 

#retrieve the message
url = "https://tmalille31.highcanfly.club/tmastatesecuredmessage"
response = urllib.request.urlopen(url)

#parse the response
json_tma = json.loads(response.read())
json_message = json.loads(json_tma['message'])
uuid = json_message['uuid']
timestamp = json_message['timestamp']
raw_message = json_tma['message']
signature = bytes.fromhex(json_tma['signature'])

#all the need is here !
print('raw message received: %s' % raw_message)
#print('signature: %s' % binascii.hexlify(bytearray(signature)))

#check signature
try:
    verifySignature(cert, bytes(raw_message,'utf-8'), signature)
    print("Signature is valid\nmessage broadcasting is allowed\n")
except:
    print ("Signature verification failed")
else:
    print('uuid: %s' % uuid)
    print('timestamp: %s' % timestamp)
    try:
        from gpiozero import LED    
        LED(18).on()    #push PTT
    except:
        print('GPIO function was not executed') # probably not on rpi
    finally:
        sleep(0.5)
        pygame.mixer.init()
        pygame.mixer.music.load("sound/" + playsoundWithUUIDMessage(uuid))
        pygame.mixer.music.play()
        while pygame.mixer.music.get_busy() == True:
              continue
    try:    
        LED(18).off() #release PTT
    except:
        print('GPIO function was not executed')  # probably not on rpi
    finally:
        print("sleeping…")
