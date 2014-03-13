#!/usr/bin/python3
#
#    mitm-protector.py - protect's you from any kind of MITM-attacks.
#
#    Copyright (C) 2014 by Jan Helbling <jan.helbling@gmail.com>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

from os import popen,getuid,path,fork,mkdir,execvp,waitpid,WEXITSTATUS,system

from sys import exit,argv

from time import sleep

import re,socket,struct,configparser,logging,uuid,signal

import daemonic.daemon



ip_regex 	= re.compile("\d+\.\d+\.\d+\.\d+")
mac_regex	= re.compile("[A-Za-z0-9]+:[A-Za-z0-9]+:[A-Za-z0-9]+:[A-Za-z0-9]+:[A-Za-z0-9]+:[A-Za-z0-9]+")

config_filename	= 'mitm-protector.ini'
config_dir	= '/etc/mitm-protector'
config_path	= '%s/%s' % (config_dir,config_filename)

log_dir		= '/var/log'
log_filename	= 'mitm-protector.log'
log_path	= '%s/%s' % (log_dir,log_filename)

class mitm_protect:
	def __init__(self):
		logging.basicConfig(filename=log_path,filemode='a',level=logging.DEBUG,format='%(asctime)s - %(levelname)s - %(message)s',datefmt='%d.%m.%Y - %H:%M:%S')
		logging.info('mitm-protector gestartet!')
		self.devices	=	[]
		self.counter	=	0
		try:
			self.__run()
		except KeyboardInterrupt:
			logging.info('lösche Firewall')
			print('Beende mitm-protector')
			print('Lösche arptables-Firewall')
			self.remove_firewall()
		logging.info('mitm-protector beendet!')
		return
	
	def __get_hw_addr(self):
		return ':'.join(re.findall('..', '%012x' % uuid.getnode()))
	
	def __read_config(self):
		print('Lade Konfigurations-Krimskrams =)')
		config		=	configparser.ConfigParser()
		if not path.exists(config_path):
			logging.info('Erstelle nagelneue Config- Datei + Ordner %s',config_path)
			mkdir(config_dir)
			config['attack'] 			= {}
			config['attack']['exec'] 		= '/usr/bin/notify-send "MITM-Angriff" "von IP: {0}  MAC: {1}" -u critical -t 3000 -c "Security"'
			config['attack']['interfaces'] 		= 'wlp12s0,enp9s0'
			config['attack']['put-interfaces-down']	= '1'
			config['attack']['shutdown-interface-command'] = 'ifconfig {0} down'
			config['arp-scanner'] = {}
			config['arp-scanner']['timeout'] = '5'
			config['arp-scanner']['command'] = 'arp -an'
			with open(config_path,'w') as configfile:
				config.write(configfile)
			configfile.close()
		logging.info('Lese Config-Datei %s',config_path)
		config.read(config_path)
		self.exec_cmd		=	config['attack']['exec']
		self.interfaces		=	config['attack']['interfaces']
		self.putinterfacesdown	=	bool(	config['attack']['put-interfaces-down'])
		self.shutdown_iface_cmd	=		config['attack']['shutdown-interface-command']
		self.scan_timeout	=	float(	config['arp-scanner']['timeout'])
		self.arp_command	=		config['arp-scanner']['command']
	
	def __arptable_firewall(self):
		if not path.exists('/usr/bin/arptables') and not path.exists('/sbin/arptables'):
			print('arptables nicht gefunden!!! Kann keine Firewall erstellen!!!')
			logging.critical('arptables nicht gefunden!!! Kann keine Firewall erstellen!!!')
			return
		logging.info('Erstelle eine Firewall mit arptables und arp!')
		print('Erstelle eine Firewall mit arptables und arp!')
		self.fd			=	popen('arp-scan -I %s %s | grep %s' % (self.interfaces.split(',')[0],self.__getrouterip(),self.__getrouterip()),'r')
		try:
			self.mac		=	mac_regex.findall(self.fd.read())[0]
			print("Mac des Routers:",self.mac)
		except IndexError:
			sleep(1)
			self.fd.close()
			self.fd			=	popen('arp-scan -I %s %s | grep %s' % (self.interfaces.split(',')[0],self.__getrouterip(),self.__getrouterip()),'r')
			self.mac		=	mac_regex.findall(self.fd.read())[0]
			print("Mac des Routers:",self.mac)
		self.fd.close()
		self.fd			=	popen('arptables --zero && arptables -P INPUT DROP && arptables -P OUTPUT DROP && arptables -A INPUT -s %s --source-mac %s -j ACCEPT && arptables -A OUTPUT -d %s --destination-mac %s -j ACCEPT && arp -s %s %s' % (self.__getrouterip(),self.mac,self.__getrouterip(),self.mac,self.__getrouterip(),self.mac), 'r')
		self.fd.read()
		self.fd.close()
		self.fd			=	popen("arptables --list","r")
		self.lst		=	self.fd.read()
		self.fd.close()
		print("arptables --list:\n%s" % self.lst)
	
	def remove_firewall(self):
		popen('arptables --zero').read()
	
	def __run(self):
		self.__read_config()
		self.__arptable_firewall()
		logging.info('Beginne Endlosschleife')
		while True:
			self.counter = self.counter + 1
			self.__arp()
			self.__check()
			if self.attacker != ():
				print('ALARM! arppoisoning erkannt!!!')
				print('Führe festgelegtes kommando aus: \'%s\'!' % self.cmd.format(self.attacker[0],self.attacker[1]))
				logging.warning('ALARM! arppoisoning erkannt!!!')
				if not fork():
					popen(self.exec_cmd.format(self.attacker[0],self.attacker[1]),'r').read()
					if self.putinterfacesdown:
						print('Fahre die Netzwerkinterfaces herrunter: %s',self.interfaces)
						logging.critical('Fahre die Netzwerkinterfaces herrunter: %s',self.interfaces)
						for interface in self.interfaces.split(','):
							popen(self.shutdown_iface_cmd.format(interface),'r').read()
							print('%s: Ausgeschaltet!',interface)
							logging.critical('%s:  Ausgeschaltet!',interface)
					exit(0)
			print('[%d] Schlummere %d Sekunden bis zum nächsten Check.' % (self.counter,self.scan_timeout))
			sleep(self.scan_timeout)
	
	def __arp(self):
		self.fd		=	popen(self.arp_command,"r")
		self.lines	=	(self.fd.read()).split("\n")
		self.fd.close()
		print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>ARP-LIST START<<<<<<<<<<<<<<<<<<<<<<<<<<<<<")
		for line in self.lines:
			if line == '':
				break
			try:
				ip	=	ip_regex.findall(line)[0]
				mac	=	mac_regex.findall(line)[0]
				print(">>> IP:",ip," MAC:",mac)
				self.devices.append((ip,mac))
			except IndexError:
				pass
		print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>ARP-LIST END<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n\n")
	
	def __check(self):
		self.attacker	=	()
		for device in self.devices:
			for _device in self.devices:
				if device[0] != _device[0] and device[0] != self.__getrouterip():
					if device[1] == _device[1]:
						self.attacker	=	device
						logging.critical('MITM ATTACKE GESICHTET!!! IP: %s , MAC: %s',self.attacker[0],self.attacker[1])
						print('MITM ATTACKE GESICHTET!!! IP: %s , MAC: %s' % (self.attacker[0],self.attacker[1]))
						return self.attacker
		self.devices = []
					
	
	def __getrouterip(self):
		with open("/proc/net/route") as fh:
			for line in fh:
				fields = line.strip().split()
				if fields[1] != '00000000' or not int(fields[3], 16) & 2:
					continue
				return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
	
if __name__ == '__main__':
	if getuid() != 0:
		print('Muss als root (uid=0) ausgeführt werden!')
		exit(1)
	
	argc = len(argv)
	
	if '--daemon' not in argv and '-D' not in argv and '--terminate' not in argv and '-T' not in argv and '--foreground' not in argv and '-F' not in argv or '-h' in argv or '--help' in argv or '-?' in argv or argc != 2:
		print('Benutzung: %s <-D --daemon | -T --terminate | -F --foreground>' % argv[0])
		exit(0)
	elif '--terminate' in argv or '-T' in argv:
		try:
			fd		=	open('/var/run/mitm-protector.pid','r')
			daemon_pid	=	fd.read()
			fd.close()
		except FileNotFoundError:
			print('Konnte /var/run/mitm-protector.pid nicht finden... Anscheinend läuft gar kein Daemon.')
			exit(0)
		
		print("==> exec: kill -15 %s" % daemon_pid)
		
		pid		=	fork()
		if not pid:
			execvp("/usr/bin/kill",["/usr/bin/kill","-15",daemon_pid])
		_pid,st = waitpid(pid,0)
		st	= WEXITSTATUS(st)
		if st == 0:
			print("Daemon Terminiert!")
		elif st == 1:
			print("Fehlgeschlagen. Läuft der Daemon überhaupt noch?")
		exit(0)
	elif '--foreground' in argv or '-F' in argv:
		x = mitm_protect()
		exit(0)
	elif '--daemon' in argv or '-D' in argv:
		print("Starte Daemon... Pidfile: /var/run/mitm-protector.pid")
		if popen('type arptables 2>/dev/null').read() != '':
			print('Daemon nicht mit kill beenden, sondern mit %s < --terminate | -T >.' % argv[0])
			print('Damit das Programm noch kurz aufräumen kann (die arptables und arp zurücksetzen)')
		print('Ein log des Daemons gibts unter %s' % log_path)
		d = daemonic.daemon(pidfile='/var/run/mitm-protector.pid')
		def sigterm_handler(sig,frame):
			d.remove_firewall()
			exit(0)
		
		signal.signal(signal.SIGTERM,sigterm_handler)
		
		d.daemonize()
		
		x = mitm_protect()
