#!/usr/bin/python3.6
import sys, time,  json
from socket import *
from threading import Thread
from Threading import client_thread
import config as cfg


users = []

class Server():

	
	def __init__(self):
    		
		self.server_config = cfg.ServerConfig
		self.server_config["ServerPort"] = 1200
		self.default_error_msg = cfg.DEFAULT_ERROR_MESSAGE
		self.default_loc = cfg.DefaultLoc 
		self.server_auth = cfg.ServerAuth
		self.error_des = self.config_error()
		self.mime_extension = cfg.Extension_Type 
		self.server_socket = socket(AF_INET, SOCK_STREAM)

	def config_error(self):
		with open( self.default_loc["ServerError"] + "/error.json", 'r') as f_in:
			error_des = json.load(f_in)
			error_des = {int(k) : v for k, v in error_des.items()}
		return error_des
	
	def close_server(self):
		for threads in users:
			threads.join()
    		
	def run_server(self):

		self.server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
		self.server_socket.bind(('', self.server_config["ServerPort"]))
		self.server_socket.listen(self.server_config["MaxListenConnection"])
		print("server started on port {}".format(self.server_config["ServerPort"]))
		
		while True:
			try:
				client_socket, client_address = self.server_socket.accept()
				if(len(users) == self.server_config["MaxConnections"]):
					print("Terminating. Max limit reached for simultaneous connections.")
					client_socket.close()
					break
				print("server connected to {0}".format(client_address))
				new_client_thread=client_thread(client_socket, client_address, self) 
				new_client_thread.start()		
				users.append(new_client_thread)
			except(KeyboardInterrupt):
				break

		self.close_server()
		print('\nBye!')
	
		
			

if __name__ == "__main__":

	server_instance = Server()
	server_instance.run_server()
		
		

	
			
