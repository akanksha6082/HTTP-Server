#!/usr/bin/python3.6

import sys, os, time, posix, urllib 
import secrets
from socket import *
import posixpath
import mimetypes
from time import gmtime
from threading import Thread



class client_thread(Thread):
	'''
						** HTTP request handler **
		** Request format :-
			The headers and data are separated by a blank line.
			The first line of the request has the form
				<method> <path> <version>

			where <method> is a (case-sensitive) keyword such as GET or POST,
			<path> is a string containing path information for the request,
			and <version> should be the string "HTTP/1.1".

			The specification specifies that lines are separated by CRLF.
			Similarly, whitespace in the request line
			is treated sensibly.

	   	** Response format :-
		    The reply form of the HTTP 1.1 protocol again has three parts:
			    ** One line giving the response code
			    ** An optional set of RFC specified headers
			    ** The data

		    Again, the headers and data are separated by a blank line.

		    The response code line has the form
		    	<version> <responsecode> <responsestring>

		    where <version> is the protocol version "HTTP/1.1",
		    <responsecode> is a 3-digit response code indicating success or
		    failure of the request, and <responsestring> is an optional
		    human-readable string explaining what the response code means.
		    This server parses the request and the headers, and then calls a
		    function specific to the request type 
	'''

	def __init__(self, client_socket, client_address ,server_obj):
		Thread.__init__(self)
	
		self.client_socket = client_socket
		self.client_ip, self.client_port = client_address

		#request headers
		self.headers = {}
		
		#default Error format
		self.error_msg = server_obj.default_error_msg 
		
		#logging data
		self.log_header = {}
		
		#basic server details - Port, IP, max_connections, max recv bytes for socket, etc 
		self.server_config = server_obj.server_config

		#supported response status_codes
		self.error_des = server_obj.error_des

		#default location - Logs, Resources, Root 
		self.default_loc = server_obj.default_loc

		#supported extensions and MIME types
		self.extension_type = server_obj.mime_extension
		
		#server suthentication details
		self.server_auth = server_obj.server_auth	

		#binary data flag - to check for the binary data
		self.bin_data_flag = 0

		
	
	#function to recv the entire message body  
	def recvall(self):
		string = ''
		total_length = -1
		chunk = self.client_socket.recv(self.server_config['max_bytes']).decode('iso-8859-15')
		if chunk:
			string += chunk
			header, data  = chunk.split('\r\n\r\n', 1)
			for head in header.split('\n'):
				if "Content-Length" in head:
					total_length = int(head.split(":")[1].strip())

			#if it is either put or post request
			if total_length != -1:
				remaining_data = total_length - int(len(data))
				while(remaining_data > 0):
					chunk = self.client_socket.recv(self.server_config['max_bytes']).decode('iso-8859-15')
					remaining_data -= len(chunk)
					string += chunk
		return string.encode('iso-8859-15')
    				
	def run(self):
    			
		os.chdir(self.default_loc["ServerResources"])
		self.bin_data_flag = 0

				
		request = self.recvall()
		self.log_header["request_time"] = self.current_time()
	
		if request:
			try:
				request = request.decode("utf-8")	
						
			except(UnicodeDecodeError):  		
				self.bin_data_flag = 1

			try:
				#response_headers, response entity body and type of response entity body(tpye = error, file or None)
				response_header, message, message_type = self.request_handler(request)
			except():
				response_header, message, message_type = self.send_error(500)
				self.client_socket.sendall(response_header + message)
				self.log_error()
				self.terminate_thread()
			
			if message != None:
				if message_type == None or message_type == "error":
					self.log_header["message_length"] = str(len(message))
					self.client_socket.sendall(response_header + message)
				
				elif message_type == "file":
					self.client_socket.sendall(response_header)
					self.client_socket.sendfile(message)
					message.close()
			else:
				self.client_socket.sendall(response_header)
				self.log_header["message_length"] = "-"

			if message_type == "error":
				self.log_error()
			
		
			self.log_access()
			self.terminate_thread()
		
	#closes the connection socket
	def terminate_thread(self):
		self.client_socket.shutdown(SHUT_RDWR)				
		self.client_socket.close()
				
	
	#extacts headers from the request
	def header_parser(self, request, bin_req=None):
		data = ""
		dflag = 0
		headers = {}
		for header in request[ 1 : ]:
			if header != "" and dflag == 0:	
				try:
					token, value = header.strip().split(':', 1)
					token = token.strip().lower()

					if token == "authorization":
						headers[token] = value.strip()
					else:
						headers[token] = value.strip().lower()

					if token == "content-length":
						data_len = int(value.strip())
					

				except(ValueError):
					return self.send_error(400)		
			else:
				dflag = 1
				data += header + "\n"

		if self.bin_data_flag == 1 and not data:
			data = bin_req[len(bin_req) - data_len : ]

		return (headers, data)
			
	
	#examination of the request line to determine the version, resource requested and request method
	def request_handler(self, request):
		
		temp = ""
		if self.bin_data_flag == 0:
			request = request.strip().split('\r\n')
			
			
		else:
			temp = request
			headers = str(request).lstrip("b'").lstrip('b"').rstrip("'").rstrip('"').split('\\r\\n\\r\\n')[0]		
			request = headers.split("\\r\\n")
		
		
		#extracting the headers and message body from the request
		self.headers, data = self.header_parser(request,temp)	
		
		
		#error checking on request line 
		try:
			method, resource, version = request[0].split()
			self.log_header["request_line"] =  request[0]

		except(ValueError):
			return self.send_error(400)
		

		if method not in self.server_config["Methods"] or resource == "":
			return self.send_error(400)

		elif version == "HTTP/1.1":
			resource_path = self.parse_geturl(resource)
			
			if(method == "GET"):
				return self.do_get(resource_path)

			elif(method == "PUT"):
				
				return self.do_put(resource_path, data)

			elif(method == "DELETE"):
				return self.do_delete(resource_path)

			elif(method == "POST"):
				return self.do_post(resource_path, data)

			elif(method == "HEAD"):
				return self.do_head(resource_path)
					
			else:
				#requested method not supported
				return self.send_error(405)
				
		else:
			#requested HTTP version not supported 
			return self.send_error(505)
	
	
	#uses the servers default error_msg to format to hanlde the errors (response status code - 4xx 3xx 5xx)  
	def send_error(self, error):

		'''	
		 	code: an HTTP error code
            
    		message: a simple optional 1 line reason phrase.
	       
        	explaination: a detailed message defaults to the long entry
                	matching the response code.
		'''

		error_res = self.error_msg % {
			'code': error,
			'message' : self.error_des[error]["message"],
			'explain' : self.error_des[error]["explaination"]
		}
		
		response = self.server_get_header(error, error_res)
		self.log_header['error_time'] = self.current_time()
		return (response.encode(), error_res.encode(), "error")
	
	
	#headers common to all the request methods
	def get_common_header(self, status_code, resource_path):
	
		self.log_header["status_code_served"] = str(status_code)
		string = ""
		string += "HTTP/1.1 " + str(status_code) + " " + self.error_des[status_code]["message"] + "\n"
		string += "Date: " + self.current_time() + "\n"
		string += "Server: " + self.server_config["ServerName"] + "\n"

		if status_code == 200 and os.path.isfile(resource_path):
			string += "Last-Modified: " +  self.last_modified_time(resource_path)

		string += "Connection: close\n"
		string += "Set-Cookie: " + self.server_config["CookieName"] + "=" + self.gen_cookie() + "; Domain=127.0.0.1" + "\n"
		return string
	
	#GET speciifc response headers
	def server_get_header(self, status_code, resource_path=None):
		
		string = self.get_common_header(status_code, resource_path)
		if not os.path.isfile(resource_path):

			string += "Content-Length: "+ str(len(resource_path)) + '\n'
			string += "Content-Type: text/html" + '\n'
		else:
			string += "Content-Length: "+ str(os.stat(resource_path)[6]) + '\n'
			string += "Content-Type: "+ self.guess_mime(resource_path) + '\n'

		string += "Accept-Ranges: bytes\n"
		string += "Accept-Language: en-US\n\n"
		return string
	
	#PUT specific response headers
	def server_put_header( self, status_code, resource_path):
		
		string = self.get_common_header(status_code, resource_path)
		if os.path.isdir(resource_path):
			slash = "/"
		else:
			slash = ""
		string += "Content-Location: " + slash + resource_path.split(self.default_loc["ServerResources"])[1] + "\n\n"
		return string
	
	#DELETE specific response headers
	def server_delete_header(self, status_code, message):
		if status_code == 401:
			string = self.get_common_header(401, message)
			string += 'WWW-Authenticate : Basic, charset = "UTF-8"\n\n'
		else:
			string = self.server_get_header(status_code, message)
		return string

	#GET implementation
	def do_get(self, resource_path):
		
		conditional_flag = 0
		flag = 0

		
		if resource_path == "/":
			if os.path.isfile(self.default_loc["ServerResources"] + "/" + "index.html"):
				resource_path += "index.html"

		if not os.path.isfile(resource_path):
			if not os.path.isdir(resource_path):
				return self.send_error(404)
			else:
				return self.list_dir(resource_path)
		
		#check for file read permissions 
		if self.check_for_permissions(resource_path, "read"):
			pass
		else:
			return self.send_error(403)
		

		#check for the exsistence of the conditional request headers
		try:
			#check for the exsistence of atmost one conditional request header
			if(self.headers['if-modified-since'] and "if-unmodified-since" not in self.headers.keys() ):
				conditional_flag = self.do_conditional_get(resource_path, 0)
				if isinstance(conditional_flag, tuple):
						return conditional_flag 
		except(KeyError):
			pass
		
		try:
			#check for the exsistence of atmost one conditional request header
			if(self.headers['if-unmodified-since'] and "if-modified-since" not in self.headers.keys()):
				flag = 1
				conditional_flag = self.do_conditional_get(resource_path, 1)
				if isinstance(conditional_flag, tuple):
						return conditional_flag 
		except(KeyError):
			pass
			
			
		if conditional_flag == 0:
			response = self.server_get_header(200, resource_path)
			f = open(resource_path, 'rb')
			self.log_header['message_length'] = str(os.stat(resource_path)[6])
			return (response.encode(), f, "file")
		else:
			#conditional get - couldnot satisfy the precondition 
			if flag == 1:
				response = self.get_common_header(412, resource_path)
				self.log_header['error_time'] = self.current_time()
				return (response.encode(), None, "error")
			
			#conditional get - resource unmodified
			#status code 304 - Not Modified			
			else:
				response = self.get_common_header(304, resource_path)
				return (response.encode(), None, None)
						

	#PUT implementation
	def do_put(self, resource_path, data ): 
		
		conditional_put = 0
		
		#basic error checking
		if not data:
			
			return self.send_error(400)
		else:
			if os.path.basename(resource_path) == "index.html":
				return self.send_error(405)
		
		#content-type of the mesasge body
		content_type = self.headers['content-type'].split(';')[0]

		
		#check for the exsistence of the conditional request
		try:
			if self.headers['if-unmodified-since']:
				conditional_put = self.do_conditional_get(resource_path, 1)
				if isinstance(conditional_put, tuple):
					return conditional_put 
		except(KeyError):
			pass
		
		if conditional_put == 0:
			
			#file exsistence
			if os.path.isfile(resource_path):
			
				if(self.guess_mime(resource_path) in content_type):
					response = self.server_put_header(200, resource_path)
				else:
					#error - unsupported Media Types
					return self.send_error(415)
			
			#directory exsistence - generates a unique string as file name and creates the resource in specified directory
			elif os.path.isdir(resource_path):
				
				ext = self.extension_type[content_type]
				file_name = secrets.token_urlsafe(4) + ext
				resource_path += "/" + file_name
				response = self.server_put_header(201, resource_path)
			else:
				
				#content-type check - filename MIME type and message body MIME type should match
				if self.guess_mime(resource_path) in content_type:
					response = self.server_put_header(201, resource_path)
				else:
					return self.send_error(415)
			
			if self.bin_data_flag == 1:
				mode = "wb"
			else:
				mode = "w"
			
			#check for exsistence and write permissions
			if self.check_for_permissions(resource_path, "write"):
				self.write_file(resource_path, data, mode)
				return (response.encode(), None , None)
			else:
				return self.send_error(403)
	
		else:
    			#conditional PUT - conditionnot satisfied
			#status code 412 - precondition failed

			response = self.get_common_header(412, resource_path)
			self.log_header['error_time'] = self.current_time()
			return (response.encode(), None, "error")

    		
	#DELETE -implementation
	def do_delete(self, resource_path):
		
		conditional_delete = 0
		r = []
		r.append('<html>\n<body>')
		r.append('<h1> File deleted </h1>')
		r.append('</body>\n</html>')
		message = ("\n").join(r)

		#check for the basic http authorization - extracts username and password
		#status code 401 - unauthorised
		try:
			if(self.headers['authorization']):
		
				auth_type, credentials  =  self.headers['authorization'].split(" ")
				if auth_type != self.server_auth['type']:
					response = self.server_delete_header(401, "")
					self.log_header['error_time'] = self.current_time()
					return (response.encode(), None, "error")
				else:
					import base64
					username, password = base64.b64decode(credentials.encode('ascii')).decode('ascii').split(":")
		except(KeyError):
			response = self.server_delete_header(401, "")
			self.log_header['error_time'] = self.current_time()
			return (response.encode(), None, "error")			

		if resource_path == "/":
			if os.path.isfile(self.default_loc["ServerResources"]+ "/" + "index.html"):
				resource_path += "index.html"
		
		
		
		if not os.path.exists(resource_path):
			return self.send_error(404)
		else:
			if "index.html" in resource_path:
				if not (username == self.server_auth['username'] and password == self.server_auth['password']):
					return self.send_error(405)
		
		
		#check for the conditional headers
		try:
			if self.headers['if-unmodified-since']:
				conditional_delete =self.do_conditional_get(resource_path, 1)
				if isinstance(conditional_delete, tuple):
    					return conditional_delete 
		except(KeyError):
			pass

		if conditional_delete == 0:
			try:
				#deletes the resource
				os.remove(resource_path)

			except(OSError):
				return self.send_error(404)

			response = self.server_delete_header(200, message)
			return (response.encode(), message.encode(), None)
		else:
			#conditional delete- failed precondition
			response = self.get_common_header(412, resource_path)
			self.log_header['error_time'] = self.current_time()
			return (response.encode(), None, "error")
    		

	#HEAD implemntation - performs GET request
	#sends on the response headers
	def do_head(self, resource_path):
		response, _, _ = self.do_get(resource_path)
		return (response, None, None)

	
	#POST implementation
	def do_post(self, resource_path, data):
		
		#basic data check
		if not data:
			return self.send_error(400)
		
		content_type = self.headers['content-type']
		
		#url-encoded form data
		if content_type == "application/x-www-form-urlencoded":
			decoded_query = urllib.parse.unquote_plus(data).split('\n')[1]
			key_value_pair = decoded_query.split('&')
			string = ""
		
			for pair in key_value_pair:
				key, value = pair.split('=')
				string += key + " : " + value.ljust(25, " ")
			
			#logs the post data
			with open(self.default_loc["ServerLogs"] + '/post_data.txt', 'a') as f_out:
				f_out.write(string + "\n")
		
		#multipart-encoded form-data
		else:
	
			content_type, boundary = content_type.split(';')
			boundary = "--"+boundary.split('=')[1]

			if content_type.strip() == "multipart/form-data":
    				
				if self.bin_data_flag == 1:
    					self.binary_file_handler(data, boundary)
				else:
    					
					string = ""
					data = data.strip(boundary).split(boundary)
					
					#parsing multipart encoded form-data
					for part in data[1: len(data)-1]:
					
						header, data_part = part.lstrip('\n').split('\n\n', 1)
						if "Content-Type" not in  header and data_part:
							key = header.strip('\n').split(';')[1].split('=')[1].strip('"')
							string += key + " : " + data_part.strip("\n").ljust(30, " ")

						else:
							
							header = header.strip().split('\n')
							sub_header = header[0].split(';')
							upload_key = sub_header[2]
							string += upload_key.ljust(30, " ") + "content-length: " + str(len(data_part)).ljust(30, " ")
							file_name = upload_key.split("=")[1].strip('"').strip("'")
							
							resource = self.default_loc['ServerResources'] + "/" + file_name

							#check for file write permissions
							if self.check_for_permissions(resource, "write"):
								with open(resource, 'w') as f_in:
									f_in.write(data_part)
							else:
								#status code 403 - Access to the resource forbidden
								return self.send_error(403)

					if string:
						with open( self.default_loc["ServerLogs"] + '/post_data.txt', 'a') as f_out:
							f_out.write(string + "\n")

			else:
				return self.send_error(400)
		
		#response message body for successful implementation of POST
		r = []
		r.append('<html>\n<body>')
		r.append('<h1> Form Submitted Successfully </h1>')
		r.append('</body>\n</html>')					
		message = ("\n").join(r)

		response = self.server_get_header(200, message)
		return (response.encode(), message.encode(), None)

	
	#utility function to POST handler- handles the multipart binary data 
	def binary_file_handler(self, data, boundary):
		data = data.decode('iso-8859-15').strip(boundary).split(boundary)
		string = ""
		for part in data[0: len(data) - 1]:
			sub_header, data_part  = part.split('\r\n\r\n')
			data_part = data_part.strip('\r\n').encode('iso-8859-15')
			if "Content-Type" in sub_header:
				key = sub_header.strip().split('\r\n')[0].split(';')[2]
				file_name = key.split('\r\n')[0].split("=")[1].strip('"')
				string += key.split('\r\n')[0].ljust(30, " ") + "content-length=" + str(len(data_part)).ljust(30, " ")
				
				resource = self.default_loc["ServerResources"] + "/" + file_name

				#check file permissions
				if self.check_for_permissions(resource, "write"):
					with open(resource, 'wb') as f_in:
						f_in.write(data_part)
				else:
					return self.send_error(403)
			else:
				key = sub_header.strip('\n').split(';')[1].split('=')[1].strip('"')
				string += key + " : " + data_part.decode('utf-8').strip('\n').ljust(30, " ")

		if string:
			with open( self.default_loc["ServerLogs"] + '/post_data.txt', 'a') as f_out:
				f_out.write(string + "\n")
			
		return
	
	
	#directory listing GET request
	#displays all the files and sub directories in requested directory and provides navigational links to the resources 
	def list_dir(self, resource_path):

		try:
			list_file = os.listdir(resource_path)
		except(OSError):
			return self.send_error(501)
			

		enc = sys.getfilesystemencoding()
		current_dir = (resource_path).split(self.default_loc["ServerResources"])[1]

		title = 'Directory listing %s' % current_dir
		list_file.sort(key=lambda a: a.lower())

		r = []
		r.append('<!DOCTYPE HTML>')
		r.append('<html>\n<head>')
		r.append('<meta http-equiv="Content-Type" ''content="text/html; charset=%s">' % enc)
		r.append('<title>%s</title>\n</head>' % title)
		r.append('<body>\n<h1>%s</h1>' % title)
		r.append('<hr>\n<ul>')
       
		
		base_url = "http://127.0.0.1:%s" % str(self.server_config["ServerPort"])
		base_url += current_dir

		for name in list_file:
			r.append('<li><a href="%s">%s</a></li>' % (base_url + "/" + name, name ))
		
		
		r.append('</ul>\n<hr>\n</body>\n</html>\n')
		r.append('<address>Akanksha/2.4.9 (Ubuntu) Server at 127.0.0.1</address>')
		encoded = "\n".join(r)
		
		
		response = self.server_get_header(200, encoded)
		return (response.encode(), encoded.encode(), None)	
	
	#utility function tocheck the MIME tyoe of the requested resource
	def guess_mime(self, resource_path):
		guess = mimetypes.MimeTypes().guess_type(resource_path)[0]
		if guess:
			return guess
		return 'application/octect-stream'
	
	#function to generate and serve a unique 16 bit string value as cookie value  
	def gen_cookie(self):
		cookie_value = secrets.token_urlsafe(16)
		self.log_header["CookieName"] = cookie_value
		return cookie_value 
		 
	
	#url parser to extract the path of the reqested resource
	def parse_geturl(self, resource_path):
		
		resource_path = resource_path.split('?',1)[0]
		resource_path = resource_path.split('#',1)[0]
		resource_path = posixpath.normpath(urllib.parse.unquote(resource_path))

		words = resource_path.split('/')
		words = filter(None, words)
		path = os.getcwd()
		for word in words:
		    _ , word = os.path.splitdrive(word)   
		    _ , word = os.path.split(word)
		    if word in (os.curdir, os.pardir): continue
		    path = os.path.join(path, word)
		return path

	
	#utility function to find the last modified time of resource in GMT format(HTTP date format)
	def last_modified_time(self, resourceURI):
		if os.path.exists(resourceURI):
			string = time.ctime(os.path.getmtime(resourceURI)).strip()
			token = string.split()
			sp = " "
			return token[0] + ', ' + token[2] + sp + token[1] + sp + token[4] + sp + token[3] + sp + "GMT\n"
		else:
			return None
	
	#determines the current time in GMT format(HTTP date format)
	def current_time(self):
		return time.strftime("%a, %d %b %Y %I:%M:%S", time.gmtime()) + " GMT"
		    

	def write_file(self, resourceURI, data, mode="w"):
		with open(resourceURI, mode) as myfile:
			myfile.write(data)
			
    		
	#aceess logs
	def log_access(self):
    		
		self.log_header['client_ip'] = self.client_ip
		request_time = self.log_header['request_time']
		request_line = self.log_header['request_line']
		status_code_served = self.log_header["status_code_served"]
		message_length = self.log_header["message_length"]
		cookie_name = self.log_header["CookieName"]

		string = ""
		string += self.log_wrapper(self.client_ip, 1).ljust(35, " ") + self.log_wrapper(request_time).ljust(40, " ") + self.log_wrapper(request_line).ljust(45, " ")
		string += status_code_served.ljust(15, " ") + message_length.ljust(15, " ")  + self.log_wrapper(cookie_name).ljust(20, " ") + "\n"

		with open(self.default_loc["ServerLogs"] + "/Access_logs.txt", "a+") as file:
			file.write(string)
	
	#logs error
	def log_error(self):
    		
		self.log_header['client_ip'] = self.client_ip
		status_code = self.log_header['status_code_served']
		message = self.error_des[int(status_code)]['message']
		request_line = self.log_header['request_line']
		time = self.log_header['error_time']
		string = ""
		string += self.log_wrapper(self.client_ip, 1).ljust(35, " ") + self.log_wrapper(time).ljust(40, " ") + "[ error ]".ljust(15, " ") + self.log_wrapper(request_line).ljust(45, " ")  + status_code.ljust(10, " ") + message + "\n" 
		
		with open(self.default_loc["ServerLogs"] + "/Error_logs.txt", "a+") as file:
			file.write(string)
	
	#utility log function -formats the log data
	def log_wrapper(self, string, flag=0):
    		if flag == 1:
    			string = "client " + string + ":" + str(self.client_port)	
    		return "[ " + string +  " ]"
	
	#checks for the file permissions	
	def check_for_permissions(self, resource_path, permission="read"):
	
		if os.access(resource_path, os.F_OK):
			if(permission == "read-write"):
				return os.access(resource_path, os.R_OK) and os.access(resource_path, os.W_OK)
			if(permission == "read"):
				return 	os.access(resource_path, os.R_OK)
			if(permission == "write"):
				return os.access(resource_path, os.W_OK)
			if(permission == "excecute"):
				return os.access(resource_path, os.X_OK)

		if(permission == "write"):
			return True

		return False	
	
	#conditional request implementation
	def do_conditional_get(self, resource_path, flag=0):
		
		if(flag == 0):	
			given_date = self.headers['if-modified-since']
		else:
			given_date = self.headers['if-unmodified-since']
		
		try:
			last_date = self.last_modified_time(resource_path).lower().rstrip('\n')
		except(AttributeError):
			return 0

		try:
			from datetime import datetime
			format =  '%a, %d %b %Y %H:%M:%S gmt'
		except(ImportError):
			return self.send_error(500)
			

		try:
			d1 = datetime.strptime(given_date, format)
			d2 = datetime.strptime(last_date, format)
		except(ValueError):
			return self.send_error(500)


		if flag == 0:
			if(d2 > d1):
				return 0
			return 1
		elif flag == 1 and os.path.exists(resource_path):
			
			if d2 > d1:
				return 1
			return 0
		return 0


		

    		
	
		


		
		
		
		
			
			

		
	


