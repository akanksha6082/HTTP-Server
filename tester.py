#!/usr/bin/python3.6
import os
import random
import mimetypes
import time
import requests
import webbrowser
import json
from threading import Thread
from requests_toolbelt.utils import dump
from requests_toolbelt.multipart.encoder import MultipartEncoder
from requests.auth import HTTPBasicAuth



#setting up the default locations for testing files
current_path = os.getcwd()
test_path = current_path + "/testing/"
post_test_path = current_path + "/testing/POST/"
put_test_path = current_path + "/testing/PUT/"

class Tester(Thread):
	'''
		The Tester class tests the multi threaded server
		All basic request methods GET, PUT, POST, DELETE and HEAD
		are simultaneously invoked.
		GET request - opens the request in the browser.
		PUT request - creates the resource and makes a get request to it via browser.
		HEAD request - logs the response of the server on the console.
		DELETE request - deletes the resource.
		POST request - creates the resource and makes a get request to it via browser.
	'''
	def __init__(self, urls, flag):
		Thread.__init__(self)
		self.urls = urls
		self.flag = flag

	def run(self):
		working_urls = []
		for method, url in self.urls.items():
			if method == "GET":
				get_obj = GET(url, self.flag)
				working_urls.append(get_obj)
				get_obj.start()
				
			elif method == "PUT":
				put_obj = PUT(url,self.flag)
				working_urls.append(put_obj)
				put_obj.start()

			elif method == "POST":
				post_obj = POST(url, self.flag)
				working_urls.append(post_obj)
				post_obj.start()

			elif method == "DELETE":
				delete_obj = DELETE(url, self.flag)
				working_urls.append(delete_obj)
				delete_obj.start()

			elif method == "HEAD":
				head_obj = HEAD(url, self.flag)
				working_urls.append(head_obj)
				head_obj.start()
				
class GET(Thread):
	def __init__(self, url, flag):
		Thread.__init__(self)
		self.url = url
		self.flag = flag

	def run(self):
    	
		if self.flag == 1:
			index = random.randint(0,4)
			print("GET - requested resource opened up in browser. url :" + self.url[index])
			webbrowser.open_new_tab(self.url[index])
		
		elif self.flag == 2:
			
			index = random.randint(0, len(self.url['url']) - 1)
			res = requests.head(self.url["url"][index], headers={'Connection' : 'close'})
			last_modified_time  = res.headers['Last-Modified']
	
			res = requests.get(self.url["url"][index], headers={'Connection': 'close', 'If-Modified-Since' : urls["GET"]['if-modified-since'] })
			print("If-Modified-Since: " + self.url['if-modified-since'] + "\nLast-Modified:" + last_modified_time)
			print("Last-Modified:" + last_modified_time)
			print("GET: " + str(res.status_code) + " " + res.reason + "\n")

			#directory_listing get
			index = random.randint(0, len(self.url['directory_listing']) - 1)
			print("GET: directory listing - request made via browser. url :" + self.url['directory_listing'][index] + "\n")
			webbrowser.open_new_tab(self.url['directory_listing'][index])
		
		elif self.flag == 3:
			url = self.url["url"]
			print("GET- request opened via browser. url :" + url)
			webbrowser.open_new_tab(url)


class PUT(Thread):
	def __init__(self, url, flag):
		Thread.__init__(self)
		self.url = url
		self.flag = flag
		
	def run(self):
		if self.flag == 1:
			index = random.randint(0, len(self.url) -1 )
			file_name = self.url[index].split('http://localhost:1200/')[1]
			file_name = put_test_path + file_name 
			guess = mimetypes.MimeTypes().guess_type(file_name)[0]
			file_data = open(file_name, "rb").read()

			#make a put request using reuquest
			res = requests.put(self.url[index], data = file_data, headers={"Connection": "close", "Content-Type": guess })
			print("PUT-" + self.url[index] + " : " + str(res.status_code) + " " + res.reason + "\n" )

			#opens the uploaded resource into browser
			webbrowser.open_new_tab(self.url[index])
	
		

class DELETE(Thread):
	def __init__(self, url, flag):
		Thread.__init__(self)
		self.url = url
		self.flag = flag

	def run(self):
		if self.flag == 1:
			#make a delete request with no athorisation
			index = random.randint(0, len(self.url) -1 )
			res = requests.delete(self.url[index], headers={"Connection": "close"})
			print("DELETE url :" + self.url[index] + " " +  str(res.status_code) + " " + res.reason + "\n")

		elif self.flag == 2:
			
			time.sleep(1)
			#making non-admin authorised request to index.html
			username = self.url["auth1"]['username']
			password = self.url["auth1"]['password']
			print("DELETE:")
			for index in range(0, len(self.url['auth1']['test_url'])):
				req = requests.delete(self.url['auth1']['test_url'][index], auth = HTTPBasicAuth(username, password), headers={"Connection": "close"} )
				print("Non Admin Authorised request to " + self.url['auth1']['test_url'][index] + " : " + str(req.status_code) + " " + req.reason)

			#making admin authorised request to index.html
			username = self.url["auth0"]['username']
			password = self.url["auth0"]['password']
			req = requests.delete(self.url['auth0']['test_url'], auth = HTTPBasicAuth(username, password), headers={"Connection": "close"} )
			print("Admin Authorised request to " +  self.url['auth0']['test_url'] + " : " + str(req.status_code) + " " + req.reason)

        
class HEAD(Thread):
	def __init__(self, url, flag):
		Thread.__init__(self)
		self.url = url
		self.flag = flag

	def run(self):
		if self.flag == 1:
			#making a head request
			res = requests.head(self.url, headers={"Connection": "close"})
			requests.session().close()
			print("HEAD request to" + self.url + " : " + str(res.status_code) + " " + res.reason + "\nHeaders:")
			for key, value in res.headers.items():
				print(key + ":" + value )
			print("\n")


class POST(Thread):
	def __init__(self, url, flag):
		Thread.__init__(self)
		self.url = url
		self.flag = flag
    
	def run(self):
		
		if self.flag == 1:
			#multipart/form-data
			name = self.url["data"]["uname"]
			email = self.url["data"]["email"]
			psw = self.url["data"]["psw"]

			index = random.randint(0 , len(self.url["files"]) - 1 )
			file = self.url['files'][index]
				
			file_name = file.split("http://localhost:1200/")[1]
			guess = mimetypes.MimeTypes().guess_type(file_name)[0]
			 
			mp_encoder = MultipartEncoder(
			fields= {
					"name" : name,
					"email": email,
					"psw"  : psw,
					'filename' : ( file_name, open(post_test_path + file_name, "rb"), guess)
				}
			)

			res = requests.post(self.url["url"], data=mp_encoder, headers={"Connection" : "close", "Content-Type" : mp_encoder.content_type})
			print("POST(multipart/form-data request)-" + "\nname = {0}\nemail = {1}\npasswowd = {2}\nfile = {3}\nResponse:\n".format(name, email, psw, file) + str(res.status_code) + " " + res.reason + "\n")
			webbrowser.open_new_tab(file)

		elif self.flag == 2:
    		#url-encoded form data
			fname = self.url['data']['firstname']
			lname = self.url['data']['lastname']
			data = { "firstname" : fname, "lastname" : lname }
			
			req = requests.post(self.url["url"], data = data, headers = {'Connection' : 'close'})
			print("POST(url-encoded form request): " + "\nfirstname = {0}\nlastname = {1}\nResponse:\n".format(fname, lname) + str(req.status_code) + " " +  req.reason + "\n")





if __name__ == "__main__":

	print(Tester.__doc__)

	#testing the basic requests methods
	print("=" * 50  + "\n")
	print("Testing the basic request methods")
	print("=" * 50  + "\n")

	with open(test_path + "testcase1.json", 'r') as f_in:
		urls = json.load(f_in)
	test1 = Tester(urls, 1) 
	test1.start()
	test1.join()
	
	time.sleep(1)

	#testing header specific requests
	print("=" * 50  + "\n")
	print("Testing the header specific requests")
	print("=" * 50  + "\n")

	with open(test_path + "testcase2.json") as f_in:
		urls = json.load(f_in)
	test2 = Tester(urls, 2)
	test2.start()
	test2.join()

	time.sleep(2)

	#testing multiple clients with the same access url
	print("=" * 50  + "\n")
	print("Testing multiple clients with the same access GET url")
	print("=" * 50  + "\n")

	working_clients = []
	with open(test_path + "testcase3.json", 'r') as f_in:
		urls = json.load(f_in)

	for _ in range(urls['GET']["max_client"]):
		obj = Tester(urls, 3)
		working_clients.append(obj)
		obj.start()
	for client in working_clients:
    		client.join()

	















