#Server config file
import os
#Server configuration
ServerConfig = {
	"ServerName" : "Akanksha2.4.9 (ubuntu)",
	"ServerIP" : "127.0.0.1",
	"Connection" : "close",
	"MaxListenConnection" : 10,
	"CookieName" : "SessionCookie",
	"Methods" : [ "GET",  "POST",  "PUT" ,  "DELETE",  "HEAD" ],
	"max_bytes" : 1048576,
	"MaxConnections" : 100
	
}

#Log Format
LogFormat = {
	"AcessLog" : "%h, %l, %u, %t, \"%r\", %>s, %b" 
}

#Extensions
#Add Extension to handle different MIME types
Extension_Type = {

	"text/plain" : ".txt",
	"application/pdf": ".pdf",
	"image/png": ".png",
	"image/jpeg": ".jpeg",
	"image/jpg": ".jpg",
	"image/gif": ".gif",
	"video/mp4": ".mp4",
	"audio/mpeg": ".mp3",
	"application/x-sh": ".sh",
	"text/x-python": ".py",
	"text/x-sh": ".sh",
	"text/html": ".html",
	"video/webm": ".webm",
	"application/msword" : ".doc",
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document" : ".docx",
	"application/gzip":".gzip",
	"text/csv": ".csv",
	"application/vnd.oasis.opendocument.text": ".odt",
	"video/ogg" : "ogv",
	"audio/ogg" : "oga"


}

#locations to the server asssets
DefaultLoc ={

	"ServerResources" : os.getcwd() + "/ServerFolder/Resources",
	"ServerRoot" : os.getcwd(),
	"ServerLogs" : os.getcwd() + "/ServerFolder/logs",
	"ServerError" :  os.getcwd() + "/ServerFolder/Error"
}


#Authorization

ServerAuth = {
	"type"	   : "Basic",	
	"username" : "Akanksha",
	"password" : "Timesquare"
}

#DEAFAULT ERROR FORMAT
DEFAULT_ERROR_MESSAGE ="""<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html>
	<head><meta http-equiv="Content-Type" content="text/html;charset=utf-8">
		<title>Error response</title>
	</head>
	<body>
		<h1>%(code)d - %(message)s.</h1>
		<p>%(explain)s</p>
		<hr>
		<address>Akanksha/2.4.9 (Ubuntu) Server at 127.0.0.1</address>
	</body>
</html>"""













