#!/usr/bin/env python3

'''
Call: curl -s -H "X-Something: yeah" localhost:8000 > /dev/null

Response: 
ERROR:root:User-Agent: curl/7.37.1
Host: localhost:8000
Accept: */*
X-Something: yeah

127.0.0.1 - - [05/Mar/2015 11:28:33] "GET / HTTP/1.1" 200 -

'''

import http.server as SimpleHTTPServer
import socketserver as SocketServer
import logging

PORT = 8000

class GetHandler(
        SimpleHTTPServer.SimpleHTTPRequestHandler
        ):

    def do_GET(self):
        logging.error(self.headers)
        SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)


Handler = GetHandler
httpd = SocketServer.TCPServer(("", PORT), Handler)

httpd.serve_forever()
