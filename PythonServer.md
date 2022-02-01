

```py
# From Nathan

import http.server, ssl
server_address = ('0.0.0.0', 443)
httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket(httpd.socket,
                               server_side=True,
                               certfile='server.pem',
                               ssl_version=ssl.PROTOCOL_TLS)
httpd.serve_forever()

```

Update all pip : `pip list --outdated --format=freeze | grep -v '^\-e' | cut -d = -f 1  | xargs -n1 pip install -U`

Is this useful ? : https://gist.github.com/phrawzty/62540f146ee5e74ea1ab
