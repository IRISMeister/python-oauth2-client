from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.request import urlopen, HTTPError
import urllib.request
from webbrowser import open_new
import json
import random, string
import os
import ssl
import base64

def get_access_token_from_url(url,code,client_id,client_secret,code_verifier):
    #
    # 受け取った認可コードを使用して、token_uriにアクセスする
    # client type = confidential. (client_secretが必要)
    #
    values = {
        'grant_type':'authorization_code',
        'redirect_uri': 'http://localhost:8080/',
        'code_verifier': code_verifier,
        'code':code
    }
    # Using client_secret_basic.
    encodedData = base64.b64encode(bytes(f"{client_id}:{client_secret}", "ISO-8859-1")).decode("ascii")
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
        'Authorization': 'Basic '+encodedData
    }

    body = urllib.parse.urlencode(values).encode('ascii')

    req = urllib.request.Request(url, body, headers)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(os.environ['REQUESTS_CA_BUNDLE'])

    with urllib.request.urlopen(req,context=context) as res:
      #受信内容をバイナリで返却。パースはoauthlib.oauth2に任せる。
      return res.read()


class HTTPServerHandler(BaseHTTPRequestHandler):

  """
  HTTP Server callbacks to handle OAuth2 redirects
  """
  def __init__(self, request, address, server, client_id, client_secret,token_uri,code_verifier):
    self._client_id = client_id
    self._client_secret = client_secret
    self._token_uri = token_uri
    self._code_verifier = code_verifier
    super().__init__(request, address, server)

  def do_GET(self):
    self.send_response(200)
    self.send_header('Content-type', 'text/html')
    self.end_headers()

    # リダイレクトURLから認可コードを取得できたらアクセストークンを取得するために
    # get_access_token_from_url()を呼び出す
    if 'code' in self.path:
      params = self.path.split('&')
      self.auth_code = params[0].replace('/?code=', '')
      state = params[1].replace('state=', '')
      self.wfile.write(bytes('<html><h1>Please close the window.</h1></html>', 'utf-8'))
      self.server.res_in_bytes = get_access_token_from_url(
                    self._token_uri,self.auth_code,self._client_id,self._client_secret,self._code_verifier)

class AccessTokenHandler:
  def __init__(self, auth_url, token_uri,client_id, client_secret,code_verifier):
    self._auth_url = auth_url
    self._token_uri = token_uri
    self._client_id = client_id
    self._client_secret = client_secret
    self._code_verifier= code_verifier

  def get_access_token(self):
    state = self._randomname(40)
    auth_url = self._auth_url
    open_new(auth_url)
    httpServer = HTTPServer(
      ('localhost', 8080),
      lambda request, address, server: HTTPServerHandler(
        request, address, server, self._client_id, self._client_secret,self._token_uri,self._code_verifier))
    httpServer.handle_request()
    return state,httpServer.res_in_bytes

  def _randomname(self, n):
    randlst = [random.choice(string.ascii_letters + string.digits) for i in range(n)]
    return ''.join(randlst)