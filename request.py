# Thses are for access to an IRIS based resource server
import logging
import json
import urllib
import io
import os
import ssl
import base64
import pprint
import string
import random
import hashlib
from oauthlib.oauth2 import WebApplicationClient
from webbrowser import open_new
from httpserverhandler import AccessTokenHandler

# If modifying these scopes, delete the file token.json.
SCOPES = ['openid','profile','scope1','scope2','patient/*.read']


def print_section(str):
    print('\n'+'***** '+str+' *****')

def decode(token):
    tokenarray =token.split('.')
    for pos in range(2):
        tokenarray[pos] += '=' * (-len(tokenarray[pos]) % 4)
        result = base64.urlsafe_b64decode(tokenarray[pos].encode()).decode()
        pp.pprint(json.loads(result))

def getresponse(method,title,endpoint,headers,data):
    req = urllib.request.Request(endpoint, json.dumps(data).encode("utf-8"), headers=headers,method=method)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(os.environ['REQUESTS_CA_BUNDLE'])
    print_section('response from '+title+' endpoint')
    try:
      with urllib.request.urlopen(req,context=context) as res:
        body = json.load(res)
        pp.pprint(body)
    except urllib.error.HTTPError as err:
        print(err)

def generate_code() -> tuple[str, str]:
    rand = random.SystemRandom()
    code_verifier = ''.join(rand.choices(string.ascii_letters + string.digits, k=128))

    code_sha_256 = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    b64 = base64.urlsafe_b64encode(code_sha_256)
    code_challenge = b64.decode('utf-8').replace('=', '')

    return (code_verifier, code_challenge)

def main():

    os.environ["REQUESTS_CA_BUNDLE"] = "c:\\temp\\all.crt"
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(os.environ['REQUESTS_CA_BUNDLE'])

    creds = None
    with io.open('credentials.json', "r", encoding="utf-8") as json_file:
        creds = json.load(json_file)

    client_id=creds['client_id']
    client_secret=creds['client_secret']
    issuer_uri=creds['issuer_uri']

    redirect_uri='http://localhost:8080/'

    with urllib.request.urlopen(issuer_uri+"/.well-known/openid-configuration",context=context) as response:
        json_data = json.loads(response.read())

    auth_uri=json_data['authorization_endpoint']
    token_uri=json_data['token_endpoint']

    # pkce
    code_verifier, code_challenge = generate_code()

    # 自力でlocalにweb server立てる例 https://qiita.com/kai_kou/items/d03abd6012f32071c1aa
    oauth = WebApplicationClient(client_id)
    auth_url, headers, body = oauth.prepare_authorization_request(auth_uri, redirect_url=redirect_uri, scope=SCOPES,code_challenge= code_challenge, code_challenge_method = "S256")
    print_section('auth_url')
    print(auth_url)
    print_section('headers')
    print(headers)
    print_section('body')
    print(body)

    token_handler = AccessTokenHandler(auth_url,token_uri,client_id, client_secret,code_verifier)
    state,res_in_bytes=token_handler.get_access_token()

    # 認可サーバからの応答をパースする
    oauth.parse_request_body_response(res_in_bytes)
    access_token=oauth.access_token
    id_token=oauth.token['id_token']
    refresh_token=oauth.refresh_token

    print_section('decoded access token')
    decode(access_token)
    print_section('decoded id token')
    decode(id_token)
    print_section('state')
    print(oauth.state)
    print_section('scope')
    print(oauth.token.scope)

    print_section('dumping all token')
    pp.pprint(oauth.token)

    data = {
    }
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer '+access_token
    }

    # userinfoエンドポイント
    getresponse('POST','userinfo','https://webgw.localdomain/irisauth/authserver/oauth2/userinfo',headers,data)

    # Resource server #1にaccess_tokenを添えて、RESTアクセスする。
    getresponse('POST','resource server #1','https://webgw.localdomain/irisrsc/csp/MYAPP/private',headers,data)
    # Resource server #2にaccess_tokenを添えて、RESTアクセスする。
    getresponse('POST','resource server #2','https://webgw.localdomain/irisrsc2/csp/MYAPP/private',headers,data)

    #
    # refresh tokenを使用
    #
    url, headers, body = oauth.prepare_refresh_token_request(token_uri,refresh_token=refresh_token,state=state,response_type='token')

    #client_secret_basic
    encodedData = base64.b64encode(bytes(f"{client_id}:{client_secret}", "ISO-8859-1")).decode("ascii")
    headers['Authorization'] = 'Basic '+encodedData

    req = urllib.request.Request(url, body.encode(), headers=headers)
    with urllib.request.urlopen(req,context=context) as res:
        oauth.parse_request_body_response(res.read())
    #print(oauth.token_type)
    #print(oauth.expires_in)
    print_section('refreshed access token')
    decode(oauth.access_token)

if __name__ == '__main__':
    pp = pprint.PrettyPrinter(indent=4)   
    main()

