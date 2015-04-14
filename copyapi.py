#!/usr/bin/env python

from fuse import FUSE, FuseOSError, Operations, LoggingMixIn, fuse_get_context
from errno import EACCES, ENOENT, EIO, EPERM
from threading import Lock,Thread
import Queue
import logging
import os
import tempfile
import time
import json
import hashlib
import urllib3


class CopyAPI:
    headers = {'X-Client-Type': 'api', 'X-Api-Version': '1', "Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"}

    def __init__(self, username, password):
        logging.basicConfig(filename='/var/lib/plexmediaserver/Library/api.log', filemode='w', level=logging.DEBUG)
        #logging.basicConfig(filename='/var/lib/plexmediaserver/Library/cfuse.log', filemode='w')
        logging.debug("starting Program")
        self.httpconn = urllib3.connection_from_url("https://api.copy.com", block=True, maxsize=1)
        self.login(username, password)

    def login(self, username, password):
        self.auth_token = ''
        data = {'username': username, 'password' : password}
        response = self.httpconn.request_encode_body("POST", '/auth_user', {'data': json.dumps(data)}, self.getHeaders('auth_user'), False)
        if 'auth_token' not in response.data:
            raise FuseOSError(EPERM)
        else:
            result = json.loads(response.data, 'latin-1')
            self.auth_token = result['auth_token'].encode('ascii','ignore')

    def listPath(self,path, additionalOptions = None):
        list_watermark = 0
        ret = {}
        while True:
            request = {'path': path, 'max_items': 100, 'list_watermark': list_watermark }
            if(additionalOptions):
                request.update(additionalOptions)
	        result = self.post('list_objects', self.encodeRequest('list_objects', request), True)
            print result
            if 'children' in result['result'] and len(result['result']['children']) != 0:
                logging.debug("Returning Children, No. of Children is  " + str(len(result['result']['children'])))
                ret.update(result['result']['children'])
                list_watermark = result['result']['list_watermark']
            else:
                logging.debug("returning object")
                ret.update(result['result']['object'])

            if not ('more_items' in result['result'] and result['result']['more_items'] == 1):
                break

        return ret
    
    def getMeta(self, path, root = 'copy'):
        result = self.get('meta/' + root + path)
        

        if 'error' in result:
            if result['error'] == 1301:
                return {}
            logging.debug("ERROR, Error listing path " + path + ": (" + str(result['error']) + ") " + result['message'] + ")")

        return result

    def getPart(self, fingerprint, size, shareId = 0): 
	    request = {'parts': [{'share_id': shareId, 'fingerprint': fingerprint, 'size': size}]}

	    result = self.post('get_object_parts_v2', self.encodeRequest('get_object_parts_v2', request))
	
	    null_offset = result.find(chr(0)) 
	    binary = result[null_offset+1:]

	    res = ""
	    if len(binary) > 0:
	        res = result[:null_offset]
	    else:
	        res = result

	    if len(res) <= 0:
	        logging.debug("Error getting part data")
	        raise FuseOSError(EIO)
	
	    result = json.loads(res)
	
	    if 'error' in result:
	        logging.debug('Error Getting Part')
	        raise FuseOSError(EIO)
	
	    if 'message' in result['result']['parts'][0]:
	        logging.debug('Error Getting Part. Error message = ' + result['result']['parts'][0]['message'])
	        raise FuseOSError(EIO)
	
	    if len(binary) != int(size):
	        logging.debug('Error getting part data. Expected size = ' + str(len(size)) + ' and size of data received = ' + str(len(binary)))
	        raise FuseOSError(EIO)

	    return binary

    def fingerprint(self, data):
	    return hashlib.md5(data).hexdigest() + hashlib.sha1(data).hexdigest()

    def sendData(self, data, shareId = 0):
	    fingerprint = self.fingerprint(data)
	    part_size = len(data)
	    if not self.hasPart(fingerprint, part_size, shareId):
	        self.sendPart(fingerprint, part_size, data, shareId)

	    return {'fingerprint': fingerprint, 'size': part_size}

    def post(self, method, data, decodeResponse = False):
        headers = self.getHeaders(method)

        result = self.httpconn.urlopen("POST", self.getEndPoint(method), data, headers)
        logging.debug("Post method = " + method + "Post result " + result.data)
        if decodeResponse:
            return json.loads(result.data, 'latin-1')
        else:
            return result.data

    def get(self, method):
        headers = self.getHeaders(method)

        result = self.httpconn.urlopen("GET", self.getEndPoint(method), {}, headers)

        return json.loads(result.data, 'latin-1')

    def getHeaders(self, method):
        headers = {'X-Client-Type': 'api', 'X-Api-Version': '1'}
        
        if self.auth_token != '':
            headers['X-Authorization'] = self.auth_token
        
        if (method == 'get_object_parts_v2') or (method == 'has_object_parts_v2') or (method == 'send_object_pa    rts_v2'):
            headers['Content-type'] = 'application/octet-stream'
        else:
            headers['Content-type'] = 'application/x-www-form-urlencoded'
            headers['Accept'] = 'text/plain'

        return headers

    def getEndPoint(self, method):
        if (method == 'get_object_parts_v2') or (method == 'has_object_parts_v2') or (method == 'send_object_parts_v2'):
            return '/jsonrpc_binary'
        elif (method == 'update_objects') or (method == 'list_objects'):
            return '/jsonrpc'
        elif method == 'auth_user':
            return '/auth_user'
        else:
            return '/rest/' + method

    def sendPart(self, fingerprint, size, data, shareId = 0):
        if hashlib.md5(data).hexdigest() + hashlib.sha1(data).hexdigest() != fingerprint:
            logging.debug("ERROR, Failed to validate part hash")
            raise FuseOSError(EIO)
	
        request = {'parts': [{'share_id': shareId, 'fingerprint': fingerprint, 'size': size, 'data': 'BinaryData-0-' +str(size)}]}
        result = self.post('send_object_parts_v2', self.encodeRequest('send_object_parts_v2', request)+chr(0)+data, True)

        if 'has_failed_parts' in result['result']:
            logging.debug("ERROR, Error sending part: " + result['result']['failed_parts'][0]['message'])
            raise FuseOSError(EIO)
    
    def encodeRequest(self, method, param):
	    request = {'jsonrpc': 2.0, 'id': 0, 'method': method, 'params': param}
	    return json.dumps(request)

    def createFile(self, path, parts):
        if len(parts) <= 0:
            logging.debug("ERROR, no parts in file")
            raise FuseOSError(EIO)
        else:
            request = {'object_type': 'file'}
            p = []
            size = 0
            for part in parts:
                p.append({'fingerprint': part.fingerprint, 'offset': part.offset, 'size': part.size})
                size += part.size

            request['size'] = size
            request['parts'] = p
            
            return self.updateObject('create', path, request)

    def updateObject(self, action, path, meta):
        meta['action'] = action
        meta['path'] = path

        result = self.post('update_objects', self.encodeRequest('update_objects', {"meta" : [meta]}), True);

    def hasPart(self, fingerprint, size, shareId = 0):
        request = {'parts': [{'share_id': shareId, 'fingerprint': fingerprint, 'size': size}]}
        result = self.post('has_object_parts_v2', self.encodeRequest('has_object_parts_v2', request), True)
        
        
        if len(result['result']['needed_parts']) <= 0 :	#Check that needed parts is empty
            return True
        else:
            part = result['result']['needed_parts'][0]
            if ('message' in part and len(part['message']) > 0):
                logging.debug("ERROR: Has Part, Error Message = " + part['message'])
                raise FuseOSError(EIO)
            else:
                return False
