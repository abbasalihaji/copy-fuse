#!/usr/bin/env python

from __future__ import with_statement

from errno import EACCES, ENOENT, EIO, EPERM
from threading import Lock
from stat import S_IFDIR, S_IFREG
from sys import argv, exit, stderr

import logging
import os
import argparse
import tempfile
import time
import json
import hashlib
import urllib3

from fuse import FUSE, FuseOSError, Operations, LoggingMixIn, fuse_get_context
from cachemanager import CacheManager, FileCache, Chunk

class CopyAPI:
    headers = {'X-Client-Type': 'api', 'X-Api-Version': '1', "Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"}

    def __init__(self, username, password):
	logging.basicConfig(filename='/var/lib/plexmediaserver/Library/cfuse.log', filemode='w', level=logging.DEBUG)
	logging.debug("starting Program")
	self.auth_token = ''
        self.cacheManager = CacheManager()
	self.tree_children = {}
        self.tree_expire = {}
        self.httpconn = urllib3.connection_from_url("https://api.copy.com", block=True, maxsize=1)
        data = {'username': username, 'password' : password}
        response = self.copyrequest('/auth_user', data)
        if 'auth_token' not in response:
            raise FuseOSError(EPERM)
        else:
            self.auth_token = response['auth_token'].encode('ascii','ignore')

    def copygetrequest(self, uri, data, return_json=True):
        headers = self.headers
        if self.auth_token != '':
            headers['X-Authorization'] = self.auth_token
        response = self.httpconn.request_encode_body("GET", uri, {}, headers, False)
        if return_json == True:
            return json.loads(response.data, 'latin-1')
        else:
            return response.data

    def copyrequest(self, uri, data, return_json=True):
	headers = self.headers
        if self.auth_token != '':
            headers['X-Authorization'] = self.auth_token
        response = self.httpconn.request_encode_body("POST", uri, {'data': json.dumps(data)}, headers, False)
	if return_json == True:
            return json.loads(response.data, 'latin-1')
        else:
            return response.data

    def part_request(self, method, parts, data=None):
        headers = self.headers
        headers['X-Part-Count'] = len(parts)

        payload = ''

        for i in range(0, len(parts)):
            part_num = str(i + 1)
            headers['X-Part-Fingerprint-' + part_num] = parts[i]['fingerprint']
            headers['X-Part-Size-' + part_num] = parts[i]['size']
            headers['X-Part-Share-' + part_num] = 0

            if method == 'send_parts':
                payload = payload + parts[i]['data']

        # authentication http headers
        if self.auth_token != '':
            headers['X-Authorization'] = self.auth_token

        # print headers

        if method == 'has_parts':
            response = self.httpconn.request_encode_body("POST", "/" + method, {'data': json.dumps(data)}, headers, False)
        else:
            response = self.httpconn.urlopen("POST", "/" + method, payload, headers)

        return json.loads(response.data, 'latin-1')

    def list_objects(self, path, ttl=10):
        # check cache
        if path in self.tree_expire:
            if self.tree_expire[path] >= time.time():
                return self.tree_children[path]

        # obtain data from copy
        # print "listing objects from cloud for path: " + path
        data = {'path': path, 'max_items': 1000000}
        response = self.copyrequest('/list_objects', data)
        if 'children' not in response:
            raise FuseOSError(EIO)
	
	print "LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLSSSSSSSSSSSSSSSSS"
	print json.dumps(response)
        print "ENDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
	#print response
	#print "KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKk"
	# build tree
	#print response['revisions'][0]
	#self.getPart(response['parts'][0]['fingeerprint'],response['parts'][0]['size'])
        self.tree_children[path] = {}
        for child in response['children']:
            name = os.path.basename(child['path']).encode('utf8')
            ctime = int(child['created_time'])
            if child['modified_time'] == None:
                mtime = ctime
            else:
                mtime = int(child['modified_time'])
            self.tree_children[path][name] = {'name': name, 'type': child['type'], 'size': child['size'], 'ctime': ctime, 'mtime': mtime}

        # update expiration time
        self.tree_expire[path] = time.time() + ttl

        return self.tree_children[path]

    def listPath(self,path, additionalOptions = None):
	data = {'path': path, 'max_items': 1000000, 'list_watermark': 0 }
	if(additionalOptions):
	   data.update(additionalOptions)
	response = self.copyrequest('/list_objects', data)
	print response
	if 'children' not in response:	
	   raise FuseOSError(EIO)
	
	#if not response['children']:
	#   return response['children']
	#else:
	#   print "OBBBJECTTT"
	return response['object']
    
    def getFile(self, path):
	fileCache = self.cacheManager.findFileByPath(path)
	if fileCache == -1:#not in cacheManager
	    f = tempfile.NamedTemporaryFile(delete=False)
	    additionalOption = {'include_parts': 'true'}
	    files = self.listPath(path, additionalOption)
	    latestRev = files['revisions'][0]
	    fileCache = FileCache(files['path'], f.name, latestRev['size'])
	    for part in latestRev['parts']:
    	        chunk = Chunk(part['fingerprint'], part['size'], part['offset'])
	        fileCache.chunks.append(chunk)
	        #data = self.getPart(part['fingerprint'], part['size'])
	        #f.write(data)
	    self.cacheManager.files.append(fileCache)
	    f.close()
	return 0

    def makeAvailableForRead(self, path, size, offset):
	logging.debug("Entering MakeAvailableForRead")
	#print "MAKE AVAILABLE FOR READ"
	fileCache = self.cacheManager.findFileByPath(path)
	#print "LOCAL PATH + " + fileCache.localPath
	#print "ReadingOffset =" + str(offset)
	#print "ReadingSize = " + str(size)
	f = open(fileCache.localPath, 'a+b')		#Understand pyhton write read params to fix this
	counter = 0
	while counter < len(fileCache.chunks):
	    #print "CHUNK"
	    #print "OFFSET =" + str(chunk.offset)
	    #print "SIZE ="   + str(chunk.size)
	    #print "isAvailable  " + str(chunk.isAvailable)
	    #if (int(chunk.offset) < int(offset+size)):
		#print "WORKING OFFSET"
	    #if (chunk.isAvailable == False):
		#print "working AVAILBALE"
	    chunk = fileCache.chunks[counter]
	    data = ""
	    if (int(chunk.offset) <= int(offset)) and ((int(chunk.offset) + int(chunk.size)) > int(offset)):	#found chunk between which startoffset lies 
		logging.debug("Found Starting Chunk")
		temp = ""
		while int(chunk.offset) < int(offset) + int(size):
		    logging.debug("Current Chunk Offset = " + str(chunk.offset))
		    if chunk.isAvailable:
			logging.debug("Chunk is available, starting offset is " + str(chunk.localoffset))
			f.seek(chunk.localoffset)
			logging.debug("Current file position = " + str(f.tell()))
			temp = f.read(int(chunk.size))
			#temp = self.getPart(chunk.fingerprint, chunk.size)
			logging.debug("Found Chunk. No. of Bytes Read = " +str(len(temp)))
		    else:
			temp = self.getPart(chunk.fingerprint, chunk.size)
			chunk.isAvailable = True
			f.seek(0,2)
			chunk.localoffset = f.tell()
		    	logging.debug("writting to file. Offset equal = " + str(chunk.localoffset))
			f.write(temp)
			f.seek(0,2)
			logging.debug("Finshed Writing End of file offset is " + str(f.tell()))
		    logging.debug("Got chunk data")
		    if int(chunk.offset) >= int(offset) and int(chunk.offset)+int(chunk.size) < int(offset)+int(size):
			logging.debug("Case 1")
			data += temp
		    elif int(chunk.offset) <= int(offset) and int(chunk.offset)+int(chunk.size) > int(offset)+int(size):
			logging.debug("Case 2")
			data += temp[(int(offset)-int(chunk.offset)):(int(offset)-int(chunk.offset)+int(size))]
		    elif int(chunk.offset) <= int(offset) and int(chunk.offset)+int(chunk.size) < int(offset)+int(size):
			logging.debug("Case 3")
			data += temp[int(offset)-int(chunk.offset):]
		    else:
			logging.debug("Case 4")
			data += temp[:int(offset)+int(size)-int(chunk.offset)]
		    if counter+1 < len(fileCache.chunks):
		    	chunk = fileCache.chunks[counter+1]
		    else:
			logging.debug("Last Chunk")
			return data
		    counter += 1
		if len(data) != int(size):
		    logging.debug("ERROR, Did not read correct no. of bytes")
		    logging.debug("Amount to be read = " + str(size))
	            logging.debug("Amount read = " + str(len(data)))
		    return ""
		else:	
		    logging.debug("Correct End MakeAvailableForRead")
		    return data
	    counter += 1
	f.close()
	#print "ENDMAKEAVAILABLEREAD"
	logging.debug("End MakeAvailableForRead")
	return data

    def getPart(self, fingerprint, size, shareId = 0): #Currently only doing sequentital reads
	headers = {'X-Client-Type': 'api', 'X-Api-Version': '1', "Content-type": "application/octet-stream"}
	if self.auth_token != '':
	    headers['X-Authorization'] = self.auth_token
	
	data = {'parts': [{'share_id': shareId, 'fingerprint': fingerprint, 'size': size}]}
	request = {'jsonrpc': 2.0, 'id': 0, 'method': 'get_object_parts_v2', 'params': data}
	#response = self.copyrequest('/get_object_parts_v2', data, False)
	response = self.httpconn.urlopen("POST", '/jsonrpc_binary',  json.dumps(request), headers)
	#logging.debug("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
	null_offset = response.data.find(chr(0)) 
	binary = response.data[null_offset+1:]
	if len(binary) != int(size):
	    #print "LENGTH + " + str(len(binary))
	    #print "SIZE " + str(size)
	    return FuseOSError(EIO)
	#print response.data[:null_offset]
	return response.data[null_offset+1:]

    def fingerprint(self, data):
	return hashlib.md5(data).hexdigest() + hashlib.sha1(data).hexdigest()

    def sendData(self, data, shareId = 0):
	fingerprint = self.fingerprint(data)
	part_size = len(data)
	if not self.hasPart(fingerprint, part_size, shareId):
	    print "JJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJ"
	    self.sendPart(fingerprint, part_size, data, shareId)

	return 0 #need to see what to return here

    def sendPart(self, fingerprint, size, data, shareId = 0):
	if self.fingerprint(data) != fingerprint:
	    #throw new \Exception("Failed to validate part hash");
	    return FuseOSError(EIO)
	
	headers = {'X-Client-Type': 'api', 'X-Api-Version': '1', "Content-type": "application/octet-stream"}
	if self.auth_token != '':
	    headers['X-Authorization'] = self.auth_token	

	payload = [{'parts': [{'share_id': shareId, 'fingerprint': fingerprint, 'size': size, 'data': 'BinaryData-0-' +str(size)}]}]
	request = {'jsonrpc': 2.0, 'id': 0, 'method': 'send_object_parts_v2', 'params': {'parts': [{'share_id': shareId, 'fingerprint': fingerprint, 'size': size, 'data': 'BinaryData-0-' +str(size)}]}}
	print json.dumps(request)
	#response = self.copyrequest('/send_object_parts_v2', payload+chr(0)+data)
	response = self.httpconn.urlopen("POST", '/jsonrpc_binary', json.dumps(request)+chr(0)+data, headers)
	print "SEEEEEEEEEEEEEEEEEEEEENDDDDDDDDDDDDDDD"
	print response.data
	#print self.encodeRequest('send_object_parts_v2', payload)
	print "ENDDDDSENNDDDDDDDDDDDDD"
	return 0
    
    def encodeRequest(self, method, json):
	request = {'jsonrpc': 2.0, 'id': 0, 'method': method, 'params': json}
	return json.dumps(request)
    def hasPart(self, fingerprint, size, shareId = 0):
	data = {'parts': [{'share_id': shareId, 'fingerprint': fingerprint, 'size': size}]}
	response = self.copyrequest('/has_object_parts_v2', data)
	print "CCC"
	if not response['needed_parts']:	#Check that needed parts is empty
	    return True
	else:
	    part = response['needed_parts'][0]
	    return False
	     #if part['message']:
	        #throw new \Exception("Error checking for part: " . $part->message)
		#raise FuseOSError(EIO)
            #else:
		#return False
    def partify(self, f, size):
        parts = {}

        part_num = 0
        offset = 0
        while f.tell() < size:
            # obtain the part data
            offset = f.tell()
            part_data = f.read(1048576)
            parts[part_num] = {'fingerprint': hashlib.md5(part_data).hexdigest() + hashlib.sha1(part_data).hexdigest(), 'offset': offset, 'size': len(part_data), 'data': part_data}
            offset = f.tell()
            part_num += 1

        if size != offset:
            # print str(size) + " != " + str(offset)
            raise FuseOSError(EIO)

        return parts

class CopyFUSE(LoggingMixIn, Operations):
    def __init__(self, username, password, logfile=None):
        self.rwlock = Lock()
        self.copy_api = CopyAPI(username, password)
        self.logfile = logfile
        self.files = {}

    def file_rename(self, old, new):
        if old in self.files:
            self.files[new] = self.files[old]
            del self.files[old]

    def file_get(self, path, download=True):
        if path in self.files:
            return self.files[path]

        if download == True:
            raw = self.copy_api.copyrequest("/download_object", {'path': path}, False)
        else:
            raw = ''

        f = tempfile.NamedTemporaryFile(delete=False)
        #f.write(raw)
        self.files[path] = {'object': f, 'modified': False}

        # print "opening: " + path

        return self.files[path]

    def file_close(self, path):
        if path in self.files:
            if self.files[path]['modified'] == True:
                self.file_upload(path)

            # print "closing: " + path

            self.files[path]['object'].close()
            del self.files[path]

    def file_upload(self, path):
        if path not in self.files:
            raise FuseOSError(EIO)

        fileObject = self.file_get(path)
        if fileObject['modified'] == False:
            return True

        # print 'uploading: ' + path

        f = fileObject['object']

        # obtain the size of the file
        f.seek(0, os.SEEK_END)
        size = f.tell()
        f.seek(0)

        parts = self.copy_api.partify(f, size)

        # obtain list of parts that need to be sent
        response = self.copy_api.part_request('has_parts', parts)

        if 'send_parts' not in response:
            raise FuseOSError(EIO)

        # build array of parts that need to be sent
        need_parts = {}
        for need_part in response['send_parts']:
            need_parts[need_part['fingerprint'] + '-' + need_part['size']] = True

        # send the missing parts
        send_parts = {}
        for i in range(0, len(parts)):
            if parts[i]['fingerprint'] + '-' + str(parts[i]['size']) in need_parts:
                send_parts[len(send_parts)] = parts[i]
        response = self.copy_api.part_request('send_parts', send_parts)

        # trap any errors
        if (response == False or response['result'] != 'success'):
            raise FuseOSError(EIO)

        # remove data from parts (already sent)
        for i in range(0, len(parts)):
            del parts[i]['data']

        # send file metadata
        params = {'meta': {}}
        params['meta'][0] = {'action': 'create', 'object_type': 'file', 'path': path, 'size': size, 'parts': parts}
        response = self.copy_api.copyrequest('/update_objects', params, True)

        # trap any errors
        if response['result'] != 'success':
            raise FuseOSError(EIO)

        fileObject['modified'] = False

    def chmod(self, path, mode):
        return 0

    def chown(self, path, uid, gid):
        return 0

    def statfs(self, path):
    	params = {}
    	response = self.copy_api.copygetrequest('/rest/user', params, True)
    	blocks = response["storage"]["used"]/512
    	bavail = response["storage"]["quota"]/512
    	bfree  = (response["storage"]["quota"]-response["storage"]["used"])/512
        return dict(f_bsize=512, f_frsize=512, f_blocks=bavail, f_bfree=bfree, f_bavail=bfree)

    def getattr(self, path, fh=None):
        # print "getattr: " + path
        if path == '/':
            st = dict(st_mode=(S_IFDIR | 0755), st_nlink=2)
            st['st_ctime'] = st['st_atime'] = st['st_mtime'] = time.time()
        else:
            name = str(os.path.basename(path))
            objects = self.copy_api.list_objects(os.path.dirname(path))

            if name not in objects:
                raise FuseOSError(ENOENT)
            elif objects[name]['type'] == 'file':
                st = dict(st_mode=(S_IFREG | 0644), st_size=int(objects[name]['size']))
            else:
                st = dict(st_mode=(S_IFDIR | 0755), st_nlink=2)

            st['st_ctime'] = st['st_atime'] = objects[name]['ctime']
            st['st_mtime'] = objects[name]['mtime']

        st['st_uid'] = os.getuid()
        st['st_gid'] = os.getgid()
        return st

    def mkdir(self, path, mode):
        # print "mkdir: " + path
        # send file metadata
        params = {'meta': {}}
        params['meta'][0] = {'action': 'create', 'object_type': 'dir', 'path': path}
        response = self.copy_api.copyrequest('/update_objects', params, True)

        # trap any errors
        if response['result'] != 'success':
            raise FuseOSError(EIO)

	# update tree_children
 	name = os.path.basename(path)
 	self.copy_api.tree_children[os.path.dirname(path)][name] = {'name': name, 'type': 'dir', 'size': 0, 'ctime': time.time(), 'mtime': time.time()}

    def open(self, path, flags):
        logging.debug("Open File. Path = " + path)
	logging.debug(path)
	result = self.copy_api.getFile(path)
        logging.debug("End Open")
	#self.file_get(path)
        return 0

    def flush(self, path, fh):
        # print "flush: " + path
        if path in self.files:
            if self.files[path]['modified'] == True:
                self.file_upload(path)

    def fsync(self, path, datasync, fh):
        # print "fsync: " + path
        if path in self.files:
            if self.files[path]['modified'] == True:
                self.file_upload(path)

    def release(self, path, fh):
        # print "release: " + path
        self.file_close(path)

    def read(self, path, size, offset, fh):
        #f = self.file_get(path)['object']
        #f.seek(offset)
        #return f.read(size)
	logging.debug("Start Read")
	logging.debug("Reading File, Path = " + path)
	logging.debug("Reasing File, size = " + str(size))
	logging.debug("Reading File, Offset = " + str(offset))
	self.rwlock.acquire()
	data = self.copy_api.makeAvailableForRead(path, size, offset)
	self.rwlock.release()
	#f = open(localPath, 'r+')
	#f.seek(offset)
	logging.debug("End Read")
	#data = f.read(size)
	#f.close()
	return data
	
    def readdir(self, path, fh):
        # print "readdir: " + path
        objects = self.copy_api.list_objects(path)

        listing = ['.', '..']
        for child in objects:
            listing.append(child)
        return listing

    def rename(self, old, new):
        # print "renaming: " + old + " to " + new
        self.file_rename(old, new)
        params = {'meta': {}}
        params['meta'][0] = {'action': 'rename', 'path': old, 'new_path': new}
        self.copy_api.copyrequest("/update_objects", params, False)

    def create(self, path, mode):
        # print "create: " + path
        name = os.path.basename(path)
        if os.path.dirname(path) in self.copy_api.tree_children:
            self.copy_api.tree_children[os.path.dirname(path)][name] = {'name': name, 'type': 'file', 'size': 0, 'ctime': time.time(), 'mtime': time.time()}
        self.file_get(path, download=False)
        self.file_upload(path)
        return 0

    def truncate(self, path, length, fh=None):
        # print "truncate: " + path
        f = self.file_get(path)['object']
        f.truncate(length)

    def unlink(self, path):
        # print "unlink: " + path
        params = {'meta': {}}
        params['meta'][0] = {'action': 'remove', 'path': path}
        self.copy_api.copyrequest("/update_objects", params, False)

    def rmdir(self, path):
        params = {'meta': {}}
        params['meta'][0] = {'action': 'remove', 'path': path}
        self.copy_api.copyrequest("/update_objects", params, False)

    def write(self, path, data, offset, fh):
        #fileObject = self.file_get(path)
        #f = fileObject['object']
        #f.seek(offset)
        #f.write(data)
        #fileObject['modified'] = True
        #return len(data)
	print "WRTTEEEEEEEEEEEEEEEEEEEE"
	return 0

    # Disable unused operations:
    access = None
    getxattr = None
    listxattr = None
    opendir = None
    releasedir = None

def main():
    parser = argparse.ArgumentParser(
        description='Fuse filesystem for Copy.com')

    parser.add_argument(
        '-d', '--debug', default=False, action='store_true',
        help='turn on debug output (implies -f)')
    parser.add_argument(
        '-s', '--nothreads', default=False, action='store_true',
        help='disallow multi-threaded operation / run with only one thread')
    parser.add_argument(
        '-f', '--foreground', default=False, action='store_true',
        help='run in foreground')
    parser.add_argument(
        '-o', '--options', help='add extra fuse options (see "man fuse")')

    parser.add_argument(
        'username', metavar='EMAIL', help='username/email')
    parser.add_argument(
        'password', metavar='PASS', help='password')
    parser.add_argument(
        'mount_point', metavar='MNTDIR', help='directory to mount filesystem at')

    args = parser.parse_args(argv[1:])

    username = args.__dict__.pop('username')
    password = args.__dict__.pop('password')
    mount_point = args.__dict__.pop('mount_point')

    # parse options
    options_str = args.__dict__.pop('options')
    options = dict([(kv.split('=', 1)+[True])[:2] for kv in (options_str and options_str.split(',')) or []])

    fuse_args = args.__dict__.copy()
    fuse_args.update(options)

    logfile = None
    if fuse_args.get('debug', False) == True:
        # send to stderr same as where fuse lib sends debug messages
        logfile = stderr

    fuse = FUSE(CopyFUSE(username, password, logfile=logfile), mount_point, **fuse_args)


if __name__ == "__main__":
	main()
