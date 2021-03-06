#!/usr/bin/env python

from __future__ import with_statement

from errno import EACCES, ENOENT, EIO, EPERM
from threading import Lock,Thread
from stat import S_IFDIR, S_IFREG
from sys import argv, exit, stderr
import Queue
import logging
import os
import argparse
import tempfile
import time
import json
import hashlib
import urllib3

from fuse import FUSE, FuseOSError, Operations, LoggingMixIn, fuse_get_context
from copyapi import CopyAPI
from cachemanager import FileManager, File, Chunk, CQueue

class CopyFUSE(LoggingMixIn, Operations):
    def __init__(self, username, password, logfile=None):
        logging.basicConfig(filename='/var/lib/plexmediaserver/Library/fuse.log', filemode='w', level=logging.DEBUG)
        logging.debug("Started copyfuse")
        self.rwlock = Lock()
        self.copy_api = CopyAPI(username, password)
        self.logfile = logfile
        self.files = FileManager()
        self.buffer = CQueue(3)
        self.jobqueue = Queue.Queue(1)
        self.crtchunk = -10

    def getFileEntry(self, path):
        meta = self.copy_api.getMeta(path)
        if not meta:    #couldnt find entry
            return -1   
        else:
            children = []
            for child in meta['children']:
                children.append(child['name'].encode('ascii', 'ignore'))
            if path == '/':
                file = File(path, 'dir', 0, children)
            else:
                file = File(path, meta['type'],meta['size'], children)
            self.files.files.append(file)
            return file

    def getParts(self, path):
        additionalOption = {'include_parts': 'true'}
        files = self.copy_api.listPath(path, additionalOption)
        latestRev = files['revisions'][0]
        chunks = []
        count = 0
        for part in latestRev['parts']:
            chunk = Chunk(part['fingerprint'], part['size'], part['offset'], count)
            chunks.append(chunk)
            count += 1
        if len(chunks) <= 0:
            logging.debug("ERROR, Could not get parts")
            raise FuseOSError(EIO)
        return chunks
    
    def getBufferParts(self):
        while True:
            job = self.jobqueue.get()
            chunk = job['chunk']
            logging.debug('In thread, getting chunk number = ' + str(chunk.num))
            
            self.buffer.put({'chunk': chunk, 'data': self.copy_api.getPart(chunk.fingerprint, chunk.size)})
            logging.debug('Finished processing in thread chunk')
    
    def preRead(self, file, offset):
        crtchunknum = file.getChunkNumber(self.crtchunk, offset)
        
        logging.debug("Cuurent chunk it thinks i am in = " + str(crtchunknum) + ' and sjsls = ' + str(self.crtchunk))
        if crtchunknum == -1:
            logging.debug("ERROR, couldnt find chunk")
            raise FuseOSError(EIO)
        else:
            if crtchunknum != self.crtchunk:
                if crtchunknum == self.crtchunk+1:
                    self.crtchunk += 1
                    self.buffer.get()
                    if self.crtchunk+2 < len(file.chunks):
                        logging.debug("Putting on job queue, chunk number = " + str(self.crtchunk+2))
                        self.jobqueue.put({'chunk': file.chunks[self.crtchunk+2]})
                else:
                    self.crtchunk = crtchunknum
                    currentChunk = crtchunknum
                    while not self.jobqueue.empty():
                        try:
                            jobqueue.get(False)
                        except Empty:
                            continue
                    self.buffer.clear()
                    for i in range(0,3):
                        if i + currentChunk < len(file.chunks):
                            chunk = file.chunks[i]
                            if i == 0:
                                self.buffer.currentChunk = {'chunk': chunk, 'data': self.copy_api.getPart(chunk.fingerprint, chunk.size)}
                            else:
                                 self.buffer.put({'chunk': chunk, 'data': self.copy_api.getPart(chunk.fingerprint, chunk.size)})
                                
                    
                

    def readData(self, file, offset, size, chunknum):
        chunk = self.buffer.currentChunk['chunk']
        #logging.debug('Reading Chunk = ' + str(chunknum))
        #logging.debug('chunk in queue head = ' + str(chunk.num))
        if offset >= file.size:
            return ""
        logging.debug('Head chunk num = ' + str(chunk.num) + ' size = ' + str(chunk.size))
        if chunk.num != chunknum:
            logging.debug('ERROR,  reading wrong chunk reading = ' + str(chunk.num) + 'Expected =' + str(chunknum))
            raise FuseOSError(EIO)
        
        data = ""
        while int(chunk.offset) < int(offset) + int(size):
            if self.buffer.currentChunk['chunk'].num != self.crtchunk:
                logging.debug('ERROR, reading wrong chunk reading = ' + str(self.buffer.currentChunk['chunk'].num) + 'Exoected =' + str(self.crtchunk))
                raise FuseOSError(EIO)
            if chunknum == len(file.chunks)-1:  #last chunk
                temp = file.size - offset
                if temp == 0:
                    return ""
                elif temp <= size:
                    size = temp
            logging.debug('chunk o = ' + str(chunk.offset) + ' chunk size = ' + str(chunk.size) + ' offset = ' +str(offset) + ' shs = ' + str(size))
            if int(chunk.offset) <= int(offset) and int(chunk.offset)+int(chunk.size) > int(offset)+int(size):
                logging.debug('case1')
                data += self.buffer.currentChunk['data'][(int(offset)-int(chunk.offset)):(int(offset)-int(chunk.offset)+int(size))]
            elif int(chunk.offset) <= int(offset) and int(chunk.offset)+int(chunk.size) <= int(offset)+int(size):
                logging.debug('case2')
                data += self.buffer.currentChunk['data'][int(offset)-int(chunk.offset):]    
                self.crtchunk += 1
                if self.crtchunk < len(file.chunks):
                    self.buffer.get()
                if self.crtchunk+2 < len(file.chunks):
                    logging.debug("Putting on job queue, chunk number = " + str(self.crtchunk+2))
                    self.jobqueue.put({'chunk': file.chunks[self.crtchunk+2]})
            else:
                data += self.buffer.currentChunk['data'][:int(offset)+int(size)-int(chunk.offset)]
            chunknum += 1
            if chunknum < len(file.chunks):
                chunk = file.chunks[chunknum]
            else:
                if len(data) != int(size):
                    logging.debug('ERROR, data length = ' + str(len(data)) + ' and size requested = '+ str(len(size)))
                    raise FuseOSError(EIO)
                else:
                    return data
        if len(data) != int(size):
            logging.debug('ERROR, data length and size requested not same length')
            raise FuseOSError(EIO)
        else:
            return data

    def chmod(self, path, mode):
        return 0

    def chown(self, path, uid, gid):
        return 0

    def statfs(self, path):
    	params = {}
    	response = self.copy_api.get('user')
        blocks = response["storage"]["used"]/512
    	bavail = response["storage"]["quota"]/512
    	bfree  = (response["storage"]["quota"]-response["storage"]["used"])/512
        return dict(f_bsize=512, f_frsize=512, f_blocks=bavail, f_bfree=bfree, f_bavail=bfree)
        #return dict(f_bsize=512, f_frsize=512)

    def getattr(self, path, fh=None):
        logging.debug("getattr: " + path)
        file = self.files.findFileByPath(path)
        if file == -1:
            file = self.getFileEntry(path)
           
            if file == -1: #for now empty, some other action such as mkdir or create will be called 
                st = dict(st_mode=(S_IFREG | 0644))
                return st
        
        if path == '/':
            st = dict(st_mode=(S_IFDIR | 0755), st_nlink=2)
            st['st_ctime'] = st['st_atime'] = st['st_mtime'] = time.time()
        else:
            if file.type  == 'file':
                logging.debug('file size = ' + str(int(file.size)))
                st = dict(st_mode=(S_IFREG | 0644), st_size=int(file.size))
            else:
                st = dict(st_mode=(S_IFDIR | 0755), st_nlink=2)
                st['st_ctime'] = st['st_atime'] = st['st_mtime'] = time.time()
                #later change these and add them as attributes of file class
                #st['st_ctime'] = st['st_atime'] = objects[name]['ctime']
                #st['st_mtime'] = objects[name]['mtime']

        st['st_uid'] = os.getuid()
        st['st_gid'] = os.getgid()
        return st

    def mkdir(self, path, mode):
        print "mkdir: " + path
        # send file metadata
        #params = {'meta': {}}
        #params['meta'][0] = {'action': 'create', 'object_type': 'dir', 'path': path}
        #response = self.copy_api.copyrequest('/update_objects', params, True)

        # trap any errors
        #if response['result'] != 'success':
        #    raise FuseOSError(EIO)

	# update tree_children
 	#name = os.path.basename(path)
 	#self.copy_api.tree_children[os.path.dirname(path)][name] = {'name': name, 'type': 'dir', 'size': 0, 'ctime': time.time(), 'mtime': time.time()}

    def open(self, path, flags):
        logging.debug("Open File. Path = " + path)
        logging.debug("End Open")
        file = self.files.findFileByPath(path)
        if file == -1:
            file = self.getFileEntry(path)
            if file == -1:
                logging.debug("ERROR, Couldnot get file")
                raise FuseOSError(EIO)
        if len(file.chunks) <= 0:
            file.chunks = self.getParts(path)
        logging.debug('Size of file = ' + str(file.size))
        return 0

    def flush(self, path, fh):
         print "flush: " + path
        #if path in self.files:
        #    if self.files[path]['modified'] == True:
        #        self.file_upload(path)

    def fsync(self, path, datasync, fh):
         print "fsync: " + path
        #if path in self.files:
        #    if self.files[path]['modified'] == True:
        #        self.file_upload(path)

    def release(self, path, fh):
         print "release: " + path
        #self.file_close(path)

    def read(self, path, size, offset, fh):
        logging.debug("Start Read, size = " + str(size) + ' offset = '+ str(offset))
        if self.crtchunk == -10:
            t = Thread(target=self.getBufferParts)
            t.deamon = True
            t.start()
        file = self.files.findFileByPath(path)
        if file == -1:
            logging.debug("ERROR, Couldnt find file, in method readir")
            raise FuseOSError(EIO)
        else:
            self.preRead(file, offset)
            logging.debug("End Read1")
            data = self.readData(file, offset, size, self.crtchunk)
            logging.debug("End Read2")
            return data
        #logging.debug("Reading File, Path = " + path)
        #logging.debug("Reasing File, size = " + str(size))
        #logging.debug("Reading File, Ofafset = " + str(offset))
        #self.rwlock.acquire()
        #data = self.copy_api.makeAvailableForRead(path, size, offset)
        #self.rwlock.release()
        logging.debug("End Read")
        return 0
	
    def readdir(self, path, fh):
        logging.debug("readdir: " + path)
        listing = ['.', '..']
        file = self.files.findFileByPath(path)
        if file == -1:
            logging.debug("ERROR, Couldnt find file, in method readir")
            raise FuseOSError(EIO)
        else:
            for child in file.children:
                listing.append(child)
            return listing

    def rename(self, old, new):
        print "renaming: " + old + " to " + new
        #logging.debug("Renaming file. Old file = " + old + " New file = " + new)
        #self.file_rename(old, new)
        #params = {'meta': {}}
        #params['meta'][0] = {'action': 'rename', 'path': old, 'new_path': new}
        #self.copy_api.copyrequest("/update_objects", params, False)

    def create(self, path, mode):
        print "create: " + path
        #name = os.path.basename(path)
        #if os.path.dirname(path) in self.copy_api.tree_children:
        #    self.copy_api.tree_children[os.path.dirname(path)][name] = {'name': name, 'type': 'file', 'size': 0, 'ctime': time.time(), 'mtime': time.time()}
        #self.file_get(path, download=False)
        #self.file_upload(path)
        return 0

    def truncate(self, path, length, fh=None):
        print "truncate: " + path
        #f = self.file_get(path)['object']
        #f.truncate(length)

    def unlink(self, path):
        print "unlink: " + path
        #params = {'meta': {}}
        #params['meta'][0] = {'action': 'remove', 'path': path}
        #self.copy_api.copyrequest("/update_objects", params, False)

    def rmdir(self, path):
        params = {'meta': {}}
        params['meta'][0] = {'action': 'remove', 'path': path}
        #self.copy_api.copyrequest("/update_objects", params, False)

    def write(self, path, data, offset, fh):
        #logging.debug("Enter Fuse Write Function")
	#logagiang.debug("Write, Path = " + path)
	#logging.debug("Write, Offset = " + str(offset))
	#fileObject = self.file_get(path)
        #f = fileObject['object']
        #f.seek(offset)
        #f.write(data)
        #fileObject['modified'] = True
        #return len(data)
	#print "WRTTEEEEEEEEEEEEEEEEEEEE"
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
