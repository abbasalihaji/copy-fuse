#!/usr/bin/env python

import Queue
class FileManager:

    def __init__ (self):
	    self.files = []

    def findFileByPath(self, path):
	    for file in self.files:
	        if file.path == path:
		    return file
	    return -1

class File:

    def __init__ (self, path, type, size, children):
        self.path = path
        self.type = type
        self.size = size
        self.children = children
        self.chunks = []

class Chunk:

    def __init__ (self, fingerprint, size, offset, isAvailable = False):
	    self.fingerprint = fingerprint
	    self.size = size
	    self.offset = offset
	    self.isAvailable = isAvailable
	    self.localoffset = 0

class CQueue:
	
    def __init__ (self, size):
	    self.q = Queue.Queue(10)
	    self.currentChunk = ""
	
    def get(self):
	    if self.q.empty():
	        temp = ""
	    else:
	        self.currentChunk = self.q.get()

    def empty(self):
	    return self.q.empty()

    def put(self, data):
	    self.q.put(data)

    def clear(self):
	    self.q.queue.clear()
