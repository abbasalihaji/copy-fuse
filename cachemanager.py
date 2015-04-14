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
    
    def getChunkNumber(self, guess, offset):
        numChunks = len(self.chunks)
        if numChunks <= 0:
            return -1
        else:
            if guess < numChunks:
                chunk = self.chunks[guess]
                if int(chunk.offset) <= int(offset) and (int(chunk.offset) + int(chunk.size)) > int(offset):
                    return guess
                else:
                    if (guess+1) < numChunks:
                        chunk = self.chunks[guess+1]
                        if int(chunk.offset) <= int(offset) and (int(chunk.offset) + int(chunk.size)) > int(offset):
                            return guess+1
            counter = 0
            while counter < numChunks:
                chunk = self.chunks[counter]
                if int(chunk.offset) <= int(offset) and (int(chunk.offset) + int(chunk.size)) > int(offset):
                    return counter
                counter += 1
            return -1

class Chunk:

    def __init__ (self, fingerprint, size, offset, num, isAvailable = False):
        self.num = num
        self.fingerprint = fingerprint
        self.size = size
        self.offset = offset
        self.isAvailable = isAvailable
        self.localoffset = 0

class CQueue:
	
    def __init__ (self, size):
	    self.q = Queue.Queue(size-1)
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
        while not self.q.empty():
            try:
                q.get(False)
            except Empty:
                continue
	        q.task_done()
