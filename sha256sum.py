import sys
import hashlib

def sha256sum(filename):
    # Read file in chunks, trying to read large files into RAM
    # may crash the program if too large of a file
    chunk_sz = 1024
    
    with open(filename, 'rb') as f:
        data = f.read(chunk_sz)
        sha = hashlib.sha256()
        while data != '':
            sha.update(data)
            data = f.read(chunk_sz)
    return sha.hexdigest()

if __name__ == '__main__':
    filename = sys.argv[1]
    sha_hash = sha256sum(filename)
    sys.stdout.write('%s\t%s\n' % (sha_hash, filename))
