#file header dissector for Forensic/Malware pre-analysis
import sys
import os
import errno
import sha256sum #from hashlib
import shutil
header_map = {
    # Need to specify byte sequences to match the file types
    # Recall to specify byte values in a Python string use '\xFF'
    'png': '\x89\x50\x4E\x47\x0D\x0A\x1A',
    'jpeg': '\xFF\xD8\xFF',
    'pdf': '\x25\x50\x44\x46',
    'mz': '\x4D\x5A'}

def create_dir(name):
    try:
        os.makedirs(name)
    except OSError as exception:
        if exception.errno != errno.EEXIST:
            raise

def classify(dir_name):
    dir_fmt = '%s_samples'

# Create the directories:
    for key in header_map.keys():
        create_dir(dir_fmt % (key))

    create_dir(dir_fmt % ('unk'))

    for root, _, files, in os.walk(dir_name):
        for filename in files:
            path= os.path.join(root, filename)
            #Requires sha256sum sum first!
            sha_hash = sha256sum.sha256sum(path)
            with open(path, 'rb') as f:
                # Do you need to read the entire file into mercory?
                data= f.read(1024)#can it be less?
            found = False
                # Once you have header data you need to check aqainst the
                # header signatures in header_map
            for key, magic in header_map.items():
                print("Checking key in file: ", key, magic, data.find(magic))
                if data.find(magic) != -1:
                #-1 Means not found: if find lack of missing {double negative)
                    print("Found something", key)
                    found - True
                    new_path = os.path.join(dir_fmt % (key), '%s.bin' % (sha_hash))
                    shutil.copyfile(path, new_path)
                    break
            if found == False:
                print("defaulting")
                new_path = os.path.join(dir_fmt % ('unk'), '%s.bin' % (sha_hash))
                shutil.copyfile(path, new_path)

if __name__ == '__main__':
    classify(sys.argv[1])