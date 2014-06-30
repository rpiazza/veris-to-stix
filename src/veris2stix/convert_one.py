# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import sys
from convert import convert_file

if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.stderr.write("veris2stix warning: provide a json file that contains a VERIS record\n")
    else:
        convert_file(sys.argv[1], None, True)