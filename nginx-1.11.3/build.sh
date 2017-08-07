#########################################################################
# File Name: build.sh
# Author: xgod
# mail: xgod@163.com
# Created Time: Mon 19 Dec 2016 03:57:06 PM CST
#########################################################################
#!/bin/bash

./configure --with-debug --prefix=$(pwd)/../bin --add-module=$(pwd)/.. --with-pcre=$(pwd)/../pcre-8.40
