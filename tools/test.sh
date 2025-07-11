#!/bin/bash

echo "--- Timing /bin/ls ---"
/bin/time --verbose /bin/ls > /dev/null
echo "--- Timing /bin/ls with Pin ---"
/bin/time --verbose pin -t obj-intel64/taintfuzz.so -- /bin/ls > /dev/null

echo ""
echo "--- Timing /bin/grep ---"
/bin/time --verbose /bin/grep "test" /dev/null > /dev/null
echo "--- Timing /bin/grep with Pin ---"
/bin/time --verbose pin -t obj-intel64/taintfuzz.so -- /bin/grep "test" /dev/null > /dev/null

echo ""
echo "--- Timing /usr/bin/find ---"
/bin/time --verbose /usr/bin/find . -maxdepth 1 > /dev/null
echo "--- Timing /usr/bin/find with Pin ---"
/bin/time --verbose pin -t obj-intel64/taintfuzz.so -- /usr/bin/find . -maxdepth 1 > /dev/null

echo ""
echo "--- Timing /usr/bin/sort ---"
/bin/time --verbose /usr/bin/sort /etc/passwd > /dev/null
echo "--- Timing /usr/bin/sort with Pin ---"
/bin/time --verbose pin -t obj-intel64/taintfuzz.so -- /usr/bin/sort /etc/passwd > /dev/null

echo ""
echo "--- Timing /usr/bin/wc ---"
/bin/time --verbose /usr/bin/wc /etc/group > /dev/null
echo "--- Timing /usr/bin/wc with Pin ---"
/bin/time --verbose pin -t obj-intel64/taintfuzz.so -- /usr/bin/wc /etc/group > /dev/null
