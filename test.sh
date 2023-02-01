#!/bin/bash
make clean

echo ""
echo "AES-CBC TEST:"
make aesCbcTest
bin/aesCbcTest
diff test.txt test.txt.enc.dec

echo ""
echo "FILE MANAGER TEST:"
make fileManagerTest
bin/fileManagerTest
diff test.txt test_copy.txt

echo ""
echo "SHA512 TEST:"
make sha512test
bin/sha512test

echo ""
echo "HMAC TEST:"
make hmactest
bin/hmactest
