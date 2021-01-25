openssl -aes-128-ecb -nosalt -nopad -K 00000000000000000000000000000000 -p -in pt.txt -out ct.txt; cat ct.txt | xxd -ps -u
