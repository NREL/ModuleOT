#Hex to asciii DERP....
#openssl aes-128-ecb -nosalt -nopad -K 00000000000000000000000000000000 -in pt.txt -out ct.txt| xxd -ps -u 
openssl aes-128-ecb -nosalt -nopad -K 00000000000000000000000000000000 -in pt.txt | xxd -ps -u 
