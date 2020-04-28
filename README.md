  To use Secure S3, download s3fs-fuse and simply replace the curl.cpp file with the curl.cpp file in this repository. To recompile the code, simply type "make" in the directory and it will recompile with the modified code. 
  
  To use the standalone RC4 program, compile with this command "g++ -o testRC4 testRC4.cpp -fpermissive -lcrypto". User the program in the terminal with this format "./testRC4 "filename" Key"
