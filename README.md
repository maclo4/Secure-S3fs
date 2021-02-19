# Secure S3FS
  Secure S3FS builds on top of s3fs-fuse to add encryption and decryption of files stores in Amazon S3. S3fs-fuse mounts a cloud-based storage system locally so that it can be accessed and used like a regular filesystem. Secure S3FS adds the feature that all files are encrypted when uploaded to Amazon S3 and decrypted with a unique key when mounted to your local filesystem.
  
  To use Secure S3, download s3fs-fuse and simply replace the curl.cpp file with the curl.cpp file in this repository. To recompile the code, simply type "make" in the directory and it will recompile with the modified code. 
  
  To use the standalone RC4 program, compile with this command "g++ -o testRC4 testRC4.cpp -fpermissive -lcrypto". User the program in the terminal with this format "./testRC4 "filename" Key"
