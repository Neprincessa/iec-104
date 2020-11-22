# at frst dowbload file from here -> https://osdn.net/projects/sfnet_snap7/downloads/1.4.0/snap7-full-1.4.0.zip/ 


unzip snap7-full-1.4.0.zip
cd snap7-full-1.4.0
ls
sudo apt-get install -y python3-pip
sudo -H pip3 install python-snap7
cd build/unix
make -f x86_64_linux.mk
cd ../bin/x86_64-linux/
sudo cp libsnap7.so /usr/lib
sudo ldconfig
