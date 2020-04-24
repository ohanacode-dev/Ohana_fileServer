# Ohana_fileServer

A flask file server with a frontend for browsing, uploading and streaming files and basic git management.
It provides an option to create a shareable link to a file, so you can share it with someone without any credentials.
Also, downloading is direct (no browser necessary), so you can use command line tools like 'wget' or 'cget' to download files.

This is a fork of [Wildog/flask-file-server](https://github.com/Wildog/flask-file-server) , so thanks for the startup point.

The goal is to have a file server configurable enough for a corporate environment where other file sharing solutions do not work like 
windows file share and samba file sharing due to different OS used on various machines, windows active directory, proxy and port management,...
My personal frustration is file sharing via Google drive and similar which forces me to open a browser window and click on download icon. 
This prevents me from using command line tools for download which my ocupation often requires.

What I am trying to achieve is to have a standalone, easy to start solution. 
For now, unless differently configured, the server is sharing user home folder on port 8888, so after you run it, 
open your web browser and type the computer IP address on port 8888 (eg. http://192.168.0.10:8888).

### Prerequisites

I only run this on linux, so all the instructions are for linux, but it should work on any other OS type.
This app requires python3 libraries flask and humanize. I reccomend green to run the app. You may install them like:
```
pip3 install flask humanize
sudo apt install gunicorn3
```

### Instalation

Just copy this whole folder where ever you wish and run Ohana_fileServer.py once to create the default configuration file 
in the user home folder, then stop it and edit the configuration file:
```
/home/<user>/.OCFS/config.txt
```
After this you should use green unicorn or any other server to run your flask app because it will create multiple threads, 
support multiple users and keep restarting your file server if it crashes.
A simple command to run your app via unencrypted http:
```
gunicorn3 -b 0.0.0.0:8080 -w 3 Ohana_fileServer:app
```
You can also use port 80, but as this is a protected port, you would have to start gunicorn3 as root:
```
sudo gunicorn3 -b 0.0.0.0:80 -w 3 Ohana_fileServer:app
```
Or create a startup script and run that as sudo.
To make it run automatically at startup using sudo, I created a startup shell script and added a line in my /etc/sudoers:
``` 
<username> ALL=(ALL) NOPASSWD: <path to my startup script>
```
I am using [LetsEncrypt service](https://letsencrypt.org/) to generate an ssl certificate so I could run my server via 
registered domain at port 443 (for https) like:
```
gunicorn3 --certfile /etc/letsencrypt/live/<my domain url>/fullchain.pem --keyfile /etc/letsencrypt/live/<my domain url>/privkey.pem -b 0.0.0.0:443 -w 3 Ohana_fileServer:app
```
Before I could run this I had to install and run [certboot](https://certbot.eff.org/) to create ssl certificate and now 
I have a file server running via secure https connection.

### Disclaimer
I know this is not the most secure file server. There is only one password and no user name. There is a temporary server 
lockup after 3 failed login attempts, but the failed attempts counter is in the cookie, so all one needs to do is delete 
the cookie and the server will unlock. I tried using an array for this, but gunicorn3 runs the app in multiple threads 
which do not share the same data, so the whole thing becomes unreliable. A solution would be to create a text file in 
/tmp/ or a database to store the failed attempts and the client IP address, but I did not want to complicate things 
unnecessarily even more as this is good enough for me.

### license
Use this server as you wish, but please mention me somewhere in your project. If you do build something better I would 
be interested to hear about it. 