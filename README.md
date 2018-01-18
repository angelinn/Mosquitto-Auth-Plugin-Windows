# Mosquitto-Auth-Plugin-Windows

This plugin is a Windows port of the [mosquitto-auth-plug](https://github.com/jpmens/mosquitto-auth-plug).
It allows mosquitto authentication outside the password file.

What I have currently ported is only the JWT functionality, but it will not be hard to port the other authentication methods.

# Build
What you need is:
* Visual Studio 2017
* [OpenSSL](https://github.com/openssl/openssl) version that builds ssleay32.dll and libeay32.dll source code. I used 1.0.2m.
* [Curl](https://github.com/curl/curl) source code
* [Mosquitto](https://github.com/eclipse/mosquitto) source code

Build the above following the instructions on their github repositories.
Adjust the source code and library paths of the VS project to the source folders of the above projects and the lib files folder.

The final binary will be a file named ```auth-plugin.dll```
Copy it and all the dependencies (OpenSSL and Curl dlls) in the mosquitto folder and configure as instructed in the original project.

# License
Check [LICENSE.md](LICENSE.md) for more information.
