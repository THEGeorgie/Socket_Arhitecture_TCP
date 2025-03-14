It is a simple group messaging app made in C for Linux.
This code can also run on different Unix-based OSes (macOS).

In the client code, you need to pass the IP address of the server (e.g., localhost) as an argument.
The IDE used to build this project is CLion by JetBrains.

If you dont use clion to compile the code run this command:

For the client:
gcc main.c -o "name of the executeble"
	to run:
./"name of the executeble" "ip adress of the server"

For the server:
gcc main.c -o "name of the executeble"
	to run:
./"name of the executeble"

Both programs use the port:3490
