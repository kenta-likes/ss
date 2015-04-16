
json: org/json/*.java
	javac org/json/*.java

server: json server/Server.java server/ServerConnection.java util/Pair.java util/Response.java util/Carrier.java
	javac -cp javamail-1.4.7/mail.jar:. server/Server.java server/ServerConnection.java util/Pair.java util/Response.java util/Carrier.java util/Consts.java

client: json client/Client.java client/Shell.java util/Pair.java util/Response.java
	javac client/Client.java client/Shell.java util/Pair.java util/Response.java

logging: json logging/LogServer.java logging/LogConnection.java util/Pair.java util/Response.java
	 javac logging/LogServer.java logging/LogConnection.java util/Pair.java util/Response.java

default: server client logging

clean:
	rm server/*.class client/*.class org/json/*.class util/*.class logging/*.class

all: server client logging json
