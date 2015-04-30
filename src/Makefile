
json: org/json/*.java
	javac org/json/*.java

server: json server/Server.java server/ServerConnection.java server/Logger.java util/Pair.java util/Response.java util/Carrier.java
	javac -cp javamail-1.4.7/mail.jar:. server/Server.java server/ServerConnection.java util/Pair.java util/Response.java util/Carrier.java util/Consts.java

client: json client/Client.java client/Shell.java util/Pair.java util/Response.java
	javac client/Client.java client/Shell.java util/Pair.java util/Response.java

logging: json logging/LogServer.java logging/LogClient.java logging/LogConnection.java util/Pair.java util/Response.java
	 javac logging/LogServer.java logging/LogConnection.java util/Pair.java util/Response.java logging/LogClient.java

default: server client logging

clean:
	rm server/*.class client/*.class org/json/*.class util/*.class logging/*.class

clientjar: json client
	jar cvfm Client.jar client/MANIFEST.MF client/*.class client/*.java util/*.class util/*.java org/json/*.class

serverjar: json server
	jar cvfm Server.jar server/MANIFEST.MF server/*.class server/*.java util/*.class util/*.java org/json/*.class javamail-1.4.7/mail.jar

loggingjar: json logging
	jar cvfm LogServer.jar logging/server/MANIFEST.MF logging/LogServer.class logging/LogConnection.class util/*.class util/*.java org/json/*.class; jar cvfm LogClient.jar logging/client/MANIFEST.MF logging/LogClient.class util/*.class org/json/*.class

all: server client json clientjar serverjar
