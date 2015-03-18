json: src/org/json/*.java
	javac src/org/json/*.java

server: json src/server/Server.java src/server/ServerConnection.java src/util/Pair.java src/util/Response.java
	javac src/server/Server.java src/server/ServerConnection.java src/util/Pair.java src/util/Response.java

client: json src/client/Client.java src/client/Shell.java src/util/Pair.java src/util/Response.java
	javac src/client/Client.java src/client/Shell.java src/util/Pair.java src/util/Response.java

default: server client

clean:
	rm src/server/*.class src/client/*.class src/org/json/*.class org/util/*.class *.class

all: server client
