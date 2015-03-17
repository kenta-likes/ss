json: org/json/*.java
	javac org/json/*.java

server: json server/Server.java server/ServerConnection.java util/Pair.java util/Response.java
	javac server/Server.java server/ServerConnection.java util/Pair.java util/Response.java

client: json client/Client.java client/Shell.java util/Pair.java util/Response.java
	javac client/Client.java client/Shell.java util/Pair.java util/Response.java

default: server client

clean:
	rm server/*.class; rm client/*.class; rm org/json/*.class; rm util/*.class

all: server client
