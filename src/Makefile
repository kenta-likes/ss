json: org/json/*.java
	javac -g org/json/*.java

server: json server/Server.java server/ServerConnection.java util/Pair.java util/Response.java
	javac -g server/Server.java server/ServerConnection.java util/Pair.java util/Response.java

client: json client/Client.java client/Shell.java util/Pair.java util/Response.java
	javac -g client/Client.java client/Shell.java util/Pair.java util/Response.java

default: server client

clean:
	rm bin/server/*.class bin/client/*.class bin/org/json/*.class bin/util/*.class *.class

all: server client json
