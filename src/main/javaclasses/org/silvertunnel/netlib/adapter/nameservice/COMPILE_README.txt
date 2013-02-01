# silvertunnel.org
#
# The java source files in this directory (src/main/resources/org/silvertunnel/netlib/adapter/nameservice/ )
# will be compiled manually compiled with different java versions
# and then committed tothe VCS, i.e. these files are NOT build with ant.

# go to here
cd src/main/resources/org/silvertunnel/netlib/adapter/nameservice/

# clean
rm *.class

# set enviroment to Java 1.6
...

# compile with Java 1.6
javac -source 1.5 -target 1.5 NameServiceNetlibGenericAdapter.java NameServiceNetlibJava6.java
rm NameServiceNetlibGenericAdapter.class

# set enviroment to Java 1.5
...

# compile with Java 1.5
javac NameServiceNetlibGenericAdapter.java NameServiceNetlibJava5.java

