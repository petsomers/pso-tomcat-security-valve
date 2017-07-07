# pso-tomcat-security-valve
Simple but effective security valve for Tomcat 7 and above

 ### Features:
- host name validation
- enforce https, optionally automatic redirection to https
- context based ip restriction
- set STS header
- skip valve based on
  - remote ip
  - host name
- runtime reload of configuration file

### Valve setup
1. Copy the jar file into tomcat/lib

2. server.xml:
```
<Valve className="pso.tomcat_security_valve.SecurityValve" 
   configFile="conf/pso-tomcat-security-valve.properties" />
```

### Configuration file
An example configuration file can be found here:
src/test/resources/config_example1.properties
