# Karaf embedded Apache Directory Service

This bundle inlcudes ApacheDS 2. It exports ApacheDS API, LDAP-Client and Shared classes. 

## Karaf dependencies

```
feature:install scr
feature:install transaction
feature:install http

bundle:install mvn:org.apache.mina/mina-core/2.0.20
bundle:install mvn:commons-collections/commons-collections/3.2.2
bundle:install mvn:commons-lang/commons-lang/2.6
bundle:install mvn:commons-codec/commons-codec/1.12
bundle:install mvn:org.apache.commons/commons-pool2/2.6.1
bundle:install mvn:org.apache.servicemix.bundles/org.apache.servicemix.bundles.antlr/2.7.7_5
bundle:install mvn:org.apache.servicemix.bundles/org.apache.servicemix.bundles.xpp3/1.1.4c_7
bundle:install mvn:org.apache.servicemix.bundles/org.apache.servicemix.bundles.dom4j/1.6.1_5
bundle:install mvn:org.bouncycastle/bcprov-jdk15on/1.61
bundle:install mvn:org.bouncycastle/bcpg-jdk15on/1.61
bundle:install mvn:org.apache.servicemix.bundles/org.apache.servicemix.bundles.junit/4.12_1
bundle:install mvn:org.apache.servicemix.bundles/org.apache.servicemix.bundles.quartz/2.3.0_2
```
## Install 
```
bundle:install -s mvn:org.sodeac/org.sodeac.karaf.apacheds/0.1.0
```
## Configuration

```
config:edit org.sodeac.karaf.apacheds
config:property-set servicename default
config:property-set directory "${karaf.base}/data/ads"
config:property-set ldapaddress 127.0.0.1
config:property-set ldapport 10389
config:property-set ldapsaddress 127.0.0.1
config:property-set ldapsport 10636
config:property-set allowanonymousaccess false
config:update
```

default login is: _uid=admin,ou=system_ / _secret_

## Credits
 * [Apache Karaf](https://karaf.apache.org/)
 * [Apache DS](https://directory.apache.org/apacheds/)
