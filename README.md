JavaBitcoin
===========

JavaBitcoin is a bitcoin client node written in Java.  It supports receiving and relaying blocks and transactions but does not support bitcoin mining.  This ensure that running this node won't cause a block chain fork although it might temporarily stop updating the block chain if it receives a block that it considers to be invalid.  It also support Simple Payment Verification (SPV) clients such as the Android Wallet and MultiBit.

It does full verification for blocks that it receives and will reject blocks that do not pass the verification tests.  These rejected blocks are still stored in the database and can be included in the block chain by either temporarily turning off block verification or by updating the verification logic.  Spent transaction outputs are removed from the database after 24 hours.  The full blocks are maintained in external storage in the same manner as the reference client (blknnnnn.dat files).

There is a graphical user interface that displays alerts, peer connections (network address and client version) and recent blocks (both chain and orphan).

BouncyCastle (1.50 or later) is used for the elliptic curve functions and Simple Logging Facade (1.7.5 or later) is used for console and file logging.

The PostgreSQL (9.3 or later) relational database is used.  I tried H2, Firebird and LevelDB as well but decided that I liked PostgreSQL the best.  It has a good GUI and provides tools to manage and backup the database.  You can also run SQL queries against the database from other applications if desired.  I went with an external server for this reason as well as not having to share the address space with the database manager.  However, it is fairly easy to change the block store to use a different database.  H2 and Firebird both provide embedded servers and require minor tweaks to the SQL commands.  LevelDB requires extensive changes since it is a key->value mapping.

Database performance isn't an issue during normal operation, but it is significant when loading the block chain for the first time.  This is primarily caused by the insert/update/delete cycle for the transaction outputs table.  As of February 2014, even with pruned outputs, the transaction outputs table has close to 10 million rows (one row per output).  Even consolidating this to one row per transaction doesn't really make much difference in performance.  One solution is to provide a SQL command file to recreate the database for a given point in time, although this requires some trust but no more than is required when downloading a bootstrap block chain.

Build
=====

I use the Netbeans IDE but any build environment with the Java compiler available should work.  The documentation is generated from the source code using javadoc.

Here are the steps for a manual build:

  - Create 'doc', 'lib' and 'classes' directories under the JavaBitcoin directory (the directory containing 'src')
  - Download Java SE Development Kit 7: http://www.oracle.com/technetwork/java/javase/downloads/index.html
  - Download BouncyCastle 1.50 or later to 'lib': https://www.bouncycastle.org/
  - Download Simple Logging Facade 1.7.5 or later to 'lib': http://www.slf4j.org/
  - Download PostgreSQL 9.3 or later to 'lib': http://www.postgresql.org/
  - Change to the JavaBitcoin directory (with subdirectories 'doc', 'lib', 'classes' and 'src')
  - The manifest.mf, build-list and doc-list files specify the classpath for the dependent jar files.  Update the list as required to match what you downloaded.
  - Build the classes: javac @build-list
  - Build the jar: jar cmf manifest.mf JavaBitcoin.jar -C classes JavaBitcoin
  - Build the documentation: javadoc @doc-list
  
Install
=======

After installing PostgreSQL, you need to create a role and a database for use by JavaBitcoin.

  - CREATE ROLE javabtc LOGIN CREATEDB REPLICATION INHERIT PASSWORD "btcnode"
  - CREATE DATABASE javadb WITH ENCODING='UTF8' OWNER=javabtc LC_COLLATE='English_UnitedStates.1252' LC_CTYPE='English_UnitedStates.1252' CONNECTION LIMIT=-1

The first time you start JavaBitcoin, it will create and initialize the tables in the database.  You will also need to resize the GUI to the desired size.  Stop and restart JavaBitcoin and the tables should be resized to match the new window dimensions.

If you have Bitcoin-Qt already installed, you can use its block file to build the database as follows:

  java -Xmx512m -Dbitcoin.verify.blocks=0 -jar JavaBitcoin.jar LOAD PROD "%Bitcoin%"
  
where %Bitcoin% specifies the Bitcoin-Qt application directory (for example, /Users/name/AppData/Roaming/Bitcoin).

Otherwise, start JavaBitcoin and it will download the block chain from the peer network:

  java -Xmx512m -jar JavaBitcoin.jar PROD
  
See the documentation for JavaBitcoin.Main for additional start options.