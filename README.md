JavaBitcoin
===========

JavaBitcoin is a bitcoin client node written in Java.  It supports receiving and relaying blocks and transactions but does not support bitcoin mining.  This ensure that running this node won't cause a block chain fork.  It also support Simple Payment Verification (SPV) clients such as the Android Wallet and MultiBit.

It does full verification for blocks that it receives and will reject blocks that do not pass the verification tests.  These rejected blocks are still stored in the database and can be included in the block chain by either temporarily turning off block verification or by updating the verification logic.  Spent transaction outputs are periodically removed from the database.  The full blocks are maintained in external storage in the same manner as the reference client (blknnnnn.dat files).

There is a graphical user interface that displays alerts, peer connections (network address and client version) and recent blocks (both chain and orphan).

You can use the production network (PROD) or the regression test network (TEST).  The regression test network is useful because bitcoind will immediately generate a specified number of blocks.  To use the regression test network, start bitcoind with the -regtest option.  You can then generate blocks using bitcoin-cli to issue 'setgenerate true n' where 'n' is the number of blocks to generate.  Block generation will stop after the requested number of blocks have been generated.  Note that the genesis block, address formats and magic numbers are different between the two networks.  JavaBitcoin will create files related to the TEST network in the TestNet subdirectory of the application data directory.

BouncyCastle (1.51 or later) is used for the elliptic curve functions.  Version 1.51 provides a custom SecP256K1 curve which significantly improves ECDSA performance.  Earlier versions of BouncyCastle do not provide this support and will not work with JavaBitcoin.

Simple Logging Facade (1.7.5 or later) is used for console and file logging.  I'm using the JDK logger implementation which is controlled by the logging.properties file located in the application data directory.  If no logging.properties file is found, the system logging.properties file will be used (which defaults to logging to the console only).

JavaBitcoin supports LevelDB and PostgreSQL databases and defaults to LevelDB.

The LevelDB support is provided by leveldbjni (1.8 or later).  leveldbjni provides a native interface to the LevelDB routines.  The native LevelDB library is included in the leveldbjni.jar file and is extracted when you run the program.  On Windows, this causes a new temporary file to be created each time the program is run.  To get around this, extract the Windows version of leveldbjni.dll from the leveldbjni.jar and place it in a directory in the executable path (specified by the PATH environment variable).  Alternately, you can define the path to leveldbjni.dll by specifying '-Djava.library.path=directory-path' on the command line used to start JavaBitcoin.

The PostgreSQL (9.3 or later) relational database can also be used.  It has a good GUI and provides tools to manage and backup the database.  You can also run SQL queries against the database from other applications if desired.  I went with an external server for this reason as well as not having to share the address space with the database manager.  However, it is fairly easy to change the block store to use a different database.  H2 and Firebird both provide embedded servers and require minor tweaks to the SQL commands.

Database performance isn't an issue during normal operation, but it is significant when loading the block chain for the first time.  This is primarily caused by the insert/update/delete cycle for the transaction outputs table.  As of February 2014, even with pruned outputs, the transaction outputs table has close to 10 million rows (one row per output).  Even consolidating this to one row per transaction doesn't really make much difference in performance.

A compiled version is available here: https://drive.google.com/folderview?id=0B1312_6UqRHPYjUtbU1hdW9VMW8&usp=sharing.  Download JavaBitcoin-1.1.zip and extract the files to a directory of your choice.  If you are building from the source, the dependent jar files can also be obtained here.


Build
=====

I use the Netbeans IDE but any build environment with the Java compiler available should work.  The documentation is generated from the source code using javadoc.

Here are the steps for a manual build:

  - Create 'doc', 'lib' and 'classes' directories under the JavaBitcoin directory (the directory containing 'src')
  - Download Java SE Development Kit 7: http://www.oracle.com/technetwork/java/javase/downloads/index.html
  - Download BouncyCastle 1.51 or later to 'lib': https://www.bouncycastle.org/
  - Download Simple Logging Facade 1.7.5 or later to 'lib': http://www.slf4j.org/
  - Download leveldbjni 1.8 or later to 'lib': http://repo2.maven.org/maven2/org/fusesource/leveldbjni/leveldbjni-all/1.8/
  - (Optional)Download PostgreSQL 9.3 or later to 'lib': http://www.postgresql.org/
  - Change to the JavaBitcoin directory (with subdirectories 'doc', 'lib', 'classes' and 'src')
  - The manifest.mf, build-list and doc-list files specify the classpath for the dependent jar files.  Update the list as required to match what you downloaded.
  - Build the classes: javac @build-list
  - Build the jar: jar cmf manifest.mf JavaBitcoin.jar -C classes JavaBitcoin -C resources GenesisBlock
  - Build the documentation: javadoc @doc-list
  - Copy JavaBitcoin.jar and the 'lib' directory to wherever you want to store the executables.
  - Create a shortcut to start JavaBitcoin using java.exe for a command window or javaw.exe for GUI only.  For example:
  
      java.exe -Xmx512m -jar path-to-executables\JavaBitcoin.jar PROD
  
  
Install
=======

After installing PostgreSQL, you need to create a role and a database for use by JavaBitcoin.

  - CREATE ROLE javabtc LOGIN CREATEDB REPLICATION INHERIT PASSWORD "btcnode"
  - CREATE DATABASE javadb WITH ENCODING='UTF8' OWNER=javabtc LC_COLLATE='English_UnitedStates.1252' LC_CTYPE='English_UnitedStates.1252' CONNECTION LIMIT=-1

No special installation is required for the LevelDB database.

JavaBitcoin stores its application data in user-home/AppData/Roaming/JavaBitcoin.  You can override this by specifying -Dbitcoin.datadir=data-path on the command line before the -jar option.  The blocks are stored in the Blocks subdirectory.  The LevelDB databases are stored in the LevelDB subdirectory.

The first time you start JavaBitcoin, it will create and initialize the tables in the database.  You will also need to resize the GUI to the desired size.  Stop and restart JavaBitcoin and the GUI tables should be resized to match the new window dimensions.

If you have Bitcoin-Qt already installed, you can use its block files to build the database as follows:

  java -Xmx512m -Dbitcoin.verify.blocks=0 -jar JavaBitcoin.jar LOAD PROD "%Bitcoin%"
  
where %Bitcoin% specifies the Bitcoin-Qt application directory (for example, \Users\YourName\AppData\Roaming\Bitcoin).

Otherwise, start JavaBitcoin and it will download the block chain from the peer network:

  java -Xmx512m -jar JavaBitcoin.jar PROD


Runtime Options
===============

The following command-line arguments are supported:

  - LOAD PROD|TEST directory-path start-block	
    Load the block chain from the reference client data directory and create the block database. Specify PROD to load the production database or TEST to load the test database. The default reference client data directory will be used if no directory path is specified. The program will terminate after loading the block chain.
	
  - PROD peer1 peer2 ...	
    Start the program using the production network. Application files are stored in the application data directory and the production database is used. DNS discovery will be used if no peer nodes are specified.
	
  - RETRY PROD|TEST block-hash	
    Retry a block which is currently held. Specify PROD to use the production database or TEST to use the test database. The block hash is the 64-character hash for the block to be retried.
	
  - TEST peer1 peer2 ...	
    Start the program using the regression test network. Application files are stored in the TestNet folder in the application data directory and the test database is used. At least one peer node must be specified since DNS discovery is not supported for the regression test network.
	
A peer is specified as address:port. Specifying 'none' will result in no outbound connections and the program will just listen for inbound connections.

The following command-line options can be specified using -Dname=value

  - bitcoin.datadir=directory-path	
    Specifies the application data directory. Application data will be stored in /UserHome/AppData/Roaming/JavaBitcoin if no path is specified.
	
  - bitcoin.verify.blocks=n	
    Blocks are normally verified as they are added to the block chain. Block verification can be disabled to improve performance. Specify 1 to enable verification and 0 to disable verification. The default is 1.
	
  - java.util.logging.config.file=file-path	
    Specifies the logger configuration file. The logger properties will be read from 'logging.properties' in the application data directory. If this file is not found, the 'java.util.logging.config.file' system property will be used to locate the logger configuration file. If this property is not defined, the logger properties will be obtained from jre/lib/logging.properties.
	
    JDK FINE corresponds to the SLF4J DEBUG level	
	JDK INFO corresponds to the SLF4J INFO level	
	JDK WARNING corresponds to the SLF4J WARN level	
	JDK SEVERE corresponds to the SLF4J ERROR level	
	
The following properties can be specified in javabitcoin.properties:

  - maxconnections=n	
    Specifies the maximum number of inbound and outbound connections and defaults to 32.
	
  - maxoutbound=n	
    Specifies the maximum number of outbound connections and defaults to 8.
	
  - port=n	
	Specifies the port for receiving inbound connections and defaults to 8333
	
  - dbtype=type	
	Specify 'leveldb' to use LevelDB for the database or 'postgresql' to use PostgreSQL. The LevelDB database will be used if no value is specified.  Note that changing the database type after running JavaBitcoin will require the new database to be built starting with the genesis block.  For this reason, the Blocks subdirectory should be deleted before starting JavaBitcoin for the first time after changing the database.  You can move the files to another directory and then use them to load the new database.
	
  - dbuser=userid	
    Specifies the PostgreSQL database user name
	
  - dbpw=password	
    Specifies the PostgreSQL database password
	
  - dbport=n	
	Specifies the PostgreSQL database TCP/IP port  
