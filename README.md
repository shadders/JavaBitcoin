JavaBitcoin
===========

JavaBitcoin is a bitcoin client node written in Java.  It supports receiving and relaying blocks and transactions but does not support bitcoin mining.  This ensure that running this node won't cause a block chain fork although it might temporarily stop updating the block chain if it receives a block that it considers to be invalid.  It also support Simple Payment Verification (SPV) clients such as the Android Wallet and MultiBit.

It does full verification for blocks that it receives and will reject blocks that do not pass the verification tests.  These rejected blocks are still stored in the database and can be included in the block chain by either temporarily turning off block verification or by updating the verification logic.  Spent transaction outputs are removed from the database after 24 hours.  The full blocks are maintained in external storage in the same manner as the reference client (blknnnnn.dat files).

There is a graphical user interface that displays alerts, peer connections (network address and client version) and recent blocks (both chain and orphan).

BouncyCastle (1.50 or later) is used for the elliptic curve functions and Simple Logging Facade (1.7.5 or later) is used for console and file logging.

The PostgreSQL (9.3 or later) relational database is used.  I tried H2, Firebird and LevelDB as well but decided that I liked PostgreSQL the best.  It has a good GUI and provides tools to manage and backup the database.  You can also run SQL queries against the database from other applications if desired.  I went with an external server for this reason as well as not having to share the address space with the database manager.  However, it is fairly easy to change the block store to use a different database.  H2 and Firebird both provide embedded servers and require minor tweaks to the SQL commands.  LevelDB requires extensive changes since it is a key->value mapping.

Database performance isn't an issue during normal operation, but it is significant when loading the block chain for the first time.  This is primarily caused by the insert/update/delete cycle for the transaction outputs table.  As of February 2014, even with pruned outputs, the transaction outputs table has close to 10 million rows (one row per output).  Even consolidating this to one row per transaction doesn't really make much difference in performance.  One solution is to provide a SQL command file to recreate the database for a given point in time, although this requires some trust but no more than is required when downloading a bootstrap block chain.

There are no special build instructions.  I use the Netbeans IDE but any build environment with the Java compiler available should work.  The documentation is generated from the source code using javadoc.
