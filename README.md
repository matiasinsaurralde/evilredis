evilredis
=========
Small script for doing evil stuff to Redis servers
(for educational purposes only)

## usage
```
npm install -g evilredis
```
Then:
```
== evilredis >:)

 Syntax:	evilredis [ target ] [ level = 0 ]
 Ex.		evilredis 192.168.0.0/24 1

 - Level 0: quick scan, dump server info & keys
 - Level 1: flushall
 - Level 2: flushall & shutdown
 - Level 3: root >:) (requires a pubkey)

   Specify your pubkey after evilness level
   Example: $ evilredis x.x.x.x 3 ~/.ssh/id_rsa.pub

 USE AT YOUR OWN RISK!
 ```
