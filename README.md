Concurrent Web Server
==============

Ryan Lukas

CS 4400 - Computer Systems - Spring 2020

*C*

Background
------------

This project we implemented and modified a web server to implement a concurrent friend-list server.

*NOTE: My implemented code is within friendlist.c.*

Starting
------------

To build and initialize the server type in console:
```
make
./friendlist <port>
```
where < port > is between 1024 and 65535.
  
Server Queries
------------
```
-/friends?user=‹user› — Returns the friends of ‹user›, each on a separate newline-terminated line as plain text (i.e., text/plain; charset=utf-8).  The result is empty if no friends have been registered for the user.

The result can report the friends of ‹user› in any order.

-/befriend?user=‹user›&friends=‹friends› — Adds each user in ‹friends› as a friend of ‹user›, which implies adding ‹user› as a friend of each user in ‹friends›.  The ‹friends› list can be a single user or multiple newline-separated user names, and ‹friends› can optionally end with a newline character.

If ‹user› and any user in ‹friends› are already friends, then the befriend request does not create a redundant friend entry.

The result should be a list of friends for ‹user›, the same as if the query /friends?user=‹user› were immediately sent.

Note that a long list of friends in ‹friends› requires that the friends part of the query is sent as POST data, instead of supplied as part of the URL.  The provided code already merges POST query data with URL query arguments for you, so POST is only relevant if you want to construct extra large tests.

-/unfriend?user=‹user›&friends=‹friends› — Removes each user in ‹friends› as a friend of ‹user› and vice versa.  The result should be a list of remaining friends to ‹user›.

If ‹user› and any user in ‹friends› are not currently friends, then the unfriend request ignores that user in ‹friends› (i.e., it is not an error).

-/introduce?user=‹user›&friend=‹friend›&host=‹host›&port=‹port› — Contacts a friend-list server running on ‹host› at ‹port› to get all of the friends of ‹friend›, and adds ‹friend› plus all of ‹friend›’s friends as friends of ‹user› and vice versa.
```

Example of server call on localhost at port 8090
```
$ curl "http://localhost:8090/befriend?user=me&friends=alice"

alice

$ curl "http://localhost:8090/befriend?user=me&friends=alice"

alice
```



