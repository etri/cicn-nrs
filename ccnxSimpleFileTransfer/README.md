CCNx 1.0 Simple File Transfer Example
=================

A simple file transfer server and client application for CCNx built on the Portal API. 

[CCNx Simple File Transfer main page](https://github.com/PARC/ccnxSimpleFileTransfer)   
[CCNx.org](https://www.ccnx.org/)


This is the CCNx Simple File Transfer tutorial (formerly CCNx Tutorial Demo), a very simple tutorial demonstrating
an application using the CCNx Portal API, the CCN Software Stack and the CCN Metis Forwarder.  It includes a set 
of programs, with source code, to serve files and retrieve files. Files are transferred using a basic 'chunked' protocol.

The point of the tutorial is to demonstrate how to use the CCNx Portal API.
With this as an example, you should be able to understand how you could apply the API to your own application.

After building, the demo consists of 2 programs:

* `ccnxSimpleFileTransfer_Server`: Serves files out of a directory.
* `ccnxSimpleFileTransfer_Client`: Lists and retrieves files from the server.

REQUIREMENTS
------------

The CCNx-Tutorial-Demo needs the Distillery CCNx distribution installed on the
system. Please install the [CCNx Distillery](  https://github.com/PARC/CCNx_Distillery) by downloading it from GitHub, [here]( https://github.com/PARC/CCNx_Distillery), and
building it according to the instructions there.


Building and Running
--------------------

To run the tutorial programs you will need a CCN forwarder (metis or athena) running.
We'll use metis for this example, but either would work.


Start by running 'metis_daemon --capacity 0', then the `ccnxSimpleFileTransfer_Server` (to serve files) 
and then the `ccnxSimpleFileTransfer_Client` to access the server.   It is recommended that you run 
the `metis_daemon`, `ccnxSimpleFileTransfer_Server` and `ccnxSimpleFileTransfer_Client` in different windows.

It is also recommended you run metis_daemon with the '--capacity 0' option to disable the cache
on the forwarder. This makes experimenting more predictable, as all Interests will make it
through to the ccnxSimpleFileTransfer_Server. 

Compiling the tutorial:

1. Set the CCNX_HOME environment variable to the location of your Distillery build. In zsh, for example,
it might look like this:
`export CCNX_HOME=/path/to/CCNx_Distillery/usr`
   
2. If you ran 'make all' when you built the CCNx_Distillery distribution, you should already have
   the binaries in your $CCNX_HOME/bin directory.

   If they are not there, you can run 'make ccnxSimpleFileTransfer' from the CCNx_Distillery directory.

3. At this point, the compiled binaries for `ccnxSimpleFileTransfer_Client` and the
`ccnxSimpleFileTransfer_Server` should be built and exist in $CCNX_HOME/bin

4. Start a forwarder. Do ONE of the following:

   4a. Start the CCNx forwarder, `metis_daemon`:
    `$CCNX_HOME/bin/metis_daemon --capacity 0 &`

   4b. Start the CCNx forwarder, `athena`:
    `$CCNX_HOME/bin/athena -s 0 &`

5. Run the `ccnxSimpleFileTransfer_Server`:
  Start the `ccnxSimpleFileTransfer_Server`, giving it a directory path as an argument.
  `$CCNX_HOME/bin/ccnxSimpleFileTransfer_Server /path/to/a/directory/with/files/to/serve`

6.  Run the `ccnxSimpleFileTransfer_Client` to retrieve the list of files
  available from the `ccnxSimpleFileTransfer_Server`:

  `$CCNX_HOME/bin/ccnxSimpleFileTransfer_Client list ` # Will return a list of available files

  Or, use the `ccnxSimpleFileTransfer_Client` to fetch a file from the `ccnxSimpleFileTransfer_Server`:

  `$CCNX_HOME/bin/ccnxSimpleFileTransfer_Client fetch <filename>`   # Will fetch a file using the chunked protocol

NOTE: Do not run the `ccnxSimpleFileTransfer_Client` in the same directory from which you are serving files as it will overwrite the source file and things will break.

## Notes: ##

- The `ccnxSimpleFileTransfer_Client` and `ccnxSimpleFileTransfer_Server` automatically create keystore files in
  their working directory.

- You can experiment with different chunk sizes by changing the value of `ccnxSimpleFileTransferCommon_DefaultChunkSize`, which is defined in `ccnxSimpleFileTransfer_Common.c`.


If you have any problems with the system, please discuss them on the developer
mailing list:  `ccnx@ccnx.org`.  If the problem is not resolved via mailing list
discussion, you can file tickets in the issue tracker.


CONTACT
-------

For any questions please use the CCNx mailing list.  ccnx@ccnx.org


LICENSE
-------

This software is licensed under the PARC Software License. See LICENSE File.

