# rocacheck-posh
Powershell ROCA vulnerability scanner

This project is a powershell port of the csharp implementation of crocs-muni ROCA vulnerability detection tool (https://github.com/crocs-muni/roca/tree/master/csharp).  Likewise, it has a dependency on the BouncyCastle crypto library.  The precompiled dll's from Bouncy Castle fail to load into powershell due to missing dependencies, so you will need to download the source and compile your own dll for use with this script.

Some basic features were added to this script for remote system checks, and handling file input.  For the remote system connections, the remote machine name will need to be a valid name on the cert.  
