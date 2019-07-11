# Roca tester port by Nathan Linley
#   based on csharp implementation https://github.com/crocs-muni/roca/tree/master/csharp
#
#
#  3 modes of opeation
#    1) by pipeline where input is from get-childitem
#    2) single filename provided
#    3) pulling an ssl cert from a remote machine and testing it

[cmdletbinding()]

param (
[Parameter(Position=0, Mandatory=$true,HelpMessage="path to a working copy of BouncyCastle dll")]
          [ValidateScript({if ((test-path $_ -pathtype leaf) -and ($_ -match "BouncyCastle.*dll$")) {$true} else {throw "BouncyCastle dll required"}  })]
          [string]$BouncyCastlePath,

[Parameter(Position=1,Mandatory=$true,ParameterSetName='RemoteHost',HelpMessage="Remote machine name")]$Computername,
[Parameter(Position=2,Mandatory=$true,ParameterSetName='RemoteHost',HelpMessage="Remote SSL port")]$port,

[Parameter(Position=1,Mandatory=$true,ParameterSetName='SingleFile',HelpMessage="Path for a single file")]
          [ValidateScript({test-path $_ -pathtype leaf})][string]$filename,

[Parameter(position=1,valuefrompipeline=$true,mandatory=$true,parametersetname='GCIinput',HelpMessage="List of files from get-childitem via pipeline")] 
          [System.IO.FileSystemInfo]$files

)


Begin {
     function isVulnerable {
          param (
               [Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters]$rsakey
          )

          if ($rsaKey -eq $null) {
               return $false

          }

          for ($i = 0; $i -lt $script:primes.Length; $i++)

          {

               if ([Org.BouncyCastle.Math.BigInteger]::One.ShiftLeft($rsaKey.Modulus.Remainder($script:primes[$i]).IntValue).And($script:markers[$i]).Equals([Org.BouncyCastle.Math.BigInteger]::Zero))

               {

                    return $false;
               }

          }

          return $true;

     }


     try {
          #load the bouncy castle DLL
          add-type -path $BouncyCastlePath -ea stop

     } catch {
          throw $_

     }

     [Org.BouncyCastle.Math.BigInteger[]]$script:markers = (
          [Org.BouncyCastle.Math.BigInteger]"6",
          [Org.BouncyCastle.Math.BigInteger]"30",
          [Org.BouncyCastle.Math.BigInteger]"126",
          [Org.BouncyCastle.Math.BigInteger]"1026",
          [Org.BouncyCastle.Math.BigInteger]"5658",
          [Org.BouncyCastle.Math.BigInteger]"107286",
          [Org.BouncyCastle.Math.BigInteger]"199410",
          [Org.BouncyCastle.Math.BigInteger]"8388606",
          [Org.BouncyCastle.Math.BigInteger]"536870910",
          [Org.BouncyCastle.Math.BigInteger]"2147483646",
          [Org.BouncyCastle.Math.BigInteger]"67109890",
          [Org.BouncyCastle.Math.BigInteger]"2199023255550",
          [Org.BouncyCastle.Math.BigInteger]"8796093022206",
          [Org.BouncyCastle.Math.BigInteger]"140737488355326",
          [Org.BouncyCastle.Math.BigInteger]"5310023542746834",
          [Org.BouncyCastle.Math.BigInteger]"576460752303423486",
          [Org.BouncyCastle.Math.BigInteger]"1455791217086302986",
          [Org.BouncyCastle.Math.BigInteger]"147573952589676412926",
          [Org.BouncyCastle.Math.BigInteger]"20052041432995567486",
          [Org.BouncyCastle.Math.BigInteger]"6041388139249378920330",
          [Org.BouncyCastle.Math.BigInteger]"207530445072488465666",
          [Org.BouncyCastle.Math.BigInteger]"9671406556917033397649406",
          [Org.BouncyCastle.Math.BigInteger]"618970019642690137449562110",
          [Org.BouncyCastle.Math.BigInteger]"79228162521181866724264247298",
          [Org.BouncyCastle.Math.BigInteger]"2535301200456458802993406410750",
          [Org.BouncyCastle.Math.BigInteger]"1760368345969468176824550810518",
          [Org.BouncyCastle.Math.BigInteger]"50079290986288516948354744811034",
          [Org.BouncyCastle.Math.BigInteger]"473022961816146413042658758988474",
          [Org.BouncyCastle.Math.BigInteger]"10384593717069655257060992658440190",
          [Org.BouncyCastle.Math.BigInteger]"144390480366845522447407333004847678774",
          [Org.BouncyCastle.Math.BigInteger]"2722258935367507707706996859454145691646",
          [Org.BouncyCastle.Math.BigInteger]"174224571863520493293247799005065324265470",
          [Org.BouncyCastle.Math.BigInteger]"696898287454081973172991196020261297061886",
          [Org.BouncyCastle.Math.BigInteger]"713623846352979940529142984724747568191373310",
          [Org.BouncyCastle.Math.BigInteger]"1800793591454480341970779146165214289059119882",
          [Org.BouncyCastle.Math.BigInteger]"126304807362733370595828809000324029340048915994",
          [Org.BouncyCastle.Math.BigInteger]"11692013098647223345629478661730264157247460343806",
          [Org.BouncyCastle.Math.BigInteger]"187072209578355573530071658587684226515959365500926"

     )



     $script:prims = ( 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167 )

     $script:primes = [Org.BouncyCastle.Math.BigInteger[]]@()
     for ($i = 0; $i -lt $script:prims.length; $i++) {
          $script:primes += [Org.BouncyCastle.Math.BigInteger]::valueof($script:prims[$i])

     }

}

 

process {

     $certs = @()

     if ($psCmdlet.ParameterSetName -eq 'GCIinput' ) {
          $certs = $files
          $extractneeded = $true

     } else {
          if ($psCmdlet.ParameterSetName -eq 'SingleFile') {
               $certs += gci $filename
               $extractneeded = $true
          } else {

               #remote network connection
               try {
                    $conn = new-object system.net.sockets.tcpclient($computername,$port)
                    $stream = new-object system.net.security.sslstream($conn.getstream())
                    $stream.authenticateasclient($computername)
                    $cert = $stream.get_remotecertificate()
                    $cert2 = New-Object system.security.cryptography.x509certificates.x509certificate2($cert)      
                    $certs += $cert2

               } catch {

                    throw $_

               }
          }
     }

    

     foreach ($certificate in $certs) {

          $parser = new-object org.bouncycastle.x509.x509certificateparser
          if ($extractneeded) {
               $tempcert =  New-Object system.security.cryptography.x509certificates.x509certificate(($certificate.fullname))      
               $x509 = $parser.ReadCertificate(($tempcert.getrawcertdata()))

          } else {
               $x509 = $parser.ReadCertificate(($certificate.getrawcertdata()))

          }

          $rsaparam = [Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters]$x509.GetPublicKey()
          $isvuln = isVulnerable -rsakey $rsaparam

          $x509 | select @{name='serial';expr = {$_.serialnumber.tostring(16)}}, subjectdn, isvalidnow, notbefore, notafter, @{name='isVulnerable';expr={$isvuln}}

     }

}

 
