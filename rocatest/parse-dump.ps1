#work through a file produced from a CA dump in the format from dumpcerts.ps1

 
$foundrowstart = $false
$readingcert = $false
$certend = $false
$serialnum = ""
$cert = ""

get-content d:\scripts\testcertdump.txt | %{

               $line = $_

               if ($readingcert) {

                              if ($line -match "-----END CERTIFICATE-----") {
                                             $readingcert = $false
                                             $certend = $true
                              }


                              $cert += $line += "`r`n"

               } else {
                              #not currently reading the certificate

                              if ($foundrowstart) {
                                             $serialnum = ($line.split(":"))[1].replace(" ","").replace('"','')
                                             $foundrowstart = $false

                              } elseif ($line -match "^Row ") {
                                             $foundrowstart = $true

                              }


                              if ((-not ([string]::isnullorempty($serialnum))) -and $line -match "-----BEGIN CERTIFICATE-----") {
                                             $readingcert = $true
                                             $cert += $line + "`r`n"

                              }


               }

              

               if ($certend) {

                              $cert | out-file .\pem-$serialnum.cer
                              certutil -decode "pem-$serialnum.cer" "$serialnum.cer"
                              del "pem-$serialnum.cer"
                              $cert =""
                              $serialnum = ""
                              $certend = $false

               }

}

