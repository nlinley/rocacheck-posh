#this example code will help you dump out all certificates from a CA matching a certain template OID value, that are still valid based on date and revocation status

$datefilter = (get-date).tostring("MM/dd/yyyy")

certutil -config "myca.contoso.com\Intermediate CA1" -view -out "serialnumber,binary certificate" -restrict "certificatetemplate=1.3.6.1.4.1.311.21.8.x.x.x.x,Disposition=20,NotAfter>=$datefilter"  >> .\testcertdump.txt
