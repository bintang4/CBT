<?php
 $blue = "\033[0;34m";
 $yel = "\033[0;33m";
 $white = "\033[1;37m";
echo $yel."[{$blue}+{$yel}]$green Tools CBT Arbitary File Upload {$yel}[{$blue}+{$yel}]
    $white  Author : root@star | Sunda Cyber Army\n\n";
echo "1). CBT Beesmart Mass\n";
echo "2). IndoCBT Mass\n";
echo "00). Exit\n";
echo "====> ";
$pilih = trim(fgets(STDIN));
if(empty($pilih)) exit("Please Enry The Submit !!");
if($pilih == "1"){
 echo "List => ";
 $lst = trim(fgets(STDIN));
 system("php cbt.php $lst");
}elseif($pilih == "2"){
 echo "List => ";
 $lst = trim(fgets(STDIN));
 system("php indocbt.php $lst");
}elseif($pilih == "00"){
 exit("\n");
}
   
?>