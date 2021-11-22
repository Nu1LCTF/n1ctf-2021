<?php
if(isset($_GET['str'])) $str = $_GET['str'];
else $str = "world";
$sql_query = "SELECT '".$str."' as hello;";
echo $sql_query."<br>";
$args = escapeshellarg($sql_query);
system("echo ".$args." | osqueryi --json" );
?>