<?php
// include('db.php');
// include('checkfunctions.php');
$message=array();
$salt='NWjrZFx6UeXc5uKZ7tLfanzYhSfCsvreEzp8tywz';
if(!isset($_POST['password'])||$_POST['password']!=$salt){
	exit;
}
$prods=array(
	"usmtp587",
	"unlimited",
	"domainsmtp",
	"ipsmtp",
	"587smtp",
	"office365smtp",
	"usmtpssl",
	"sslsmtp",
	"phpmailer",
	"leads"
	);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
$emails=array('yahoo'=>"smtp_checker@yahoo.com");
//echo $_POST['type'];
file_put_contents('adsada.txt',$_POST['prodinfo']);
if(isset($_POST['type'],$_POST['prodinfo'])){
		//echo 'Loged';
		if(in_array($_POST['type'], $prods)){
			$prod=json_decode(base64_decode($_POST['prodinfo']),true);
 
			if($prod!=false){
				if($prod['bought']=='1'){
					$message=array(0,'This product it\'s already sold.');
				}else{
 
					switch ($_POST['type']) {
						case 'leads':
						$type=strtolower($prod['type']);
						if(strpos($type, 'cpanel')!==false || strpos($type, 'bpcpanel')!==false)
						{
							//echo 'cpanel';
							//$sp=explode(',',$prod['addinfo']);
							$command = escapeshellcmd('python3 check.py cpCheck'.' '.$prod['ip'].' '.$prod['user'].' '.$prod['pass']);
							$output = shell_exec($command);

							// echo $output
							if($output == 1 || $output == "1")
								$message=array(1,'ok');
							else
								$message=array(0,'bad');
						}elseif (strpos($type, 'shell')!==false) {
							//$row=$prod['addinfo'];
							//$pass=($prod['login']!=''?$prod['login']:"");
						       //echo $host;
							//echo 'shell';
							$command = escapeshellcmd('python3 check.py shellCheck'.' '.$prod['ip'].' '.$prod['pass']);
							$output = shell_exec($command);

							if($output == 1 || $output == "1")
								$message=array(1,'ok');
							else
								$message=array(0,'bad');		
						}
						break;
						case 'phpmailer':
						if(strpos($prod['type'], 'mailer')!==false)
						{
							//echo 'mailer';
							//$sp=$prod['addinfo'];
							$command = escapeshellcmd('python3 check.py mailerCheck'.' '.$prod['ip']);
							$output = shell_exec($command);

							if($output == 1 || $output == "1")
								$message=array(1,'ok');
							else
								$message=array(0,'bad');
 
						} else {
							$message=array(0,"Unsupported product! ");
						}
						break;
						case "unlimited":
							$command = escapeshellcmd('python3 check.py checkUnlimited'.' '.$prod['ip'].' '.$prod['user'].' '.$prod['pass']);
							$output = shell_exec($command);
                                                        if($output == 1 || $output == "1")
                                                                $message=array(1,'ok');
                                                        else
                                                                $message=array(0,'Error!');
						break;
						default:
						if(strpos($_POST['type'],'smtp')!==false){
							if(isset($_POST['email'])&&filter_var($_POST['email'],FILTER_VALIDATE_EMAIL)){
								$host=$prod['ip'];
								$user=$prod['user'];
								$pass=$prod['pass'];
								$send=$_POST['email'];
								$command = escapeshellcmd('python3 check.py sendEmail'.' '.$host.' '.$user.' '.$pass.' '.$send.' '.$prod['id']);
								// $command = escapeshellcmd('python3 check.py sendEmail 203.198.23.150 noc2@netvigator.com 123456 nursultansaudirbaev157@gmail.com 123');
								$output = shell_exec($command);
								// $output = 1;
								// $rez= sendEmail($host,$user,$pass,$send,"Check from smtp #".(int)$prod['id'],$user);
								if($output == 1 || $output == "1")
									$message=array(1,'ok');
								else
									$message=array(0,"Error! ");								
							}else
								$message=array(0,"Invalid Email!");
						}else
							$message=array(0,"Unsupported product! ");

					}
				}
			}else
			$message=array(0,'Product dosen\'t exist!');
		}else
		$message=array(0,'Unknow product');
		// $message = array(0, $_POST['type']);
 
}
exits:
 
 
echo json_encode($message);
?>
 