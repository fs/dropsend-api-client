<?php

session_name('partyvan');
session_save_path('/tmp/');
session_start();

require_once("client.inc");

//print_r($_SESSION);exit;

$client = new Dropsend_OAuth_Client();

$action = isset($_GET['action']) ? $_GET['action'] : '';
switch ($action) {
case '':
	if ($client->authorized()) {
		die(file_get_contents('static_client.html'));
	} else {
		echo '<div style="text-align:center;padding:200px;"><a href="?action=authorize"><img src="http://myaccount.dropsend.com/images/dropsendlogo.png" style="border: 1px solid #000; padding: 10px;-moz-border-radius-topleft:5px;-moz-border-radius-topright:5px;" /></a><br/><div style="width: 254px;padding:10px;background: #eee; align:center;-moz-border-radius-bottomleft:5px;-moz-border-radius-bottomright:5px; display: inline-block;border:1px solid #000;border-top:0;"><a href="?action=authorize" style="font-family: verdana, sans-serif; font-size:14px;color:blue;font-weight:700">Dropsend Connect</a></div></div>';
	}
	break;
case 'authorize':
	$client->oauth_authorize();
	break;
case 'unauthorize':
	$client->unauthorize();
	header('Location: /');
	break;
default:
	$result = $client->$action($_REQUEST);
	break;
case 'callback':
	$client->oauth_handle_callback();
	header('Location: /');
	break;
}

if (isset($result)) {
	if (strpos($result, "\n")) {
		echo $result;
	} else {
		if (!in_array($result{0}, array('[', '{'))) {
			parse_str($result, $r);
		} else {
			$r = $result;
		}
		echo '<pre>';
		print_r($r);
	}
}

?>
