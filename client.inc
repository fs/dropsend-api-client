<?php

DEFINE('DS_OAUTH_SIG_METHOD_PLAINTEXT', 'plaintext');
DEFINE('DS_OAUTH_SIG_METHOD_HMAC', 'hmac_sha1');
DEFINE('DS_OAUTH_SIG_METHOD_RSA', 'rsa');

class curl {
	var $c;
	var $url;
	var $file_path;

	function curl ($url) {
		$this->url = $url;
	}

	function post ($data) {
		curl_setopt($this->c,CURLOPT_POST,1);
		curl_setopt($this->c,CURLOPT_POSTFIELDS,$data);
	}

	function upload_file ($path) {
		$this->file_path = $path;
	}

	function go ($return = 0) {
		$file_headers = '/tmp/header' . time();
		$file_content = '/tmp/httpresponse' . time();
		if (file_exists($file_headers)) {
			unlink($file_headers);
			touch($file_headers);
		}
		if (file_exists($file_content)) {
			unlink($file_content);
			touch($file_content);
		}
		$params = array();
		//$params[] = '-u alexeymamaev:\'password\'';
		$params[] = '--insecure';
		$params[] = '--header "Accept:plaintext" ';
		if ($_FILES) {
			foreach($_FILES as $fname => $file) {
				$f = '/tmp/' . $file['name'];
				move_uploaded_file($file['tmp_name'], $f);
				$params[] = '-F ' . $fname . '=@' . $f;
			}
		}
		$params[] = '--dump-header ' . $file_headers;
		$params[] = '--url "' . $this->url . '"';
		//die('curl ' . join(' ', $params));
		exec('curl ' . join(' ', $params) . ' > ' . $file_content);

		$output = file_get_contents($file_content);

		$headers = split("\n", file_get_contents($file_headers));
		foreach ($headers as $h) {
			if (preg_match('/([^:]+):(.*)/', $h, $m)) {
				$header = $m[1];
				//$value = $m[2];
				if ($header === 'Dropsend-API-Download-File') {
					// resend original headers before output data
					foreach ($headers as $h) {
						header($h);
					}
					echo $output;
					exit;
				}
			}
		}

		if ($return) {
			return $output;
		} else {
			echo $output;
		}
	}
}

require_once("oauth4/OAuth.php");

class Dropsend_OAuth_Client {
	var $key = 'RCr8fTDErh5'; //rHZzgtALWbD
	var $secret = 'qZHEzLK3bDFQ2gtLX6kAN'; // YcLkWxeEwGgkdfSgfNrry
	var $domain = 'myaccount.dropsend-stage.flatsourcing.com';
	var $protocol = 'http';
	var $consumer = null;
	var $signature_method = null;

	function Dropsend_OAuth_Client($signature_method_name = DS_OAUTH_SIG_METHOD_HMAC) {
		$this->consumer = new OAuthConsumer($this->key, $this->secret, null);
		switch ($signature_method_name) {
		case DS_OAUTH_SIG_METHOD_PLAINTEXT:
			$this->signature_method = new OAuthSignatureMethod_PLAINTEXT();
			break;
		case DS_OAUTH_SIG_METHOD_RSA:
			$this->signature_method = new TestOAuthSignatureMethod_RSA_SHA1();
			break;
		case DS_OAUTH_SIG_METHOD_HMAC:
		default:
			$this->signature_method = new OAuthSignatureMethod_HMAC_SHA1();
			break;
		}
		//$this->domain = $_SERVER['HTTP_HOST'] == '3rdparty.van' ? 'myaccount-stage.dropsend.com' : 'dummy.groupaccounts.dropsend.tsweb.toa';
		$this->protocol = $_SERVER['HTTP_HOST'] == '3rdparty.van' ? 'https' : 'http';
	}

	function oauth_fetch_request_token() {
		$endpoint = $this->protocol . '://' . $this->domain . '/oauth/get_request_token';

		$parsed = parse_url($endpoint);
		$query = isset($parsed['query']) ? $parsed['query'] : '';
		$params = array();
		parse_str($query, $params);

		$req_req = oauthrequest_from_consumer_and_token($this->consumer, NULL, "GET", $endpoint, $params);
		$req_req->sign_request($this->signature_method, $this->consumer, NULL);
		$url = $req_req->to_url();
		$query_request_token = new curl($url);
		$result = array();
		$service_response = $query_request_token->go(true);
		parse_str($service_response, $result);

		if (empty($result['oauth_token']) || empty($result['oauth_token_secret'])) {
			echo 'Can not fetch request token. Server\'s response:' . "\n";
			print_r($service_response);
			exit;
		}

		$request_key = $result['oauth_token'];
		$request_secret = $result['oauth_token_secret'];
		$_SESSION['request_key'] = $request_key;
		$_SESSION['request_secret'] = $request_secret;
		return new OAuthToken($request_key, $request_secret);
	}

	function oauth_authorize() {
		$domain = $this->domain;
		$endpoint = $this->protocol . '://' . $domain . '/oauth/authorize_request_token';
		$rt = $this->oauth_fetch_request_token();
		$url = $endpoint . '?oauth_callback=' . urlencode(($_SERVER['HTTPS'] ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'] . '/?action=callback') . '&oauth_token=' . urlencode($rt->key);
		header('Location: ' . $url);
		exit;
	}

	function authorized() {
		return isset($_SESSION['access_key']) && isset($_SESSION['access_secret']);
	}

	function unauthorize() {
		unset($_SESSION['access_key']);
		unset($_SESSION['access_secret']);
	}

	function oauth_handle_callback() {
		$oauth_token = $_SESSION['request_key'];
		$oauth_secret = $_SESSION['request_secret'];
		$request_token = new OAuthToken($oauth_token, $oauth_secret);
		$this->oauth_fetch_access_token($request_token);
	}

	function oauth_fetch_access_token() {
		$endpoint = $this->protocol . '://' . $this->domain . '/oauth/get_access_token';

		$request_token = new OAuthToken($_SESSION['request_key'], $_SESSION['request_secret']);

		$acc_req = oauthrequest_from_consumer_and_token($this->consumer, $request_token, "GET", $endpoint, array());
		$acc_req->sign_request($this->signature_method, $this->consumer, $request_token);
		$url = $acc_req->to_url();
		$query_access_token = new curl($url);

		$access = array();
		parse_str($query_access_token->go(true), $access);

		$access_key = $access['oauth_token'];
		$access_secret = $access['oauth_token_secret'];

		$_SESSION['access_key'] = $access_key;
		$_SESSION['access_secret'] = $access_secret;
	}

	function __call($name, $params) {
		$access_token = new OAuthToken($_SESSION['access_key'], $_SESSION['access_secret']);

		$endpoint = $this->protocol . '://' . $this->domain . '/oauth/call_api/' . $name . (isset($_GET['format']) ? '.' . $_GET['format'] : '');
		$is_upload = isset($_FILES) && isset($_FILES['file']);
		if ($is_upload) {
			$params[0]['file_name'] = $_FILES['file']['name'];
		}

		$echo_req = oauthrequest_from_consumer_and_token($this->consumer, $access_token, $is_upload ? "POST" : "GET", $endpoint, $params[0]);
		$echo_req->sign_request($this->signature_method, $this->consumer, $access_token);
		$query_api = new curl($echo_req->to_url());
		if ($is_upload) {
			$query_api->upload_file($_FILES['file']['tmp_name']);
		}
		$return = $query_api->go(true);
		return $return;
	}

}

if (function_exists('overload')) {
	overload('Dropsend_OAuth_Client');
}

?>
