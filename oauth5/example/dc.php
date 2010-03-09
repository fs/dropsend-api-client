<?php

DEFINE('DS_OAUTH_SIG_METHOD_PLAINTEXT', 'plaintext');
DEFINE('DS_OAUTH_SIG_METHOD_HMAC', 'hmac_sha1');

class curl{
	var $c;
	var $url;
	
	function curl($url){
		$this->c = curl_init();
		//curl_setopt($this->c,CURLOPT_PROXY,'192.168.x.x:8000'); // это прокси (если надо)
		//curl_setopt($this->c,CURLOPT_PROXYUSERPWD,'user:pass'); 
		//curl_setopt($this->c,CURLOPT_PROXYUSERPWD,'user2:pass2');
		curl_setopt($this->c,CURLOPT_COOKIE,'cookie here'); // представляемся гуглу
		curl_setopt($this->c,CURLOPT_URL,$url);
		$this->url = $url;
	}
	
	function post($data){
		curl_setopt($this->c,CURLOPT_POST,1);
		curl_setopt($this->c,CURLOPT_POSTFIELDS,$data);
	}
	
	function go($return=0){
		if($return){
			curl_setopt($this->c,CURLOPT_RETURNTRANSFER,$return);
			$response = curl_exec($this->c);
			curl_close($this->c);
			return $response;
		}else{
			curl_exec($this->c);
			curl_close($this->c);
		}
	}
}

require_once("common.inc.php");

class Dropsend_OAuth_Client {
	var $key = 'key';
	var $secret = 'secret';
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
	}
	
	function fetch_request_token() {
		$endpoint = 'http://myaccount.dropsend.tsweb.toa/oauth/get_request_token';
		
		$parsed = parse_url($endpoint);
		$params = array();
		parse_str($parsed['query'], $params);
		
		$req_req = oauthrequest_from_consumer_and_token($this->consumer, NULL, "GET", $endpoint, $params);
		$req_req->sign_request($this->signature_method, $this->consumer, NULL);
		$url = $req_req->to_url();
		
		$query_request_token = new curl($url);
		$result = array();
		parse_str($query_request_token->go(true), $result);
		
		$request_key = $result['oauth_token'];
		$request_secret = $result['oauth_token_secret'];
		return new OAuthConsumer($request_key, $request_secret);
	}
	
	function fetch_access_token($request_token = null) {
		if (is_null($request_token)) {
			$request_token = $this->fetch_request_token();
		}
		
		$endpoint = 'http://myaccount.dropsend/oauth/get_access_token';
		
		$acc_req = oauthrequest_from_consumer_and_token($this->consumer, $request_token, "GET", $endpoint, array());
		$acc_req->sign_request($this->signature_method, $this->consumer, $request_token);
		$url = $acc_req->to_url();
		$query_access_token = new curl($url);
		
		$access = array();
		parse_str($query_access_token->go(true), $access);
		
		$access_key = $access['oauth_token'];
		$access_secret = $access['oauth_token_secret'];
		
		return new OAuthConsumer($access_key, $access_secret, 1);
	}
	
	function make_api_call($access_token = null) {
		
		if (is_null($access_token)) {
			$access_token = $this->fetch_access_token();
		}
		
		$endpoint = 'http://myaccount.dropsend.tsweb.toa/oauth/call_api';
		
		$echo_req = OAuthRequest::from_consumer_and_token($this->consumer, $access_token, "GET", $endpoint, array("method"=> "foo%20bar", "bar" => "baz"));
		$echo_req->sign_request($this->signature_method, $this->consumer, $access_token);
		
		$query_api = new curl($echo_req->to_url());
		$query_api->go();
	}

}

echo '<h2>Test for HMAC client</h2>';
$client_hmac = new test_client();
$client_hmac->make_api_call();

/*
echo '<h2>Test for RSA client</h2>';
$client_rsa = new test_client();
$client_rsa->make_api_call();

echo '<h2>Test for PLAINTEXT client</h2>';
$client_plaintext = new test_client();
$client_plaintext->make_api_call();
*/

?>
