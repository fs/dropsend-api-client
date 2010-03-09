<?php
require_once("common.inc.php");

  $req = oauthrequest_from_request();
  $token = $test_server->fetch_access_token($req);
  print $token->__toString();

?>
