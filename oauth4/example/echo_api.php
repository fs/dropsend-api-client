<?php
require_once("common.inc.php");

  $req = oauthrequest_from_request();
  list($consumer, $token) = $test_server->verify_request($req);

  // lsit back the non-OAuth params
  $total = array();
  foreach($req->get_parameters() as $k => $v) {
    if (substr($k, 0, 5) == "oauth") continue;
    $total[] = urlencode($k) . "=" . urlencode($v);
  }
  print implode("&", $total);

?>
