def member($value; $values): any($values[]; . == $value);
def root_section($path): if ($path | length) > 0 then $path[0] else "" end;
def path_has($path; $value): any($path[]; . == $value);
def normalize_key($key): $key | ascii_downcase | gsub("-"; "_");
def parent_type($parent): if ($parent | type) == "object" then ($parent.type // "") else "" end;
def leafish($value): ($value | type) != "object";

def is_placeholder($value):
  ($value | type) == "string" and (
    ($value | startswith("<REDACTED:")) or
    ($value == "00000000-0000-4000-8000-000000000000") or
    ($value == "0000000000000000") or
    ($value | test("^(redacted\\.example|[a-z]+-[0-9]+(?:\\.[a-z0-9-]+)*\\.redacted\\.example|redacted@example\\.com|user-[0-9]+|redacted-process(?:-[0-9]+)?|com\\.example\\.redacted(?:[0-9]+)?|interface-[0-9]+|02:00:00:00:00:[0-9a-fA-F]{2}|192\\.0\\.2\\.[0-9]+(?:/24)?|2001:db8::[0-9a-fA-F]*(?:/32)?)$"))
  );

def is_sensitive_header($key):
  ($key | test("(?i)^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|x-auth-token|x-access-token)$")) or
  ($key | test("(?i)(authorization|credential|password|passwd|secret|token|api[-_]?key|cookie)"));

def header_decision($mode; $container; $key):
  if member(($container | ascii_downcase); ["headers", "extra_headers"]) then
    if ($key | test("(?i)^(authorization|proxy-authorization)$")) then {action:"AUTHORIZATION", category:"AUTHORIZATION"}
    elif ($key | test("(?i)^(cookie|set-cookie)$")) then {action:"COOKIE", category:"COOKIE"}
    elif is_sensitive_header($key) then {action:"SECRET", category:"CREDENTIAL"}
    elif (($mode != "credentials") and ($key | test("(?i)^host$"))) then {action:"ENDPOINT", category:"ENDPOINT"}
    else null end
  else null end;

def is_secret_allowlisted($key): member($key; [
  "public_key", "certificate_public_key_sha256", "client_certificate_public_key_sha256",
  "key_type", "key_direction", "host_key_algorithms", "server_port", "server_ports",
  "listen_port", "port", "relay_server_port"
]);

def is_password_key($key):
  ($key | test("(^|_)(password|passwd|passphrase)(_|$)")) or
  member($key; ["client_key_password", "mca_key_password", "private_key_passphrase"]);

def is_private_key_key($key): member($key; [
  "private_key", "client_key", "mca_key", "origin_ca_key", "account_key"
]);

def is_psk_key($key): member($key; ["pre_shared_key", "static_key", "mesh_psk", "psk"]);

def is_secret_material_path($key): member($key; [
  "private_key_path", "client_key_path", "mca_key_path", "key_path", "static_key_path",
  "secret_path", "credential_path", "mesh_psk_file"
]);

def is_generic_secret_key($key):
  (is_secret_allowlisted($key) | not) and
  ($key | test("(^|_)(secret|credential|token|cookie|api_key|auth_key|access_key_secret|security_token|zone_token|pin)(_|$)"));

def is_url_key($key): ($key == "url") or ($key | endswith("_url"));

def is_endpoint_server($path; $parent):
  ((root_section($path) == "outbounds") and (($path | length) == 2)) or
  ((root_section($path) == "endpoints") and (($path | length) == 2)) or
  ((root_section($path) == "endpoints") and path_has($path; "servers")) or
  ((root_section($path) == "dns") and (($path | length) >= 2) and ($path[1] == "servers")) or
  (root_section($path) == "ntp") or
  (path_has($path; "handshake") or path_has($path; "handshake_for_server_name")) or
  (((root_section($path) == "outbounds") or (root_section($path) == "endpoints")) and (($parent | type) == "object") and ($parent | has("server_port")));

def is_reality_context($path; $parent):
  path_has($path; "reality") or
  ((($parent | type) == "object") and ($parent | has("reality")) and ($parent.reality != null));

def is_auth_username($path; $key; $parent):
  (($key == "username") and member(root_section($path); ["outbounds", "endpoints"])) or
  (($key == "user") and (root_section($path) == "outbounds")) or
  (($key == "username") and path_has($path; "dns01_challenge")) or
  (($key == "device_id") and path_has($path; "token")) or
  (($key == "access_key_id") or ($key == "key_id"));

def is_local_path($path; $key; $parent):
  ($key | test("(_path|_directory|_directory_path)$")) or
  member($key; ["data_directory", "state_directory", "taildrop_directory", "directory", "external_ui", "dhcp_lease_files", "executable_path", "usages_path"]) or
  (($key == "path") and (
    path_has($path; "cache_file") or
    path_has($path; "rule_set") or
    path_has($path; "rule_sets") or
    (root_section($path) == "network_namespaces") or
    ((root_section($path) == "dns") and ((parent_type($parent) == "hosts") or path_has($path; "hosts"))) or
    (parent_type($parent) == "local")
  ));

def is_share_identity($path; $key):
  member($key; [
    "username", "user", "auth_user", "email", "hostname", "local_hostname", "source_hostname",
    "device_id", "device_unique_id", "subdomain", "system_interface_name", "interface_name",
    "bind_interface", "default_interface"
  ]) or
  (($key == "name") and path_has($path; "users"));

def is_wifi_or_mac($key):
  member($key; ["wifi_ssid", "wifi_bssid", "source_mac_address", "include_mac_address", "exclude_mac_address"]);

def is_share_network($path; $key; $parent):
  if parent_type($parent) == "tun" then false
  else
    member($key; [
      "allowed_ips", "advertise_routes", "relay_server_static_endpoints", "peer_address", "peer_address_ipv6",
      "inet4_bind_address", "inet6_bind_address", "interface_address", "network_interface_address",
      "default_interface_address", "route_address", "route_exclude_address", "dns_address", "loopback_address"
    ]) or
    (($key == "address") and member(root_section($path); ["endpoints", "inbounds"])) or
    (($key == "address") and path_has($path; "peers"))
  end;
def is_strict_domain($key): member($key; [
  "domain", "domain_suffix", "domain_keyword", "server_name", "default_server_name", "query_server_name",
  "neighbor_domain", "override_domain", "search_domains", "resolve_domains", "bypass_domain", "match_domain"
]);

def is_strict_domain_regex($key): $key == "domain_regex";

def is_strict_network($key): member($key; [
  "source_ip_cidr", "ip_cidr", "query_client_subnet", "client_subnet", "interface_address",
  "network_interface_address", "default_interface_address", "address", "addresses", "allowed_ips",
  "route_address", "route_exclude_address", "peer_address", "peer_address_ipv6", "dns_address",
  "relay_server_static_endpoints", "stun_servers"
]);

def is_strict_process($key): member($key; ["process_name", "process_path", "process_path_regex"]);
def is_strict_package($key): member($key; ["package_name", "package_name_regex", "include_package", "exclude_package"]);
def is_strict_fingerprint($key): member($key; [
  "public_key", "certificate_public_key_sha256", "client_certificate_public_key_sha256",
  "peer_fingerprint", "fingerprint", "host_key", "reserved"
]);
def is_certificate_content($key): member($key; [
  "certificate", "certificates", "client_certificate", "mca_certificate", "certificate_authority"
]);

def content_decision($value):
  if (($value | type) != "string") or is_placeholder($value) then null
  elif ($value | test("-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")) then {action:"PRIVATE_KEY", category:"PRIVATE_KEY"}
  elif ($value | test("^eyJ[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$")) then {action:"TOKEN", category:"CREDENTIAL"}
  else null end;

def field_decision($mode; $path; $container; $key0; $value; $parent):
  normalize_key($key0) as $key |
  if is_placeholder($value) then null
  elif (header_decision($mode; $container; $key0)) != null then header_decision($mode; $container; $key0)
  elif (content_decision($value)) != null then content_decision($value)
  elif (($key == "uuid") and leafish($value)) then {action:"UUID", category:"CREDENTIAL"}
  elif (($key == "short_id") and leafish($value)) then {action:"SHORT_ID", category:"CREDENTIAL"}
  elif (is_password_key($key) and leafish($value)) then {action:"PASSWORD", category:"CREDENTIAL"}
  elif (is_secret_material_path($key) and leafish($value)) then {action:"PATH", category:"PATH"}
  elif (is_private_key_key($key) and leafish($value)) then {action:"PRIVATE_KEY", category:"PRIVATE_KEY"}
  elif (is_psk_key($key) and leafish($value)) then {action:"PSK", category:"PRIVATE_KEY"}
  elif (($key == "key") and leafish($value) and (path_has($path; "tls") or path_has($path; "ech") or path_has($path; "external_account"))) then {action:"KEY", category:"PRIVATE_KEY"}
  elif (($key == "userkey") and leafish($value)) then {action:"CREDENTIAL", category:"CREDENTIAL"}
  elif (member($key; ["access_key_id", "access_key_secret", "security_token", "api_token", "zone_token", "auth_key", "mac_key", "submission_key"]) and leafish($value)) then {action:"CREDENTIAL", category:"CREDENTIAL"}
  elif (is_generic_secret_key($key) and leafish($value)) then
    if ($key | test("cookie")) then {action:"COOKIE", category:"COOKIE"}
    elif ($key | test("token")) then {action:"TOKEN", category:"CREDENTIAL"}
    else {action:"SECRET", category:"CREDENTIAL"} end
  elif (is_auth_username($path; $key; $parent) and leafish($value)) then {action:"IDENTITY", category:"IDENTITY"}
  elif (is_url_key($key) and leafish($value)) then
    if ($mode == "strict") then {action:"URL_STRICT", category:"URL"}
    elif (($mode == "share") and member($key; ["server_url", "control_url"])) then {action:"URL_ENDPOINT", category:"ENDPOINT"}
    else {action:"URL_SANITIZE", category:"URL"} end
  elif (($value | type) == "string" and ($value | contains("://"))) then {action:"URL_SANITIZE", category:"URL"}
  elif ($mode == "credentials") then null
  elif (($value | type) == "object") then null
  elif (($key == "server") and is_endpoint_server($path; $parent)) then {action:"ENDPOINT", category:"ENDPOINT"}
  elif member($key; ["exit_node", "relay_server_static_endpoints", "stun_servers"]) then {action:"ENDPOINT", category:"ENDPOINT"}
  elif is_share_identity($path; $key) then {action:"IDENTITY", category:"IDENTITY"}
  elif is_local_path($path; $key; $parent) then {action:"PATH", category:"PATH"}
  elif is_wifi_or_mac($key) then
    if ($key | test("bssid|mac")) then {action:"MAC", category:"IDENTITY"} else {action:"WIFI", category:"IDENTITY"} end
  elif (($key == "process_path") or ($key == "process_path_regex")) then {action:"PATH", category:"PATH"}
  elif ($key == "source_ip_cidr") then
    if ($mode == "strict") then {action:"NETWORK", category:"FINGERPRINT"} else {action:"PRIVATE_NETWORK", category:"LOCAL_NETWORK"} end
  elif is_share_network($path; $key; $parent) then {action:"NETWORK", category:"LOCAL_NETWORK"}
  elif (($key == "server_name") or ($key == "default_server_name") or ($key == "query_server_name")) then
    if is_reality_context($path; $parent) then
      if ($mode == "strict") then {action:"DOMAIN", category:"FINGERPRINT"} else null end
    else
      {action:"DOMAIN", category:"ENDPOINT"}
    end
  elif (($key == "domain") and (path_has($path; "certificate_providers") or path_has($path; "certificate_provider") or (root_section($path) == "certificate_providers"))) then {action:"DOMAIN", category:"IDENTITY"}
  elif ($key == "reserved") then {action:"FINGERPRINT", category:"FINGERPRINT"}
  elif (($key == "config") and path_has($path; "ech")) then {action:"FINGERPRINT", category:"FINGERPRINT"}
  elif (($key == "public_key") and path_has($path; "reality")) then {action:"FINGERPRINT", category:"FINGERPRINT"}
  elif (($mode == "strict") and is_strict_domain_regex($key)) then {action:"DOMAIN_REGEX", category:"FINGERPRINT"}
  elif (($mode == "strict") and is_strict_domain($key)) then {action:"DOMAIN", category:"FINGERPRINT"}
  elif (($mode == "strict") and is_strict_network($key)) then {action:"NETWORK", category:"FINGERPRINT"}
  elif (($mode == "strict") and is_strict_process($key)) then {action:"PROCESS", category:"FINGERPRINT"}
  elif (($mode == "strict") and is_strict_package($key)) then {action:"PACKAGE", category:"FINGERPRINT"}
  elif (($mode == "strict") and (($key == "user_id") or ($key == "user"))) then {action:"IDENTITY", category:"IDENTITY"}
  elif (($mode == "strict") and is_strict_fingerprint($key)) then {action:"FINGERPRINT", category:"FINGERPRINT"}
  elif (($mode == "strict") and is_certificate_content($key)) then {action:"CERTIFICATE", category:"FINGERPRINT"}
  elif (($mode == "share") and member($key; ["client_certificate", "mca_certificate"])) then {action:"CERTIFICATE", category:"IDENTITY"}
  elif ($container == "predefined") then
    if ($mode == "strict") then {action:"NETWORK", category:"FINGERPRINT"} else {action:"PRIVATE_NETWORK", category:"LOCAL_NETWORK"} end
  elif ($container == "interface_address") then {action:"NETWORK", category:"LOCAL_NETWORK"}
  else null end;

def key_decision($mode; $container):
  if $mode == "credentials" then null
  elif (($mode == "strict") and ($container == "handshake_for_server_name")) then {action:"KEY_SNI", category:"FINGERPRINT"}
  elif (($mode == "strict") and ($container == "predefined")) then {action:"KEY_HOST", category:"FINGERPRINT"}
  elif $container == "interface_address" then {action:"KEY_INTERFACE", category:"IDENTITY"}
  else null end;

def scan($mode; $path; $container):
  . as $node |
  if ($node | type) == "object" then
    [to_entries[] | . as $entry |
      (key_decision($mode; $container)) as $key_action |
      (field_decision($mode; $path; $container; $entry.key; $entry.value; $node)) as $value_action |
      (if $key_action == null or is_placeholder($entry.key) then [] else [{
        kind:"key", path:($path + [$entry.key]), action:$key_action.action, category:$key_action.category
      }] end) +
      (if $value_action == null then
        ($entry.value | scan($mode; $path + [$entry.key]; $entry.key))
      else [{
        kind:"value", path:($path + [$entry.key]), action:$value_action.action, category:$value_action.category
      }] end)
    ] | add // []
  elif ($node | type) == "array" then
    [to_entries[] | . as $entry | $entry.value | scan($mode; $path + [$entry.key]; $container)] | add // []
  else [] end;

scan($mode; []; "")
