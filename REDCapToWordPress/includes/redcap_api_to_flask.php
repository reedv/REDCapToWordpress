<?php

/**
 * Each of these functions make POST and GET RESTful requests to the middleman server.
 * If you need to add more functions, add an endpoint to the middleman server and then query that endpoint with the new function.
 * I'm sorry this isn't easier :( . I'll try to automate this process.
 */

 /**
 * Get configuration from WordPress options with fallback to config.ini
 * 
 * @param string $key The configuration key to retrieve
 * @return string The configuration value
 */
function get_middleware_config($key) {
    // Try to get setting from WordPress options if available
    if (function_exists('get_option')) {
        $options = get_option('redcap_portal_settings');
        if (isset($options[$key]) && !empty($options[$key])) {
            return $options[$key];
        }
    }
    
    // Fall back to config.ini
    $configs = parse_ini_file(dirname(__FILE__, $levels=2) . "/config.ini");

    return isset($configs[$key]) ? $configs[$key] : '';
}

/**
 * Verify a participant against REDCap records via middleware
 *
 * @param string $email The participant's email address
 * @param string $first_name The participant's first name
 * @param string $last_name The participant's last name
 * @return array Response with verification status and record_id if verified
 */
function verify_participant($email, $first_name, $last_name) {
    $middleware_url = get_middleware_config('middleware_url');
    $middleware_api_key = get_middleware_config('middleware_api_key');
    
    $data = array(
        'email' => $email,
        'first_name' => $first_name,
        'last_name' => $last_name
    );
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $middleware_url . '/verify_participant');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_VERBOSE, 0);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_AUTOREFERER, true);
    curl_setopt($ch, CURLOPT_MAXREDIRS, 10);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
    curl_setopt($ch, CURLOPT_FRESH_CONNECT, 1);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json'));
    curl_setopt($ch, CURLOPT_HTTPHEADER, array(
        'Content-Type: application/json',
        'X-API-KEY: ' . $middleware_api_key,
        'X-Original-Client-IP: ' . $_SERVER['REMOTE_ADDR'],
        'X-Original-User-Agent: ' . $_SERVER['HTTP_USER_AGENT']
    ));
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    
    $output = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    $response = json_decode($output, true);
    
    if ($http_code != 200 || !$response) {
        return array(
            'verified' => false,
            'message' => 'Failed to verify participant information. Please try again.',
            'error' => $http_code
        );
    }
    
    return $response;
}

function insert_data_redcap($email, $record_id){
	global $wpdb;
	$wpdb -> insert(
	'wp_redcap',
	array(
	'email' => $email,
	'record_id' => $record_id,));
}

?>
