<?php
/*
Plugin Name: Google reCAPTCHA Login
Description: Adds Google reCAPTCHA to the WordPress admin login page and provides a settings dashboard for API keys.
Version: 1.0
Author: Sharafat Siam
*/

if (!defined('ABSPATH')) {
    exit; 
}

class GRecaptchaLogin {
    private $option_name = 'grecaptcha_settings';
    private $site_key;
    private $secret_key;
    private $version = 'v2'; 

    public function __construct() {

        $options = get_option($this->option_name);
        $this->site_key   = isset($options['site_key']) ? $options['site_key'] : '';
        $this->secret_key = isset($options['secret_key']) ? $options['secret_key'] : '';
        $this->version    = isset($options['version']) ? $options['version'] : 'v2';

        // Hooks.
        add_action('login_form', [$this, 'render_captcha']);
        add_filter('authenticate', [$this, 'verify_captcha'], 30, 3);
        add_action('admin_menu', [$this, 'add_settings_page']);
        add_action('admin_init', [$this, 'register_settings']);
    }

    public function render_captcha() {
        if (empty($this->site_key)) {
            return; 
        }
        if ($this->version === 'v3') {
            // v3 invisible reCAPTCHA.
            echo '<script src="https://www.google.com/recaptcha/api.js?render=' . esc_attr($this->site_key) . '" async defer></script>';
            echo '<script>grecaptcha.ready(function(){ grecaptcha.execute("' . esc_attr($this->site_key) . '", {action: "login"}).then(function(token){ var recaptchaResponse = document.createElement("input"); recaptchaResponse.setAttribute("type","hidden"); recaptchaResponse.setAttribute("name","g-recaptcha-response"); recaptchaResponse.setAttribute("value", token); document.querySelector("form#loginform").appendChild(recaptchaResponse); }); });</script>';
        } else {
            // v2 checkbox.
            echo '<div class="g-recaptcha" data-sitekey="' . esc_attr($this->site_key) . '"></div>';
            echo '<script src="https://www.google.com/recaptcha/api.js" async defer></script>';
        }
    }

    // Verify the response after login submission.
    public function verify_captcha($user, $username, $password) {
        // Skip verification if site key not set.
        if (empty($this->site_key) || empty($this->secret_key)) {
            return $user;
        }
        // If a previous auth error occurred, bail early.
        if (is_wp_error($user)) {
            return $user;
        }
        $response = isset($_POST['g-recaptcha-response']) ? sanitize_text_field($_POST['g-recaptcha-response']) : '';
        if (empty($response)) {
            return new WP_Error('recaptcha_error', '<strong>ERROR</strong>: Please complete the reCAPTCHA.');
        }
        $remote_ip = $_SERVER['REMOTE_ADDR'];
        $verify_url = 'https://www.google.com/recaptcha/api/siteverify';
        $args = [
            'body' => [
                'secret'   => $this->secret_key,
                'response' => $response,
                'remoteip' => $remote_ip,
            ],
            'timeout' => 10,
        ];
        $verify_response = wp_remote_post($verify_url, $args);
        if (is_wp_error($verify_response)) {
            return new WP_Error('recaptcha_error', '<strong>ERROR</strong>: reCAPTCHA verification failed.');
        }
        $body = wp_remote_retrieve_body($verify_response);
        $result = json_decode($body, true);
        if (empty($result['success'])) {
            return new WP_Error('recaptcha_error', '<strong>ERROR</strong>: reCAPTCHA validation failed.');
        }
        return $user;
    }

    // Add a settings page under Settings menu.
    public function add_settings_page() {
        add_options_page(
            'Google reCAPTCHA Settings',
            'reCAPTCHA Login',
            'manage_options',
            'grecaptcha-login',
            [$this, 'render_settings_page']
        );
    }

    // Register settings fields.
    public function register_settings() {
        register_setting($this->option_name, $this->option_name, [$this, 'sanitize_options']);
        add_settings_section('grecaptcha_main', 'reCAPTCHA Configuration', null, $this->option_name);
        add_settings_field(
            'site_key',
            'Site Key',
            [$this, 'site_key_field'],
            $this->option_name,
            'grecaptcha_main'
        );
        add_settings_field(
            'secret_key',
            'Secret Key',
            [$this, 'secret_key_field'],
            $this->option_name,
            'grecaptcha_main'
        );
        add_settings_field(
            'version',
            'reCAPTCHA Version',
            [$this, 'version_field'],
            $this->option_name,
            'grecaptcha_main'
        );
    }

    public function sanitize_options($input) {

        $new = [];

        $fields = ['site_key', 'secret_key'];

        foreach ($fields as $field) {
            $new[$field] = isset($input[$field])
                ? sanitize_text_field($input[$field])
                : '';
        }

        $new['version'] = (isset($input['version']) && in_array($input['version'], ['v2', 'v3'], true))
            ? $input['version']
            : 'v2';

        return $new;
    }

    public function site_key_field() {
        printf(
            '<input type="text" name="%s[site_key]" value="%s" class="regular-text" />',
            esc_attr($this->option_name),
            esc_attr($this->site_key)
        );
    }

    public function secret_key_field() {
        printf(
            '<input type="text" name="%s[secret_key]" value="%s" class="regular-text" />',
            esc_attr($this->option_name),
            esc_attr($this->secret_key)
        );
    }

    public function version_field() {
        $selected_v2 = $this->version === 'v2' ? 'selected' : '';
        $selected_v3 = $this->version === 'v3' ? 'selected' : '';
        printf(
            '<select name="%s[version]">
                <option value="v2" %s>v2 (Checkbox)</option>
                <option value="v3" %s>v3 (Invisible)</option>
            </select>',
            esc_attr($this->option_name),
            $selected_v2,
            $selected_v3
        );
    }

   public function render_settings_page() {

    if (!current_user_can('manage_options')) {
        return;
    }

   echo <<< AB
             <h1>Google reCAPTCHA Login Settings</h1>
            <p>Don't you have site key and secret key? <a href="https://www.google.com/recaptcha/admin/create">Create Here</a></p>   
   AB;

    echo '<form method="post" action="options.php">';

    settings_fields($this->option_name);
    do_settings_sections($this->option_name);

    submit_button('Save Settings');

    echo '</form>';
    echo '</div>';
}
}

new GRecaptchaLogin();
?>


