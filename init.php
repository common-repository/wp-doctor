<?php
/*
Plugin Name: WP Doctor
Plugin URI: https://www.bestiaweb.com/wpdoctor/
Description: Malware removal and security plugin. Perform a full scan for malware and security breaches. Periodically scan the files and send an email with the list of infected files. Very easy to use and configure: Settings->WP Doctor.
Version: 1.7
Author: BestiaWeb S.C.P.
Author URI: https://www.bestiaweb.com

Copyright 2017  BestiaWeb S.C.P.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.
*/

include("scanner1/scan.php");
 
function wpdoctor_install() {
 
global $wpdb; 
	$table_name = $wpdb->prefix . "wpdoctor_configuration";	
	
		$re = $wpdb->query("select * from $table_name");
		
		
//autos  no existe
if(empty($re))
{	
	
		$sql = " CREATE TABLE $table_name(
		id mediumint( 9 ) NOT NULL AUTO_INCREMENT ,
		emailsend mediumint( 9 ) NOT NULL,
		email longtext NOT NULL ,
		op1 longtext NOT NULL ,
		op2 longtext NOT NULL ,
		op3 longtext NOT NULL ,
		op4 longtext NOT NULL ,
		op5 longtext NOT NULL ,

			PRIMARY KEY ( `id` )	
		) ;";

		$wpdb->query($sql);

		   $blogusers = get_users('role=Administrator');
    //print_r($blogusers);

		   $email="";
    foreach ($blogusers as $user) {
        if($email=="") $email=$user->user_email;
      }

			
		$wpdb->insert(
   $table_name,
   array(
      'emailsend' => 240,
      'email' => $email,
      'op2' => 'c'
      ),
   array(
   	  '%d',
      '%s',
      '%s'

   )
  );


	}
 
}

register_activation_hook( __FILE__, 'wpdoctor_install' );

// head function

function wpdoctor_head() {

	global $wpdb; 
	$table_name = $wpdb->prefix . "wpdoctor_configuration";

	$re = $wpdb->query("select * from $table_name");
	if(empty($re)) wpdoctor_install();

	$myrows = $wpdb->get_results( "SELECT * FROM $table_name WHERE op2 = 'b'" );


	if(isset($myrows[0]->op3) && $myrows[0]->op3!="") {

		$ipb=explode("*b*", $myrows[0]->op3);

		if (in_array(get_the_user_ip(), $ipb)) {
    		header("location: http://www.google.com/");
   			exit();
		}
	}

}

add_action( 'wp_head', 'wpdoctor_head', 0 );
 
//get ip

function get_the_user_ip() {
	if ( ! empty( $_SERVER['HTTP_CLIENT_IP'] ) ) {
	//check ip from share internet
	$ip = $_SERVER['HTTP_CLIENT_IP'];
	} elseif ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
	//to check ip is pass from proxy
	$ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
	} else {
	$ip = $_SERVER['REMOTE_ADDR'];
	}
	return apply_filters( 'wpb_get_ip', $ip );
}

function wpdoctor_panel(){
	
	global $panelactivo;
	$panelactivo=0;
	global $wpdb; 

	$table_name = $wpdb->prefix . "wpdoctor_configuration";

	if(isset($_POST["wpdoctorsave"])) {

		$nonce = $_REQUEST['nonce'];

		if ( ! wp_verify_nonce( $nonce, 'wpdoctor' ) ) {

     die( 'Security check' ); 

} else {


		$wpdb->update(
  $table_name,
  array( 'emailsend' => sanitize_text_field($_POST["emailsend"]), 'email' => sanitize_email($_POST["email"]) ),
  array( 'op2' => 'c' )
);

	}
			
		$panelactivo=1;	
	}


		if(isset($_POST["cont"]) && !isset($_POST["noti"]) && isset($_POST["sav"])) {


			$cont=0;

			while($cont<$_POST["cont"]) {


if(isset($_POST["c".$cont]) && $_POST["c".$cont]==1) {


	$filemal=sanitize_text_field($_POST["f".$cont]);

	$filemal=str_replace("\\\\", "\\", $filemal);


$wpdb->insert(
   $table_name,
   array(
      'emailsend' => 0,
      'op1' => $filemal,
      'op2' => 'f'
   ),
   array(
   	  '%d',
      '%s',
      '%s'

   )
  );


		}
		$cont++;
		}

		$panelactivo=3;
	}


	if(isset($_POST["cont"]) && isset($_POST["noti"])) {

			$cont=0;

			$nonce = $_REQUEST['nonce'];

		if ( ! wp_verify_nonce( $nonce, 'wpdoctor' ) ) {

     die( 'Security check' ); 

} else {

			while($cont<$_POST["cont"]) {


if(!isset($_POST["c".$cont])) {

		
				$filemal=sanitize_text_field($_POST["f".$cont]);

	$filemal=str_replace("\\\\", "\\", $filemal);
			
			$wpdb->query($wpdb->prepare("DELETE FROM $table_name WHERE op1 = %s", $filemal));
		}
		$cont++;
		}
	}

	$panelactivo=3;
	}

	if(isset($_POST["bip"]) && isset($_POST["cont"])) {

		$contb=0;

		$op3="";

		while($contb<$_POST["cont"]) {

			if(isset($_POST["c".$contb])) {

				if($op3!="") $op3.='*b*'.sanitize_text_field($_POST["f".$contb]);
				else  $op3.=sanitize_text_field($_POST["f".$contb]);
			}

			$contb++;


		}

			$wpdb->update(
				$table_name,
				array( 'op3' => $op3 ),
				array( 'op2' => 'b' )
				);

			$panelactivo=4;
	}
	else if(isset($_POST["bip"])) {

		$nonce = $_REQUEST['nonce'];

		if ( ! wp_verify_nonce( $nonce, 'wpdoctor' ) ) {

    	die( 'Security check' ); 

		} else {

			$myrows = $wpdb->get_results( "SELECT * FROM $table_name WHERE op2 = 'b'" );


			if(isset($myrows[0]->op3)) {

				if($myrows[0]->op3!="") {
					$wpdb->update(
					$table_name,
					array( 'op3' => $myrows[0]->op3.'*b*'.sanitize_text_field($_POST["blockip"]) ),
					array( 'op2' => 'b' )
					);
				}
				else {

					$wpdb->update(
					$table_name,
					array( 'op3' => sanitize_text_field($_POST["blockip"]) ),
					array( 'op2' => 'b' )
					);
				}

			}
			else {

				$wpdb->insert(
					$table_name,
					array(
					'op2' => 'b',
					'op3' => sanitize_text_field($_POST["blockip"])
					),
					array(
					'%s',
					'%s'

					)
				);

			}
		}

		$panelactivo=4;
	}


	$myrows = $wpdb->get_results( "SELECT * FROM $table_name" );
	$nonce=wp_create_nonce( 'wpdoctor' );

	?>
	<style>

	.wpdoctor {
		background: #f6f6f6;
		padding: 15px;
	}

	.wpdoctor h1, .wpdoctor span {
		    height: 64px;
    vertical-align: text-top;
	}
	.wpdoctor h1 {
		border-radius:5px;
		padding:10px;
		background-color: #34495e;
		color: #ecf0f1;

	}

		.wpdoctor h2 {
		border-radius:5px;
		padding:10px;
		background-color: #d54e21;
		color: #ecf0f1;
		margin-right: 30px;

	}
		.wpdoctor h3 {
		border-radius:5px;
		padding:10px;
		background-color: #d54e21;
		color: #ecf0f1;
		margin-right: 30px;

	}
	.wpdoctor strong {
		color: #e74c3c;

	}
	.orange {
		background-color: #e67e22;
	}
	.panel {
		display:none;
		padding-left: 30px;
	}
	.active {
		display: block;
	}
	.settings-nav {
	    background: #f6f6f6;
	    border-bottom: 1px solid #d6d6d6;
	    padding: 5px 0 0 30px;
	    margin: 0;
	}
	ul {
	    list-style: none;
	}
	.settings-nav li.active {
	    background: #f0f0f0;
	    border-bottom-color: #f0f0f0;

	}
	.settings-nav li {
	    display: inline-block;
	    margin: 0 0 -1px 0;
	    background: #ffffff;
	    line-height: 1em;
	    font-size: 12px;
	    position: relative;
	    border: 1px solid #d6d6d6;
	    border-width: 1px 1px 1px 1px;
	    transition: all 0.2s;
	}
	.settings-nav li a {
	    display: block;
	    text-decoration: none;
	    color: #555;
	    padding: 12px 25px;
	    font-weight: bold;
	    box-shadow: none !important;
	}

	</style>

	<script>

		function wpdoctor_panels(panel) {

			jQuery( ".settings-nav li" ).removeClass( "active" );
			jQuery( "#bpanel"+panel ).addClass( "active" );

			jQuery( ".panel" ).removeClass( "active" );
			jQuery( "#panel"+panel ).addClass( "active" );

		}

		jQuery(document).ready(function($){
			wpdoctor_panels(<?php global $panelactivo; echo $panelactivo; ?>);
		});

	</script>

<div class="wpdoctor">
	<h1><img src="<?php echo plugins_url( 'wpdoctor.png', __FILE__ ); ?>"><span><?php _e("WP DOCTOR", "wpdoctor"); ?> by Bestiaweb.com</span><a href="https://www.bestiaweb.com" target="_blank" title="Design web"><img src="<?php echo plugins_url( 'bestiaweb.png', __FILE__ ); ?>"></a></h1>
	<p><?php _e("Automatically scans server files for malware. Configure every few hours be performed scanning and email where notices are sent. Analyzes the .htaccess file and prompts you to insert code to make sure your website. Analyzes the files and folders permissions. It has a function to directly remove malware files. It has another function to automatically change the permissions on files and folders. Ip's Manager(add and delete) to which they are not allowed access to the web. Is based on <a href='http://codex.wordpress.org/Hardening_WordPress' target='_blank'>security guidelines wordpress</a>. For <strong>more information about the plugin and safety of wordpress enter <a href='https://www.bestiaweb.com/wpdoctor/' target='_blank'>WP Doctor website</a></strong>.", "wpdoctor"); ?></p>
	<strong><?php echo __("Last scan: ", "wpdoctor").' '.$myrows[0]->op1; ?></strong><br/>
	<center><br/>
		<a href="options-general.php?page=<?php echo $_GET["page"]; ?>&scan=1&nonce=<?php echo $nonce; ?>" class="button-primary"><?php _e("WP DOCTOR SCAN", "wpdoctor"); ?></a>
		<br/><br/><strong><?php _e("Scan malware, .htaccess file, blacklist, file permissions, ... . This function is secure and not changes files.", "wpdoctor"); ?></strong>
	</center>
</div>

<ul class="settings-nav">
		<li class="active" id="bpanel0" name="bpanel0"><a href="javascript:wpdoctor_panels(0);"><?php _e("Scan results", "wpdoctor"); ?></a></li>
		<li id="bpanel1" name="bpanel1"><a href="javascript:wpdoctor_panels(1);"><?php _e("Settings", "wpdoctor"); ?></a></li>
		<li class="" id="bpanel2" name="bpanel2"><a href="javascript:wpdoctor_panels(2);"><?php _e("Operations", "wpdoctor"); ?></a></li>
		<li class="" id="bpanel3" name="bpanel3"><a href="javascript:wpdoctor_panels(3);"><?php _e("Not suspicious files", "wpdoctor"); ?></a></li>
		<li class="" id="bpanel4" name="bpanel4"><a href="javascript:wpdoctor_panels(4);"><?php _e("Block ip", "wpdoctor"); ?></a></li>	
</ul>

<div class="panel" id="panel1" name="panel1">	

		<form method="post" action="">
			<br/><br/>
				<label><?php echo _e("Scanning period(in hours):", "wpdoctor"); ?></label>
	<input type="text" value="<?php echo esc_attr($myrows[0]->emailsend); ?>" id="emailsend" name="emailsend"><br/><br/>
			<label><?php echo _e("Notifications email:", "wpdoctor"); ?></label>
	<input type="text" value="<?php echo esc_attr($myrows[0]->email); ?>" id="email" name="email">
	<input type="hidden" name="nonce" id="nonce" value="<?php echo $nonce; ?>"><br/><br/><br/>
	 <input type='submit' class="button-primary" name='wpdoctorsave' id='wpdoctorsave' value='<?php echo _e("Save settings", "wpdoctor"); ?>' />
	</form>

</div>



<div class="panel" id="panel2" name="panel2">
<br/><br/>

<a href="options-general.php?page=<?php echo $_GET["page"]; ?>&scan=3&nonce=<?php echo $nonce; ?>" class="button-primary"><?php _e("Changing file permissions", "wpdoctor"); ?></a> <strong><?php _e("The plugin changes the incorrect permissions only if the server configuration allows.", "wpdoctor"); ?></strong>

<br/><br/>
<a href="options-general.php?page=<?php echo $_GET["page"]; ?>&scan=2&nonce=<?php echo $nonce; ?>" class="button-primary"><?php _e("Clean Malware", "wpdoctor"); ?></a> <strong><?php _e("¡It is recommended that you scan and back up files before cleaning the files!", "wpdoctor"); ?></strong>

</div>

	<?php

	echo '<div class="panel" id="panel3" name="panel3"><br/>';
	echo '<h2>Not suspicious files</h2><form method="post" action=""><table>';

	$cont=0;
	foreach($myrows as $r) {

		if($r->op2=="f") {

			echo '<tr><td>'.$r->op1.'</td><td><input type="hidden" name="f'.$cont.'" id="f'.$cont.'" value="'.$r->op1.'"><input type="checkbox" id="c'.$cont.'" name="c'.$cont.'" value="1" title="file not infected" checked="checked"></td></tr>';
			$cont++;
		}	
			
		
	}

	if($cont==0) echo '<tr><td>'.__("Not files", "wpdoctor").'</td></tr>';

	echo '<input type="hidden" value="'.$cont.'" name="cont" id="cont"><input type="hidden" value="0" name="scan" id="scan"></table>';

	if($cont>0) echo '<br/><input type="hidden" name="nonce" id="nonce" value="'.$nonce.'"><input type="submit" id="noti" name="noti" value="Save">';

	echo '</form>';

	echo '</div>';


	echo '<div class="panel" id="panel4" name="panel4"><br/>';
	
	echo '<br/><form method="post" action="">';
	echo '<input type="text" value="" name="blockip" id="blockip"> <input type="hidden" name="nonce" id="nonce" value="'.$nonce.'"><input type="submit" id="bip" name="bip" value="'.__("Add blocked IP", "wpdoctor").'">';
	echo '</form>';

	echo '<h2>'.__("LIST BLOCK IP", "wpdoctor").'</h2><form method="post" action=""><table>';

	$myrows = $wpdb->get_results( "SELECT * FROM $table_name WHERE op2 = 'b'" );

	$cont=0;

	if(isset($myrows[0]->op3) && $myrows[0]->op3!="") {

	 $ipb=explode("*b*", $myrows[0]->op3);

		foreach($ipb as $r) {

			echo '<tr><td>'.$r.'</td><td><input type="hidden" name="f'.$cont.'" id="f'.$cont.'" value="'.$r.'"><input type="checkbox" id="c'.$cont.'" name="c'.$cont.'" value="1" title="IP Block" checked="checked"></td></tr>';
					
			$cont++;
		}

	}

	echo '<input type="hidden" value="'.$cont.'" name="cont" id="cont"><input type="hidden" value="0" name="scan" id="scan"></table>';
	
	if($cont>0) echo '<br/><input type="submit" id="bip" name="bip" value="Save blocked IP list">';
	else echo '<strong>'.__("Not blocked ip's", "wpdoctor").'</strong>';
	
	echo '</form>';
	echo '</div>';

	echo '<div class="panel active" id="panel0" name="panel0"><br/>';
	global $info_wpdoctor;

	if($info_wpdoctor=="") {
		$myrows = $wpdb->get_results( "SELECT * FROM $table_name WHERE op2 = 'c'" );
		if($myrows[0]->op4!="") $info_wpdoctor=$myrows[0]->op4;
		else echo '<br/><strong>'.__("Not scan", "wpdoctor").'</strong>';
	}

	else {
		$wpdb->update(
			$table_name,
			array( 'op4' => $info_wpdoctor),
			array( 'op2' => 'c' )
		);
	}

	echo $info_wpdoctor;

	echo '</div>';
}




function wpdoctor_add_menu(){	
	if (function_exists('add_options_page')) {
		//add_menu_page
		add_options_page('wpdoctor', 'WP Doctor', 'manage_options', basename(__FILE__), 'wpdoctor_panel');
	}
}


if (function_exists('add_action')) {
	add_action('admin_menu', 'wpdoctor_add_menu'); 
}


if(isset($_GET["scan"]) && $_GET["scan"]==1 && !isset($_POST["cont"]) && !isset($_POST["wpdoctorsave"])) {

ini_set('memory_limit', '-1'); ## Avoid memory errors (i.e in foreachloop)


	global $wpdb; 

	$nonce = $_REQUEST['nonce'];

	$table_name = $wpdb->prefix . "wpdoctor_configuration";
	
	$myrows = $wpdb->get_results( "SELECT * FROM $table_name" );

$wpdb->update($table_name, array('op1' => date("Y-m-d H:i:s")), array('op2' => 'c'));


new WpDoctorMalCodeScan(1, $nonce, 0);


}

if(isset($_GET["scan"]) && $_GET["scan"]==2 && !isset($_POST["cont"]) && !isset($_POST["wpdoctorsave"])) {

ini_set('memory_limit', '-1'); ## Avoid memory errors (i.e in foreachloop)


	global $wpdb; 

	$nonce = $_REQUEST['nonce'];

	$table_name = $wpdb->prefix . "wpdoctor_configuration";
	
	$myrows = $wpdb->get_results( "SELECT * FROM $table_name" );

$wpdb->update($table_name, array('op1' => date("Y-m-d H:i:s")), array('op2' => 'c'));


new WpDoctorMalCodeScan(1, $nonce, 1);


}


if(isset($_GET["scan"]) && $_GET["scan"]==3 && !isset($_POST["cont"]) && !isset($_POST["wpdoctorsave"])) {

ini_set('memory_limit', '-1'); ## Avoid memory errors (i.e in foreachloop)


	global $wpdb; 

	$nonce = $_REQUEST['nonce'];

	$table_name = $wpdb->prefix . "wpdoctor_configuration";
	
	$myrows = $wpdb->get_results( "SELECT * FROM $table_name" );

$wpdb->update($table_name, array('op1' => date("Y-m-d H:i:s")), array('op2' => 'c'));


new WpDoctorMalCodeScan(1, $nonce, 2);


}


function wpdoctor_scan() {
	global $wpdb; 

	$nonce=wp_create_nonce( 'wpdoctor' );

	$table_name = $wpdb->prefix . "wpdoctor_configuration";
	
	$myrows = $wpdb->get_results( "SELECT * FROM $table_name" );


############################################ INITIATE CLASS

define('SEND_EMAIL_ALERTS_TO', $myrows[0]->email);


$diferencia = date("H", strtotime($myrows[0]->op1))-date("H");	

$horas=$myrows[0]->emailsend;

																			

	if($diferencia > $horas || $diferencia < -$horas || $myrows[0]->op1=='') {

		$wpdb->update($table_name, array('op1' => date("Y-m-d H:i:s")), array('op2' => 'c'));


	ini_set('memory_limit', '-1'); ## Avoid memory errors (i.e in foreachloop)

	new WpDoctorMalCodeScan(0, $nonce, 0);
}

}

class WpDoctorMalCodeScan {

	public $not_files=array();

	public $infected_files = array();
	private $scanned_files = array();
	public $cleaned_files=array();

	public $notpermfiles=array();
	public $notpermdire=array();
	public $home="";

	public $scan;
	
	function __construct($option, $nonce, $clean) {



		global $wpdb; 

		global $info_wpdoctor;

		$this->scan=new MalwareScanner();

	$table_name = $wpdb->prefix . "wpdoctor_configuration";
	
	$myrows = $wpdb->get_results( "SELECT * FROM $table_name" );


	foreach($myrows as $r) {

		if($r->op2=="f") $this->not_files[]=$r->op1;

	}


		$dir = plugin_dir_path( __FILE__ );

		$dir2=explode("wp-content", $dir);

		if(isset($dir2[0])) $dir=$dir2[0];

		$this->home=$dir;

	

		$this->scan($dir, $clean, $option);
		if($option!=1) $this->sendalert();

		if($option==1) { 

			
			$info_wpdoctor.='<h3>'.__("Malware scan results", "wpdoctor").'</h3><strong>'.count($this->scanned_files).' '.__("Files scaned", "wpdoctor").', '.count($this->infected_files).' '.__("suspicious files", "wpdoctor").'</strong><br/><form method="post" action=""><table>';


			if(count($this->infected_files)>0) {

				$cont=0;
				foreach($this->infected_files as $f) {

					$info_wpdoctor.='<tr><td><strong style="color:red;">'.$f.'</strong></td><td><input type="hidden" name="f'.$cont.'" id="f'.$cont.'" value="'.$f.'"><input type="checkbox" id="c'.$cont.'" name="c'.$cont.'" value="1" title="file not infected"></td></tr>';
					$cont++;
				} 

				foreach($this->cleaned_files as $f) {

					$info_wpdoctor.='<tr><td><strong style="color:green;">'.$f.'</strong></td><td>Cleaned</td></tr>';

				} 

				$info_wpdoctor.='<input type="hidden" value="'.$cont.'" name="cont" id="cont"><input type="hidden" value="0" name="scan" id="scan"></table><br/>'.__("Check not suspicious files.", "wpdoctor").'<br/><br/><input type="hidden" id="nonce" name="nonce" value="'.$nonce.'"><input type="submit" id="sav" name="sav" value="Save"></form>';

			}
		}
	


		if($option==1) {


			// blacklist



			$info_wpdoctor.='<br/><h3>'.__("Domain in blacklist?", "wpdoctor").'</h3>';

			$url=get_home_url();


			    $parsed = wpdoctor_parse($url);
           
		    // Remove www. from domain (but not from www.com)
		    $parsed['host'] = trim(preg_replace( '/^www\.(.+\.)/i', '$1', $parsed['host']));
		  
		    //The major blacklists
		    $blacklists = array(
		     'dnsbl-1.uceprotect.net',
		     'surbl.org',
		     'uribl.com'
		    );

		    $isinblack="";
		    $ipweb = gethostbyname($parsed['host']); 
		    // Check against each black list, exit if blacklisted
		    foreach( $blacklists as $blacklist ) {
		        //$domain = $parsed['host'] . '.' . $blacklist . '.';
		        //$record = dns_get_record(trim($domain));  
		        if( wpdoctor_dnsbl_check( $ipweb, $blacklist ) == true ) {
		             $isinblack.=$blacklist." ";  
		        } 
		     } 

		     if($isinblack!="") $info_wpdoctor.=$url.' is in this blacklists: <strong>'.$isinblack.'</strong>.';
		     else  $info_wpdoctor.=$url.' not is in blacklists.';


			// htaccess


		if(is_file($dir.'.htaccess')) {

			$info_wpdoctor.='<h3>'.__("Recommend adding in .htaccess file", "wpdoctor").'</h3>';

		 $conthaccess= file_get_contents($dir.'.htaccess');

		 if(strpos($conthaccess, "files wp-config.php")===false) {

		 	$info_wpdoctor.='
		 	<pre>&lt;files wp-config.php&gt;
order allow,deny
deny from all
&lt;/files&gt;</pre>

		 	';
		 }

		 if(strpos($conthaccess, "wp-includes/js/tinymce/langs")===false) {

		 	$info_wpdoctor.='
<pre># Block the include-only files.
&lt;IfModule mod_rewrite.c&gt;
RewriteEngine On
RewriteBase /
RewriteRule ^wp-admin/includes/ - [F,L]
RewriteRule&#160;!^wp-includes/ - [S=3]
RewriteRule ^wp-includes/[^/]+\.php$ - [F,L]
RewriteRule ^wp-includes/js/tinymce/langs/.+\.php - [F,L]
RewriteRule ^wp-includes/theme-compat/ - [F,L]
&lt;/IfModule&gt;


# BEGIN WordPress</pre>



		 	';
		 }

		}

		else $info_wpdoctor.='<br/><h3>'.__("Not .htaccess file", "wpdoctor").'</h3>';

}

		if($option==1) {

			if(count($this->notpermdire)>0) $info_wpdoctor.='<h3>'.__("Recommend changing directory permissions to 755", "wpdoctor").'</h3>';

			foreach($this->notpermdire as $f) {

				$info_wpdoctor.=''.$f.'<br/>';

			} 

			if(count($this->notpermfiles)>0) $info_wpdoctor.='<h3>'.__("Recommend changing file permissions to 644", "wpdoctor").'</h3>';

			foreach($this->notpermfiles as $f) {

				$info_wpdoctor.=''.$f.'<br/>';

			} 
		}
	}
	

	
	function scan($dir, $clean, $option) {
		$this->scanned_files[] = $dir;
		$files = scandir($dir); 
		
		if(!is_array($files)) {
			throw new Exception('Unable to scan directory ' . $dir . '.  Please make sure proper permissions have been set.');
		}
		
		foreach($files as $file) {
			
			if(is_file($dir.'/'.$file) && !in_array($dir.'/'.$file,$this->scanned_files)) {
				if($option==1 && (strpos($dir, "wp-admin") || strpos($dir, "wp-includes" || $dir==$this->home))) {

				 $per= substr(sprintf('%o', fileperms($dir.'/'.$file)), -4);
				 $noc=0;

				 if($clean==2 && $per!=0644 && $per!=1644 && $per!=644) {



				 	if(!chmod($dir.'/'.$file, 644)) {

				 		if(chmod($dir.'/'.$file, 0644)) $noc=1;
				 	}
				 	else $noc=1;
				 }

				 if($per!=0644 && $per!=1644 && $per!=644 && $noc==0) $this->notpermfiles[]=$dir.'/'.$file;

				}

				if(strpos($file, ".php")!==false || strpos($file, ".tpl")!==false || strpos($file, ".htm")!==false || strpos($file, ".html")!==false) $this->check(file_get_contents($dir.'/'.$file),$dir.'/'.$file, $clean);
			} elseif(is_dir($dir.'/'.$file) && substr($file,0,1) != '.') {

				if($option==1) {

				 $per= substr(sprintf('%o', fileperms($dir.'/'.$file)), -4);
				 $noc=0;

				 if($clean==2 && $per!=0755 && $per!=1755 && $per!=755) {

				 	if(!chmod($dir.'/'.$file, 755)) {

				 		if(chmod($dir.'/'.$file, 0755)) $noc=1;
				 	}
				 	else $noc=1;
				 }

				 if($per!=0755 && $per!=1755 && $per!=755 && $noc==0) $this->notpermdire[]=$dir.'/'.$file;

				}

				$this->scan($dir.'/'.$file, $clean, $option);
			}

		}


	}
	
	
	function check($contents,$file, $clean) {
		$this->scanned_files[] = $file;
		if(preg_match('/[\@]?eval\(gzinflate\(base64_decode\([\"\']?[a-zA-F0-9\=\+\$](.*?)[\"\']?\)\)\);/', $contents, $matches0) || preg_match('/[\@]?eval\(base64_decode\([\"\']?[a-zA-F0-9\=\+\$](.*?)[\"\']?\)\);/', $contents, $matches1) || preg_match('/eval\((base64|eval|gzinflate|\$_|\$\$|\$[A-Za-z_0-9\{]*(\(|\{|\[))/i',$contents, $matches2)) {
			if (!in_array($file, $this->not_files))  {
				$isclean=0;
				if($clean==1) {

					foreach ($matches0 as $m) {
						if(strpos($m, ")")) $contents = str_replace($m, '', $contents);
						else {

							$cadena="";

							$aux=explode($m, $contents);

							if(isset($aux[1])) {

								$cadena.=$m;

								$aux2=explode(");", $aux[1]);

								if(isset($aux2[1])) {

									$cadena.=$aux2[0].');';
								}

								$contents = str_replace($cadena, '', $contents);

							}
						}
					}


					foreach ($matches1 as $m) {
						if(strpos($m, ")")) $contents = str_replace($m, '', $contents);
						else {

							$cadena="";

							$aux=explode($m, $contents);

							if(isset($aux[1])) {

								$cadena.=$m;

								$aux2=explode(");", $aux[1]);

								if(isset($aux2[1])) {

									$cadena.=$aux2[0].');';
								}

								$contents = str_replace($cadena, '', $contents);

							}
						}
					}



					foreach ($matches2 as $m) {
						if(strpos($m, ")")) $contents = str_replace($m, '', $contents);
						else {

							$cadena="";

							$aux=explode($m, $contents);

							if(isset($aux[1])) {

								$cadena.=$m;

								$aux2=explode(");", $aux[1]);

								if(isset($aux2[1])) {

									$cadena.=$aux2[0].');';
								}

								$contents = str_replace($cadena, '', $contents);

							}
						}
					}
					
					if(is_writable($file)){
						$fh = fopen($file, 'w+'); 
						fwrite($fh, $contents); 
						fclose($fh);
						$this->cleaned_files[] = $file;
						$isclean=1;
					}
				}
				if($isclean==0) $this->infected_files[] = $file;
			}
		}

		else if($this->scan->scan($file)) {
			if (!in_array($file, $this->not_files)) $this->infected_files[] = $file;
		}

		
	}


	function sendalert() {
		if(count($this->infected_files) != 0) {
			$message = __("== MALICIOUS CODE FOUND ==", "wpdoctor")." \n\n";
			$message .= __("The following files appear to be infected:", "wpdoctor")." \n";
			foreach($this->infected_files as $inf) {
				$message .= "  -  $inf \n";
			}
			mail(SEND_EMAIL_ALERTS_TO, __("Malicious Code Found!", "wpdoctor"),$message,'FROM:');
		}
	}


}

	function wpdoctor_parse($url) {
	    if(strpos($url,"://")===false && substr($url,0,1)!="/") $url = "http://".$url;
	    $info = parse_url($url);
	    if($info)
	    return($info);
	}

  	function wpdoctor_dnsbl_check( $ip_address = NULL, $dnsbl = NULL ) {
        if( $ip_address == NULL )
        {
              /* No IP address given */
              return false;
        }

        if( filter_var($ip_address, FILTER_VALIDATE_IP) === false )
        {
              /* IP address is invalid */
              return false;
        }

        if( $dnsbl == NULL )
        {
              /* No DNSBL to check against */
              return false;
        }

        /* Need to reverse the IP address */
        $array = explode( ".", $ip_address );
        $array = array_reverse( $array );
        $reverse_ip = implode( ".", $array );

        /* Perform the check */
        $res = gethostbyname( $reverse_ip.".".$dnsbl );

        if( $res == $reverse_ip.".".$dnsbl )
        {
              /* IP is not in given DNSBL */
              return false;
        }

        /* No checks failed, hostname does not match request, IP is in DNSBL */
        return true;
  }

?>
