=== WP Doctor ===
Contributors: https://www.bestiaweb.com
Donate link: https://www.bestiaweb.com
Tags: doctor, malware, malwares, webshells, antivirus, malware cleaner, antimalware, anti malware, malware scan, malware scanner, security, protection, virus, security, protection, permissions, htaccess, ip block, blacklist
Requires at least: 2.8.0
Tested up to: 4.8.3
Stable tag: 1.7

Malware removal and security plugin. Periodically perform a full scan for malware, breaches security analysis and check if the domain is in blacklist.

== Description ==

Scan directories testing files against text or regexp rules, the rules based on self gathered samples and publicly vailable malwares/webshells.

WP Doctor is based on [security guidelines wordpress](http://codex.wordpress.org/Hardening_WordPress). For more information visit [WP DOCTOR PLUGIN PAGE](https://www.bestiaweb.com/wpdoctor) and [our website](https://www.bestiaweb.com).

<strong>Malware scanner/cleaner</strong>:

<strong>Malware removal plugin</strong>. Periodically scan the files and send an email with the list of infected files. Specify files that are not infected despite having been detected.

<ul>
<li> Scan the server for infected with malicious code or malware.</li>
<li> Clean infected files.</li>
<li> Scanning is automatically activated every x hours (the hours are configurable).</li>
<li> Send an email indicating the infected files.</li>
<li> Provides the ability to specify files that are not infected despite having been detected.</li>
<li> The Hours, email and infected files are configurable by the user in a very easy way.</li>
<li> This plugin will be continually updated with new viruses and new features.</li>
</ul>

<strong>Detects and removes malware such as</strong>:

<ul>
<li> eval (base64_decode ...</li>
<li> eval (gzinflate ...</li>
<li> eval (base64 ...</li>
<li> eval (gzinflate (base64_decode ...</li>
</ul>

<strong>Search domain blacklist</strong>

Check if the domain is in this blacklist:

<ul>
<li>dnsbl-1.uceprotect.net</li>
<li>surbl.org</li>
<li>uribl.com</li>
</ul>

<strong>Htaccess analysis</strong>

A good .htaccess can protect your wordpress. WP Doctor make an analysis of the .htaccess file and <strong>suggests safety modifications</strong>.

<ul>
<li> Securing wp-includes.</li>
<li> Securing wp-admin.</li>
</ul>

<strong>File permissions analysis</strong>

Allowing write access to your files is potentially dangerous. WP Doctor <strong>analyzes the files and folders permissions</strong>.

<ul>
<li>Check the files to have permission 644.</li>
<li>Check the folders to have permission 755.</li>
<li>Function to automatically switch to the correct permissions (depending on the server configuration).</li>
</ul>

<strong>IP blocks</strong>

Ip's Manager(add and delete) to which they are not allowed access to the web.

<strong>Using the plugin</strong>:

<ul>
<li> Install and activate the plugin.</li>

<li> Plugin administration is in Settings -> WP Doctor.</li>

<li> Since the administration you can set the hours and the email.</li>

<li> The Auto Scan runs when they pass the hours indicated in the configuration.</li>

<li> You can scan whenever you want from the administration of the plugin.</li>

<li> The delete function malware is executed from the administration.</li>

<li> Before making a removal of malware is recommended to back up files to be treated.</li>

<li> Changing permissions of files and folders depends on the server configuration.</li>

</ul>

== Installation ==

This section describes how to install the plugin and get it working.

1. Install the plugin via the plugins menu in your administrator.
2. Activate it and you'll see a new menu option in "Settings" the "wp doctor". 
3. Configure hours and email.


== Frequently Asked Questions ==

- What can I customize on wp doctor?
	<ul>
	<li>Scan period</li>
	<li>Email</li>
	<li>Files</li>
	</ul>

== Screenshots ==

1. WPDoctor Admin.
2. Clean and changing permissions operations.
3. Automatic scan settings.

== Changelog ==

= 1.7 =
* Detect webshells.

= 1.6 =
* Add dnsbl-1.uceprotect.net scan blacklist.

= 1.5 =
* New design.

= 1.4 =
* Check if the domain is in blacklist.

= 1.3 =
* Blocks access to the ips you indicate.

= 1.2 =
* htaccess and permissions analysis.
= 1.1 =
* Clean function and more security.
= 1.0 =
* first release

== Upgrade Notice ==

= 1.7 =
* Detect webshells.

= 1.6 =
* Add dnsbl-1.uceprotect.net scan blacklist.

= 1.5 =
* New design.

= 1.4 =
* Check if the domain is in blacklist.

= 1.3 =
* Blocks access to the ips you indicate.

= 1.2 =
* htaccess and permissions analysis.
= 1.1 =
* Clean function and more security.
= 1.0 =
* first release