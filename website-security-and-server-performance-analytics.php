<?php
/*
Plugin Name: Website Security and Server Performance Analytics
Plugin URI: https://www.siteguarding.com/en/website-extensions
Description: Helps to analyze website security and server performance.
Version: 1.2
Author: SiteGuarding
Author URI: https://www.siteguarding.com/
License: GPLv2
*/
// rev.20200601
if( is_admin() ) {

    
    
    
	function register_plgwsspa_page() 
	{
		add_menu_page('plgwsspa_server_analytics', 'Server Analytics', 'activate_plugins', 'plgwsspa_server_analytics', 'register_plgwsspa_plugin_page', plugins_url('images/', __FILE__).'icon-logo.png');
	}
    add_action('admin_menu', 'register_plgwsspa_page');
    

	
	add_action( 'wp_ajax_plgwsspa_ajax_report', 'plgwsspa_ajax_report' );
    function plgwsspa_ajax_report($data) 
    {
        if (!plgwsspa_Copy_SG_tools_file())
        {
            echo json_encode( array('status' => 'error', 'reason' => 'Error. Can\'t copy siteguarding_tools.php to '.ABSPATH, 'url' => '') );
            wp_die();
        }
        
        $logfile = trim( $_POST['logfile'] );
        $website_url = get_site_url();
        $report_id = md5($logfile.'-'.$website_url);
        
        $url = "https://www.siteguarding.com/index.php";
        $response = wp_remote_post( $url, array(
            'method'      => 'POST',
            'timeout'     => 600,
            'redirection' => 5,
            'httpversion' => '1.0',
            'blocking'    => true,
            'headers'     => array(),
            'body'        => array(
                'option' => 'com_securapp',
                'task' => 'ServerReport_API_generate_report',
                'logfile' => $logfile,
                'logfile_size' => filesize($logfile),
                'report_id' => $report_id,
                'website_url' => $website_url
            ),
            'cookies'     => array()
            )
        );
        
        $json = (array)json_decode($response['body'], true);
        
        if (!isset($json['reason'])) $json['reason'] = 'Error. Reason is unknown. Contact SiteGuarding.com support.';
        
        if ($json['status'] == 'ok') echo json_encode( array('status' => 'ok', 'reason' => '', 'report_url' => $json['report_url']) );
        else  echo json_encode( array('status' => 'error', 'reason' => $json['reason'], 'report_url' => '') );

        wp_die();
    }   
    

	function register_plgwsspa_plugin_page() 
	{
        ?>
        <style>
        .mrg_lft_0{margin-left:0!important;}
        .color_red{color: red;}
        .ajax_centered{padding:20px; position: fixed;top: 35%;left: 40%;width:350px;height:250px;background-color: white; border:1px solid #777;text-align: center;}
        .ajax_centered img{width: 150px;}
        .ajax_centered span{font-size: 150%;}
        .showblockquote{display: inline;}
        </style>
        <script>
        function SG_ViewReport(logfile)
        {
            jQuery('#sg_ajax_block').show();
            
    		jQuery.post(
    			ajaxurl, 
    			{
    				'action': 'plgwsspa_ajax_report',
    				'logfile' : logfile
    			}, 
    			function(response){
    			     jQuery('#sg_ajax_block').hide();
                     const obj = JSON.parse(response);
                     if (obj.status == 'ok') openInNewTab(obj.report_url);
                     else alert(obj.reason);
    			}
            );
        }
        
        function openInNewTab(url) {
          var win = window.open(url, '_blank');
          win.focus();
        }
        </script>
        
        <h1 class="wp-heading-inline">Website security and Server performance analytics</h1>
        
        <div class="updated notice mrg_lft_0">
            <p><span class="dashicons dashicons-welcome-learn-more"></span> Plugin will scan all folders on the server to detect server log files. Tested with WHM(cPanel) and Plesk hosting panels.<br><br><span class="color_red">If you have custom configured server. Please contact with your hosting company and ask them about access_log files location.</span></p>
        </div>
        
        
        <?php
        $path = ABSPATH;
        $logs_path = '';
        
        while ($path != '/')
        {
            $path = dirname($path);
            if (file_exists($path.'/logs')) 
            {
                $logs_path = $path.'/logs';
                break;
            }   
        }

        if ($logs_path != '') 
        {
            $log_files = array();
            foreach (glob($logs_path."/*") as $filename) 
            {
                $log_size = filesize($filename);
                $log_filename = basename($filename);
                // Skip error and small files
                if (stripos($log_filename, 'error') !== false || $log_size < 1000) continue;
                // Skip not .gz and not .log files
                if (stripos($log_filename, '.gz') === false && stripos($log_filename, '.log') === false && stripos($log_filename, 'access_log') === false)  continue;
                // Validate log file
                if (!plgwsspa_Validate_Log_File($filename)) continue;
                
                $log_files[] = array(
                    'file' => $filename,
                    'size' => $log_size
                );
            }
            


            if (count($log_files))
            {
                ?>
                <h3 class="wp-heading-inline">Detected server log files</h3>
                
                <div class="ajax_centered" id="sg_ajax_block" style="display: none;">
                    <img src="<?php echo plugins_url('images/ajax_loader.svg', __FILE__); ?>"/>
                    <br />
                    <br />
                    <span><b>Analyze is started</b></span></br><br /><b>It can take up to 5 minutes.</b><br />
                    You will be redirected to the report page shortly.
                </div>
                
                <table class="wp-list-table widefat fixed striped">
            	<thead>
            	<tr>
                    <th>Log file</th>
                    <th>Size</th>
                    <th>Report</th>
            	</tr>
            	</thead>
            
            	<tbody id="the-list">
                <?php
                foreach ($log_files as $row)
                {
                    $traffic_data = plgwsspa_PrepareTrafficValue($row['size']);
                    
                    if ($row['size'] > 200 * 1024 * 1024) // Max 200Mb file
                    {
                        ?>
                    	<tr>
                            <td><?php echo $row['file']; ?></td>
                            <td><?php echo number_format( $traffic_data['value'] , 2, '.', ',' ).' '.$traffic_data['text']; ?></td>
                            <td>Log file is too large</a></td>
                    	</tr>
                        <?php
                    }
                    else {
                        ?>
                    	<tr>
                            <td><a onclick="SG_ViewReport('<?php echo $row['file']; ?>')" href="javascript:;"><?php echo $row['file']; ?></a></td>
                            <td><?php echo number_format( $traffic_data['value'] , 2, '.', ',' ).' '.$traffic_data['text']; ?></td>
                            <td><a onclick="SG_ViewReport('<?php echo $row['file']; ?>')" href="javascript:;"><span class="dashicons dashicons-media-document"></span> Report</a></td>
                    	</tr>
                        <?php
                    }
                }
                ?>
                </tbody>
                </table>
                <?php
            }
            else {
                ?>
                <div class="error notice mrg_lft_0">
                    <p>Server log files are not detected.</p>
                </div>
                <?php
            }
        }
        else {
            ?>
            <div class="error notice mrg_lft_0">
                <p>Server log files are not detected.</p>
            </div>
            <?php
        }
        
        ?>
        
        <p>&nbsp;</p>
        <hr>
        
        <h2 class="wp-heading-inline">Support</h2>
        
		<p>
		For more information about this plugin please contact our support.<br /><br />
		<a href="http://www.siteguarding.com/livechat/index.html" target="_blank">
			<img src="<?php echo plugins_url('images/livechat.png', __FILE__); ?>"/>
		</a><br />
		For any questions and support please use LiveChat or this <a href="https://www.siteguarding.com/en/contacts" rel="nofollow" target="_blank" title="SiteGuarding.com - Website Security. Professional security services against hacker activity. Daily website file scanning and file changes monitoring. Malware detecting and removal.">contact form</a>.<br>
		<br>
		<a href="https://www.siteguarding.com/" target="_blank">SiteGuarding.com</a> - Website Security. Professional security services against hacker activity.<br />
		</p>
        <p>
            <a href="https://www.siteguarding.com/" target="_blank"><img style="width: 300px;" src="<?php echo plugins_url('images/logo_siteguarding.svg', __FILE__); ?>"/></a>
        </p>
        
        <hr />
        
            <div class="" style="margin-top: 10px;">
                <a href="https://www.siteguarding.com/en/protect-your-website" target="_blank"><img src="<?php echo plugins_url('images/rek1.png', __FILE__); ?>" /></a>&nbsp;
                <a href="https://www.siteguarding.com/en/secure-web-hosting" target="_blank"><img src="<?php echo plugins_url('images/rek2.png', __FILE__); ?>" /></a>&nbsp;
                <a href="https://www.siteguarding.com/en/importance-of-website-backup" target="_blank"><img src="<?php echo plugins_url('images/rek3.png', __FILE__); ?>" /></a>
            </div>
            
        <p>&nbsp;</p>

        
        <?php
	}
	
}	
    
    function plgwsspa_PrepareTrafficValue($value)
    {
        $value = $value / 1024; // Convert to Kb
        
        $a = array(
            'value' => round($value, 2),
            'text' => 'Kb'
        );
        
        if ($value >= 1024)
        {
            $value = $value / 1024; // Convert to Mb
            
            $a = array(
                'value' => round($value, 2),
                'text' => 'Mb'
            );
        }
        else return $a;
        
        if ($value >= 1024)
        {
            $value = $value / 1024; // Convert to Gb
            
            $a = array(
                'value' => round($value, 2),
                'text' => 'Gb'
            );
        }
        else return $a;
        
        if ($value >= 1024)
        {
            $value = $value / 1024; // Convert to Tb
            
            $a = array(
                'value' => round($value, 2),
                'text' => 'Tb'
            );
        }
        
        return $a;
    }
    
    function plgwsspa_Validate_Log_File($filename)
    {
        if (stripos($filename, '.gz') !== false) $is_gz = true;
        else $is_gz = false;
        
        // Read 4096 bytes for analyze
        if ($is_gz)
        {
            $handle = gzopen($filename, "r");
            $contents = gzread($handle, 4096);
            gzclose($handle);
        }
        else {
            $handle = fopen($filename, "rb");
            $contents = fread($handle, 4096);
            fclose($handle);
        }
        
        if ($contents === false) return false;
        
        $contents = explode("\n", $contents);
        
        if (count($contents) < 2) return false;
        
        $line = $contents[0];
        $tmp = explode("\"", $line);
        $tmp2 = explode(" ", $tmp[0]);
        $ip = trim($tmp2[0]);
        
        $str = str_replace(".", " ", $ip, $count);
        if ( $count != 3 && (strlen($ip) > strlen("111.111.111.111") || strlen($ip) < strlen("1.1.1.1")) ) return false;

        return true;
    }
    



    
	function plgwsspa_activation()
	{
        plgwsspa_Copy_SG_tools_file();
        
        add_option('plgwsspa_activation_redirect', true);
	}
    register_activation_hook( __FILE__, 'plgwsspa_activation' );
    
	function plgwsspa_activation_do_redirect() 
    {
		if (get_option('plgwsspa_activation_redirect', false)) 
        {
			delete_option('plgwsspa_activation_redirect');
            wp_redirect("admin.php?page=plgwsspa_server_analytics");
            exit;
		}
	}
    add_action('admin_init', 'plgwsspa_activation_do_redirect');
    
    
	function plgwsspa_deactivation()
	{
        
	}
    register_deactivation_hook( __FILE__, 'plgwsspa_deactivation' );
    
    
	function plgwsspa_uninstall()
	{
        
	}
	register_uninstall_hook( __FILE__, 'plgwsspa_uninstall' );
