<?php
error_reporting(E_ERROR | E_PARSE);
require('/usr/share/php/AWSSDKforPHP/sdk.class.php');
$ec2 = new AmazonEC2();
$ec2_available_regions = Array(
        "ec2.eu-west-1.amazonaws.com",
        "ec2.sa-east-1.amazonaws.com",
        "ec2.us-east-1.amazonaws.com",
        "ec2.ap-northeast-1.amazonaws.com",
        "ec2.us-west-1.amazonaws.com",
        "ec2.ap-southeast-1.amazonaws.com",
        "ec2.ap-southeast-2.amazonaws.com"
);

foreach($ec2_available_regions as $region) {
   $ips_array = Array();
   $ec2->set_region($region);
   $ips = $ec2->describe_addresses()->body->to_stdClass();
   foreach($ips->addressesSet as $single_ip) {
      foreach($single_ip as $single_ip_data) {
         if(count((array)$single_ip_data->instanceId) == 0) {
            echo "- Unassociated IP: ". $single_ip_data->publicIp ." ... ";
            $ec2->release_address(array('PublicIp' => $single_ip_data->publicIp));
            echo " released.\n";
            array_push($ips_array, $single_ip_data->publicIp);
         }
      }
   }
   $sgs = $ec2->describe_security_groups()->body->to_stdClass();
   foreach($sgs->securityGroupInfo->item as $single_sgs) {
      foreach($single_sgs->ipPermissions->item as $single_rule) {
         foreach($single_rule->ipRanges->item as $single_cidr ) {
            if ($single_cidr->cidrIp != "") {
               if(in_array(strtok($single_cidr->cidrIp, "/"), $ips_array)) {
                  echo "Found match for ". strtok($single_cidr->cidrIp, "/") ." in ". $single_sgs->groupName ." (". $single_sgs->groupId .") - region: ". $region ." ... ";
                  $re=$ec2->revoke_security_group_ingress(array(
                     // Only this works with VPC
                     // change to "'GroupName' => $single_sgs->groupName" for non-vpc stuff
                     'GroupId' => $single_sgs->groupId,
                     'IpPermissions' => array(
                        array(
                           'IpProtocol' => $single_rule->ipProtocol,
                           'FromPort' => $single_rule->fromPort,
                           'ToPort' => $single_rule->toPort,
                           'IpRanges' => array(
                              array('CidrIp' => $single_cidr->cidrIp),
                           )
                        )
                     )
                  ));
                  echo "Removed from security group\n";
               }
            }
         }
      }
   }
}
?>
