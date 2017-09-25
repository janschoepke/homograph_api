<?php
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, GET");
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");
include 'Phois/Whois/Whois.php';

if($_SERVER['REQUEST_METHOD'] === 'POST'){

    $entityBody = json_decode(file_get_contents('php://input'), true);

    if(isset($entityBody['potentialLeaks']) && isset($entityBody['selectedDomains'])){

        $domainStrings = $entityBody['potentialLeaks'];
        $selectedDomains = $entityBody['selectedDomains'];

        $i = 0;
        foreach ($domainStrings as $domainString) {
            foreach ($selectedDomains as $selectedDomain) {

                $sld = $domainString['domainString'] . '.' . $selectedDomain;
                $domain = new Phois\Whois\Whois($sld);

                // 1: Checked and available
                // 2: Checked and unavailable
                if ($domain->isAvailable()) {
                    $domainStrings[$i][$selectedDomain] = 1;
                } else {
                    $domainStrings[$i][$selectedDomain] = 2;
                }
            }
            $i++;
        }
        
        echo json_encode($domainStrings);

    } else {
        echo 'Please submit the required parameters.';
    }
} else {
    echo 'POST Requests only.';
}