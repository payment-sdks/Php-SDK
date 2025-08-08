# PaymentSDK Usage Guide

## Introduction

The PaymentSDK for PHP facilitates the integration of Payment SDK's payment and checkout features into your PHP applications. This comprehensive guide will assist you in the setup and utilization of the PaymentSDK.

## Prerequisites

Before getting started, ensure you have the following:

- PHP installed on your server or development environment.
- Payment SDK API credentials, including the IV Key, Consumer Secret, Consumer Key.

## Installation

1. **Download the Payment SDK:**
   Download the Payment SDK and include it in your project.

   ```bash
   # Example using Composer
   composer require paymentsdk/payment-sdk
   
2. **Include the Composer autoloader in your PHP file:**

    ```bash
   require_once 'vendor/autoload.php';
   
3. **Instantiate the PaymentSDK class with your credentials:**

    ```bash
   use PaymentSDK\PaymentSDK\PaymentSDK;

    // Replace these values with your actual credentials
    $IVKey = 'your_iv_key';
    $consumerSecret = 'your_consumer_secret';
    $environment = 'sandbox';
    $rootDomain = 'example.com'

## Checkout Usage

1. **To initialize the PaymentSDK class, provide the $IVKey, $consumerKey, $consumerSecret, $rootDomain, and $environment parameters. The $environment should be one of the following: 'production' or 'sandbox'.**

    ```bash
   $PaymentSDK = new PaymentSDK($IVKey, $consumerKey, $consumerSecret, $rootDomain, $environment);

2. **Validate Payload**

    ```bash
    try {
    $PaymentSDK->validateCheckoutPayload($payload);
    } catch (Exception $error) {
    echo 'Error: ' . $error->getMessage() . "\n";
    }
   
3. **Encrypt Payload**

    ```bash
   $encryptedPayload = $PaymentSDK->encrypt($payload);
   
4. **Get Checkout Status**

    ```bash
   try {
    $PaymentSDK->getCheckoutStatus($payload["merchant_transaction_id"]);
   } catch (Exception $error) {
    echo 'Error: ' . $error->getMessage() . "\n";
   }

5. **Build Checkout URL**

    ```bash
   try {
        $checkoutUrl =
        'https://sandbox.checkout.{{rootDomain}}/?access_key=' .
        urlencode($accessKey) .
        '&payload=' .
        urlencode($encryptedPayload);
         echo 'Checkout URL: ' . $checkoutUrl . "\n";
       } catch (Exception $error) {
         echo 'Error: ' . $error->getMessage() . "\n";
       }

## Direct API Usage

1. **To initialize the PaymentSDK class, provide the $IVKey, $consumerSecret, and $environment parameters. The $environment should be one of the following: 'production' or 'sandbox'.**

    ```bash
   $PaymentSDK = new PaymentSDK($IVKey, $consumerSecret, $environment);
   
2. **Direct Charge**

    ```bash
   try {
    $PaymentSDK->DirectCharge($payload);
   } catch (Exception $error) {
     echo 'Error: ' . $error->getMessage() . "\n";
   }

3. **Get Charge Request Status**

    ```bash
   try {
    $PaymentSDK->getChargeRequestStatus($chargeRequestId);
    } catch (Exception $error) {
    echo 'Error: ' . $error->getMessage() . PHP_EOL;
    }

# License

## This SDK is open-source and available under the MIT License. 
