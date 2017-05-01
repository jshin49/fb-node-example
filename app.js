'use strict';

const 
  bodyParser = require('body-parser'),
  config = require('config'),
  crypto = require('crypto'),
  express = require('express'),
  https = require('https'),  
  request = require('request');

var app = express();
app.use(bodyParser.json({ verify: verifyRequestSignature }));
app.set('port', process.env.PORT || 5000);


/*
 * Be sure to setup your config values before running this code. You can 
 * set them using environment variables or modifying the config file in /config.
 *
 */

// App Secret can be retrieved from the App Dashboard
const APP_SECRET = 
  (process.env.APP_SECRET) ? 
  process.env.APP_SECRET :
  config.get('appSecret');

// Arbitrary value used to validate a webhook
const VERIFY_TOKEN = 
  (process.env.VERIFY_TOKEN) ?
  process.env.VERIFY_TOKEN :
  config.get('verifyToken');

// Generate a page access token for your page from the App Dashboard
const PAGE_ACCESS_TOKEN = 
  (process.env.PAGE_ACCESS_TOKEN) ?
  process.env.PAGE_ACCESS_TOKEN :
  config.get('pageAccessToken');

// URL where the app is running (include protocol). Used to point to scripts and 
// assets located at this address. 
const PAGE_ID = 
  (process.env.PAGE_ID) ?
  process.env.PAGE_ID :
  config.get('pageID');

if (!(APP_SECRET && VERIFY_TOKEN && PAGE_ACCESS_TOKEN && PAGE_ID)) {
  console.error("Missing config values");
  process.exit(1);
}


/*
 * Use your own verify token. Check that the token used in the Webhook 
 * setup is the same token used here.
 *
 */
app.get('/webhook', function(req, res) {
  if (req.query['hub.mode'] === 'subscribe' &&
      req.query['hub.verify_token'] === VERIFY_TOKEN) {
    console.log("Verifying webhook");
    res.status(200).send(req.query['hub.challenge']);
  } else {
    console.error("Failed verification. Make sure the verify tokens match.");
    res.sendStatus(403);
  }  
});


/*
 * All callbacks for Messenger are POST-ed. They will be sent to the same
 * webhook. Be sure to subscribe your app to your page to receive callbacks
 * for your page. 
 * https://developers.facebook.com/docs/messenger-platform/product-overview/setup#subscribe_app
 *
 */
app.post('/webhook', function (req, res) {
  var data = req.body;
  console.log(data);
  res.sendStatus(200);
  // Make sure this is a page subscription
  // if (data.object == 'page') {
  //   // Iterate over each entry
  //   // There may be multiple if batched
  //   data.entry.forEach(function(pageEntry) {
  //     var pageID = pageEntry.id;
  //     var timeOfEvent = pageEntry.time;

  //     // Iterate over each messaging event
  //     pageEntry.messaging.forEach(function(messagingEvent) {
  //       if (messagingEvent.optin) {
  //         receivedAuthentication(messagingEvent);
  //       } else if (messagingEvent.message) {
  //         receivedMessage(messagingEvent);
  //       } else if (messagingEvent.delivery) {
  //         receivedDeliveryConfirmation(messagingEvent);
  //       } else if (messagingEvent.postback) {
  //         receivedPostback(messagingEvent);
  //       } else if (messagingEvent.read) {
  //         receivedMessageRead(messagingEvent);
  //       } else if (messagingEvent.account_linking) {
  //         receivedAccountLink(messagingEvent);
  //       } else {
  //         console.log("Webhook received unknown messagingEvent: ", messagingEvent);
  //       }
  //     });
  //   });

  //   // Assume all went well.
  //   //
  //   // You must send back a 200, within 20 seconds, to let us know you've 
  //   // successfully received the callback. Otherwise, the request will time out.
  //   res.sendStatus(200);
  // }
});


/*
 * Verify that the callback came from Facebook. Using the App Secret from 
 * the App Dashboard, we can verify the signature that is sent with each 
 * callback in the x-hub-signature field, located in the header.
 *
 * https://developers.facebook.com/docs/graph-api/webhooks#setup
 *
 */
function verifyRequestSignature(req, res, buf) {
  var signature = req.headers["x-hub-signature"];

  if (!signature) {
    // For testing, let's log an error. In production, you should throw an 
    // error.
    console.error("Couldn't validate the signature.");
  } else {
    var elements = signature.split('=');
    var method = elements[0];
    var signatureHash = elements[1];

    var expectedHash = crypto.createHmac('sha1', APP_SECRET)
                        .update(buf)
                        .digest('hex');

    if (signatureHash != expectedHash) {
      throw new Error("Couldn't validate the request signature.");
    }
  }
}



// Start server
// Webhooks must be available via SSL with a certificate signed by a valid 
// certificate authority.
app.listen(app.get('port'), function() {
  console.log('Node app is running on port', app.get('port'));
});

module.exports = app;
