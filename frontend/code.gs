/**
 * Backend API endpoint configuration.
 * Remember to update this with your current tunnel URL.
 */
var API_URL = "https://39fedbdc506af8.lhr.life/analyze";

/**
 * Helper function to extract attachment metadata and calculate SHA-256 hashes.
 * This runs natively on Google's servers, preventing heavy payload transfers to our backend.
 */
function extractAttachmentsData(message) {
  var attachments = message.getAttachments();
  var attachmentData = [];
  
  for (var i = 0; i < attachments.length; i++) {
    var att = attachments[i];
    
    // Calculate SHA-256 Hash natively in Google Apps Script
    var hashBytes = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, att.getBytes());
    var hashHex = hashBytes.map(function(byte) {
      var v = (byte < 0) ? 256 + byte : byte;
      return ("0" + v.toString(16)).slice(-2);
    }).join("");

    attachmentData.push({
      "name": att.getName(),
      "mime_type": att.getContentType(),
      "size": att.getSize(),
      "hash": hashHex
    });
  }
  
  return attachmentData;
}

/**
 * Main entry point for the Gmail Add-on. 
 * Extracts security metadata from headers to sync with the backend.
 * @param {Object} e The event object containing Gmail context.
 */
function onGmailMessageOpen(e) {
  var messageId = e.gmail.messageId;
  var message = GmailApp.getMessageById(messageId);
  
  var sender = message.getFrom();
  var subject = message.getSubject();
  var body = message.getPlainBody().substring(0, 5000);

  // Security Header Extraction
  // Fetch the full 'Authentication-Results' header for sophisticated backend analysis
  var authResults = message.getHeader("Authentication-Results") || "";
  
  // IP Extraction: Search for an IPv4 address pattern in the authentication header
  var ipMatch = authResults.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
  var extractedIp = ipMatch ? ipMatch[0] : "0.0.0.0";

  // --- NEW: Extract Attachments ---
  var attachmentsList = extractAttachmentsData(message);
  
  // Debug log: Check how many attachments were found by Google's API
  console.log("Found attachments: " + attachmentsList.length);
  
  // We must stringify arrays/objects before passing them to Apps Script action parameters
  var attachmentsString = JSON.stringify(attachmentsList);

  return CardService.newCardBuilder()
      .setHeader(CardService.newCardHeader().setTitle("Upwind Scanner"))
      .addSection(CardService.newCardSection()
          .addWidget(CardService.newTextParagraph().setText("Sender: " + sender))
          // NEW: Display the number of analyzed attachments in the UI
          .addWidget(CardService.newTextParagraph().setText("Attachments Found: " + attachmentsList.length))
          .addWidget(CardService.newTextButton()
              .setText("Run Security Analysis")
              .setOnClickAction(CardService.newAction()
                  .setFunctionName("callPythonServer") 
                  .setParameters({
                    "sender": sender,
                    "subject": subject,
                    "body": body,
                    "ip": extractedIp,
                    "auth_results": authResults,
                    "attachments": attachmentsString // NEW: Passing the JSON string
                  }))))
      .build();
}

/**
 * Handles communication with the Flask server.
 * @param {Object} e Event object from the UI.
 */
function callPythonServer(e) {
  var params = e.parameters;
  
  // --- NEW: Parse the attachments string back into a JSON array ---
  var attachmentsArray = [];
  if (params.attachments) {
    try {
      attachmentsArray = JSON.parse(params.attachments);
    } catch (err) {
      console.error("Error parsing attachments JSON: ", err);
    }
  }
  
  var payload = {
    "sender": params.sender,
    "subject": params.subject,
    "body": params.body,
    "ip": params.ip,
    "auth_results": params.auth_results,
    "attachments": attachmentsArray // NEW: Added to backend payload
  };

  var options = {
    "method": "post",
    "contentType": "application/json",
    "payload": JSON.stringify(payload),
    "muteHttpExceptions": true 
  };

  try {
    var response = UrlFetchApp.fetch(API_URL, options);
    var results = JSON.parse(response.getContentText());
    return displaySecurityReport(results); 
    
  } catch (err) {
    return CardService.newCardBuilder()
        .addSection(CardService.newCardSection()
            .addWidget(CardService.newTextParagraph().setText("Backend unreachable. Check your tunnel.")))
        .build();
  }
}

/**
 * Constructs the final security report UI card.
 */
function displaySecurityReport(results) {
  var section = CardService.newCardSection();
  
  section.addWidget(CardService.newDecoratedText()
      .setTopLabel("Reliability Score")
      .setText((results.reliability_score || 0) + "/100")
      .setWrapText(true));
  
  section.addWidget(CardService.newDecoratedText()
      .setTopLabel("Verdict")
      .setText(results.verdict || "Unknown"));
  
  var findingsText = "<b>Security Insights:</b><br>";
  if (results.findings && results.findings.length > 0) {
    results.findings.forEach(function(finding) {
      findingsText += "• " + finding + "<br>";
    });
  } else {
    findingsText += "• No significant risks detected.";
  }

  section.addWidget(CardService.newTextParagraph().setText(findingsText));

  return CardService.newCardBuilder()
      .setHeader(CardService.newCardHeader().setTitle("Analysis Result"))
      .addSection(section)
      .build();
}