const RISK = {
  KEYWORD: 10,
  MANY_LINKS: 10,
  MALICIOUS_LINK: 30,
  FREE_DOMAIN: 15,
  LONG_DOMAIN: 10,
  BLACKLIST: 40
};

const KEYWORDS = ["urgent", "verify", "password", "click", "bank", "login"];

const FREE_EMAIL_DOMAINS = ["gmail.com","walla.co.il", "yahoo.com", "outlook.com"];



function onGmailMessageOpen(e) {

  const messageData = getMessageData(e);
  const analysis = analyzeMessage(messageData);
  const card = buildResultCard(messageData, analysis);

  return card.build();
}


//Message extraction 
function getMessageData(e) {

  const message = GmailApp.getMessageById(e.gmail.messageId);

  return {
    sender: message.getFrom(),
    subject: message.getSubject(),
    body: message.getPlainBody().substring(0, 200)
  };
}


//Risk calculation
function analyzeMessage(data) {

  const senderAnalysis = senderRisk(data.sender);
  const blacklistAnalysis = blacklistRisk(data.sender);
  const contentAnalysis = contentRisk(data.subject, data.body);

  const urls = extractUrls(data.body);
  const linkAnalysis = linkRisk(urls);

  const rawScore = senderAnalysis.score +
  blacklistAnalysis.score +
  contentAnalysis.score +
  linkAnalysis.score;

  const totalScore = Math.min(rawScore, 100);

  return {
    totalScore,
    urls,
    senderAnalysis,
    blacklistAnalysis,
    contentAnalysis,
    linkAnalysis,
    status: getStatus(totalScore)
  };
}


//Content check
function contentRisk(subject, body) {

  let score = 0;
  const reasons = [];

  const subjectLower = subject.toLowerCase();
  const bodyLower = body.toLowerCase();

  KEYWORDS.forEach(word => {
    if (subjectLower.includes(word) || bodyLower.includes(word)) {
      score += RISK.KEYWORD;
      reasons.push(`Contains suspicious keyword: ${word}`);
    }
  });

  return { score, reasons };
}


//Links check
function extractUrls(text) {
  return text.match(/(https?:\/\/[^\s]+)/g) || [];
}

function linkRisk(urls) {

  let score = 0;
  const reasons = [];

  if (urls.length > 2) {
    score += RISK.MANY_LINKS;
    reasons.push("Email contains multiple links");
  }

  urls.forEach(url => {

    const maliciousCount = checkUrlReputation(url);

    if (maliciousCount > 0) {
      score += RISK.MALICIOUS_LINK;
      reasons.push(`Link flagged as malicious (${url})`);
    }

  });

  return { score, reasons };
}


//Sender check
function senderRisk(senderEmail) {

  let score = 0;
  const reasons = [];

  const domain = extractDomain(senderEmail);

  if (FREE_EMAIL_DOMAINS.includes(domain)) {
    score += RISK.FREE_DOMAIN;
    reasons.push(`Sender uses free email provider (${domain})`);
  }

  if (domain.length > 20) {
    score += RISK.LONG_DOMAIN;
    reasons.push("Sender domain unusually long");
  }

  return { score, reasons };
}

function extractDomain(email) {
  return (email.match(/@([^>]+)/)?.[1] || "").toLowerCase();
}


//Blacklist
function blacklistRisk(senderEmail) {

  let score = 0;
  const reasons = [];

  const blacklist = getBlacklist();
  const domain = extractDomain(senderEmail);

  if (blacklist.includes(senderEmail) || blacklist.includes(domain)) {
    score += RISK.BLACKLIST;
    reasons.push("Sender is on your personal blacklist");
  }

  return { score, reasons };
}

function isBlacklisted(senderEmail) {
  const blacklist = getBlacklist();
  const domain = extractDomain(senderEmail);
  return blacklist.includes(senderEmail) || blacklist.includes(domain);
}

function getBlacklist() {
  const stored = PropertiesService.getUserProperties().getProperty("BLACKLIST");

  if (stored) {
    //Converts the stored JSON string back into a JavaScript array
    return JSON.parse(stored);
  } else {
    return [];
  }
}


function addToBlacklist(item) {

  const userProperties = PropertiesService.getUserProperties();
  const blacklist = getBlacklist();

  if (!blacklist.includes(item)) {
    blacklist.push(item);
    userProperties.setProperty("BLACKLIST", JSON.stringify(blacklist));
  }
}

function removeFromBlacklist(item) {

  const userProperties = PropertiesService.getUserProperties();
  const updated = getBlacklist().filter(entry => entry !== item);

  userProperties.setProperty("BLACKLIST", JSON.stringify(updated));
}

function addCurrentSender(e) {

  const sender = e.parameters.sender;
  addToBlacklist(sender);

  return notify("Sender added to blacklist");
}

function removeCurrentSender(e) {

  const sender = e.parameters.sender;
  const domain = extractDomain(sender);

  removeFromBlacklist(sender);
  removeFromBlacklist(domain);

  return notify("Sender removed from blacklist");
}

function notify(text) {
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText(text))
    .build();
}


// VirusTotal API
function checkUrlReputation(url) {
  const apiKey = PropertiesService.getScriptProperties().getProperty("VT_API_KEY");
  if (!apiKey) return 0;

  // VirusTotal v3 requires Base64 URL safe encoding without padding (=)
  const urlId = Utilities.base64EncodeWebSafe(url).replace(/=+$/, '');
  
  const options = {
    method: "get",
    headers: { "x-apikey": apiKey },
    muteHttpExceptions: true
  };

  try {
    const response = UrlFetchApp.fetch("https://www.virustotal.com/api/v3/urls/" + urlId, options);
    const data = JSON.parse(response.getContentText());
    
    // Return the number of malicious flags
    return data.data.attributes.last_analysis_stats.malicious || 0;
  } catch (e) {
    console.error("VT API Error: " + e.message);
    return 0;
  }
}

//Status
function getStatus(score) {

  if (score <= 20) return { label: "SAFE", color: "#2E7D32" };
  if (score <= 50) return { label: "SUSPICIOUS", color: "#F9A825" };

  return { label: "HIGH RISK!", color: "#C62828" };
}


//UI
function buildResultCard(data, analysis) {

  const card = CardService.newCardBuilder();
  const section = CardService.newCardSection();

  addParagraph(section,`<b><font color='${analysis.status.color}' size='+1'>Status: ${analysis.status.label}</font></b>`);

  addParagraph(section, `<b>Sender:</b> ${data.sender}`);
  addBlacklistButton(section, data.sender);

  addParagraph(section, `<b>Subject:</b> ${data.subject}`);
  addParagraph(section, `<b>Body Preview:</b><br>${data.body}`);

  addParagraph(section, `<b>Risk Score:</b> ${analysis.totalScore} / 100`);
  addParagraph(section, `<b>Risk Breakdown</b>`);

  addReasons(section, "Content Analysis", analysis.contentAnalysis.reasons);
  addReasons(section, "Link Analysis", analysis.linkAnalysis.reasons);
  addReasons(section, "Blacklist", analysis.blacklistAnalysis.reasons);
  addReasons(section, "Sender Analysis", analysis.senderAnalysis.reasons);

  if (analysis.urls.length > 0) {
    addParagraph(section, `<b>Detected Links:</b><br>${analysis.urls.join("<br>")}`);
  }

  card.addSection(section);
  return card;
}

function addParagraph(section, text) {
  section.addWidget(CardService.newTextParagraph().setText(text));
}

function addReasons(section, title, reasons) {
  if (reasons.length === 0) {
    return;
  }

  addParagraph(section,`<b>${title}</b><br>${reasons.join("<br>")}`);
}


function addBlacklistButton(section, sender) {

  const blocked = isBlacklisted(sender);

  let buttonText;
  let functionName;

  if (blocked) {
    buttonText = "Remove Sender from Blacklist";
    functionName = "removeCurrentSender";
  } else {
    buttonText = "Add Sender to Blacklist";
    functionName = "addCurrentSender";
  }

  const button = CardService.newTextButton()
    .setText(buttonText)
    .setOnClickAction(
      CardService.newAction()
        .setFunctionName(functionName)
        .setParameters({ sender: sender })
    );

  section.addWidget(button);
}
