const rawText = document.body.innerText;
const cleanedText = rawText.replace(/\s+/g, ' ').trim();
const slicedText = cleanedText.substring(0, 4000);

const currentUrl = window.location.href;

console.log("Scam Defense - URL:", currentUrl);
console.log("Scam Defense - Extracted Text:", slicedText);

const payload = {
    action: "retrieved_info",
     url: currentUrl,
    text: slicedText
}

chrome.runtime.sendMessage(payload, (response) => {
    console.log("Scam defense content script background replied with-> ", response.status);
});