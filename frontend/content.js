const rawText = document.body.innerText;
const anchorTags = document.querySelectorAll('a');
const cleanedText = rawText.replace(/\s+/g, ' ').trim();
const slicedText = cleanedText.substring(0, 4000);
const extractedLinks = []

const currentUrl = window.location.href;

anchorTags.forEach(tag => {
    let link = tag.href;
    if(link && (link.startsWith("http//") || link.startsWith("https//"))){
        extractedLinks.push(link);
    }
});

const uniqueLinks = [...new Set(extractedLinks)];

console.log("Scam Defense - URL:", currentUrl);
console.log("Scam Defense - Extracted Text:", slicedText);

const payload = {
    action: "retrieved_info",
     url: currentUrl,
    text: slicedText,
    links: uniqueLinks
}

chrome.runtime.sendMessage(payload, (response) => {
    console.log("Scam defense content script background replied with-> ", response.status);
});