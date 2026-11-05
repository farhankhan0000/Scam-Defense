const rawText = document.body.innerText;
const cleanedText = rawText.replace(/\s+/g, ' ').trim();
const slicedText = cleanedText.substring(0, 3000);

const currentUrl = window.location.href;

console.log("Scam Defense - URL:", currentUrl);
console.log("Scam Defense - Extracted Text:", slicedText);