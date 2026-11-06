chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if(message.action == "retrieved_info"){
        console.log("Background recieved URL: ", message.url);
        console.log("Background recieved Text ", message.text);
        sendResponse({status : "Package recieved successfully"});
    }
    return true;
})