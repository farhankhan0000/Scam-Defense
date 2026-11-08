chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if(message.action == "retrieved_info"){
        fetch('http://127.0.0.1:8000/text', {
            method: 'POST',
            headers: {
                'Content-Type' : 'application/json'
            },
            body: JSON.stringify({url: message.url,
            text: message.text})
        })
    }
    return true;
});